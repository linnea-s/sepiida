# Copyright 2009-2011 Linnea Skogtvedt <linnea@linuxavdelingen.no>
#
# This file is part of Sepiida.
#
# Sepiida is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Sepiida is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Sepiida.  If not, see <http://www.gnu.org/licenses/>.

from twisted.internet import \
    reactor, protocol, defer, utils, threads
from twisted.python import log

from misc import getpw, getpwuid, getgroups
import sys
import time
import socket
import os
import signal
import cStringIO
import random
import shlex
from string import Template
import config

class SlurpProtocol(protocol.ProcessProtocol):
    def __init__(self, deferred):
        self.buffer = cStringIO.StringIO()
        self.deferred = deferred
    
    def connectionMade(self):
        pass
    
    def outReceived(self, data):
        self.buffer.write(data)
    
    def processEnded(self, status):
        self.deferred.callback(self.buffer.getvalue())
        self.buffer.close()
        
class NullProtocol(protocol.ProcessProtocol):
    def __init__(self, deferred):
        self.deferred = deferred
    
    def processEnded(self, status):
        self.deferred.callback(status.value.exitCode)

class VNCProxyProtocol(protocol.ProcessProtocol):
    def __init__(self, deferred, vncPassword):
        self.deferred = deferred
        self.vncPassword = vncPassword
        self.output = ''
        self.err = ''
        self.gotPassword = False
    
    def connectionMade(self):
        self.transport.write(self.vncPassword + '\n')
        self.transport.closeStdin()

    def outReceived(self, data):
        import re
        self.output += data
        m = re.search(r'^pw=(.*)\n', self.output, re.MULTILINE)
        if m:
            self.deferred.callback(m.group(1))
            self.gotPassword = True
    
    def errReceived(self, data):
        self.err += data
    
    def processEnded(self, status):
        if not self.gotPassword or status.value.exitCode != 0:
            try:
                self.deferred.errback(Exception('VNCProxyProtocol failed: %s' % self.err))
            except defer.AlreadyCalledError:
                pass

class User(object):
    def __init__(self):
        self.uid = None
        self.gid = None
        self.username = None
        self.client = None
        self.display = None
        self.name = None
        self.groups = None
        self.env = None
        self.logintime = None
        self.clientType = None
        self.clientHWAddr = None
    
    def __repr__(self):
        return 'User("%s@%s:%s")' % (self.username, self.client, self.display)

class UserInfo(object):
    def __init__(self):
        self.users = {}
        self.processes = {} # {"username": [ (pid, commandline)] }
        self._prevPIDList = []
        self._loginPIDs = []
        self._resolveCache = {}
        
    def updateUsersProcesses(self, cbChanged):
        """
        Update list of users and processes.
        Instead of using who or similar, look for dbus-launch or
        another process. This is because we need the PID of one of the users
        processes to get misc. environment variables.
        Because of this it's convenient to update users and processes
        in the same place.
        cbChanged is called with the value True if the list of users has
        changed, otherwise False.
        """
        # actually a list of files in /proc, but the PIDs should be the only things changing
        pids = os.listdir('/proc')
        if pids == self._prevPIDList:
            cbChanged(False)
            return
        self._prevPIDList = pids
        
        cfg = config.get()
        
        import re
        # What we're matching:
        # Mon May 25 19:59:23 2009 jss      23043 /bin/bash
        re_ps = re.compile(r'^(\S+\s*\S+\s*\S+\s*\S+\s*\S+)\s*(\S+)\s*(\S+)\s*(.+)$')
        re_number = re.compile(r'^\d+$')
        cmd_login = cfg.get('Agent', 'login cmd')
        
        args = ['ww', '-e', '-o', 'lstart,user,pid,args']
        env = {'LC_ALL': 'C'}
        d = utils.getProcessOutput('/bin/ps', args, env)
        wait = defer.waitForDeferred(d)
        yield wait
        output = wait.getResult()
        
        processes = {} # {user: [ (pid, commandline)] }
        loginProcesses = [] # [ (logintime, user, pid, commandline) ]
        for line in output.splitlines()[1:]: # skip header
            m = re_ps.match(line)
            if not m:
                log.err('ps regex didn\'t match %s' % line)
                continue
            lstart, user, pid, commandline = m.groups()
            user = user.decode('utf-8')
            commandline = commandline.decode('utf-8', 'replace')
            
            # handle case where ps returns UID, e.g. for long usernames
            if re_number.match(user):
                uid = user
                try:
                    user = getpwuid(int(uid)).pw_name.decode('utf-8')
                except KeyError:
                    continue
                
            processes.setdefault(user, []).append((int(pid), commandline))

            if commandline.startswith(cmd_login):
                loginProcesses.append((lstart, user, int(pid), commandline))
        
        self.processes = processes
        
        loginPIDs = [l[2] for l in loginProcesses]
        if loginPIDs == self._loginPIDs:
            cbChanged(False)
            return
        self._loginPIDs = loginPIDs
        
        log.debug('login processes: %s' % loginProcesses)
        users = {}
        for lstart, user, pid, commandline in loginProcesses:
            try:
                logintime = time.mktime(time.strptime(lstart))
            except ValueError:
                log.err('failed to parse lstart \'%s\'' % lstart)
                continue
            try:
                env = dict(
                              ( var.split('=', 1) for var in
                                open('/proc/%s/environ' % pid, 'r').read().split('\x00') if var )
                            )
                display = env['DISPLAY']
                if 'SSH_CLIENT' in env: # remote login
                    clientIP = env['SSH_CLIENT'].split(None, 1)[0]
                    wait = defer.waitForDeferred(self._maybeResolve(clientIP))
                    yield wait
                    try:
                        client = wait.getResult()
                    except socket.error:
                        client = clientIP
                    
                    HWAddr = self._getHWAddr(clientIP)
                else:
                    client = ''
                    HWAddr = self._getOwnHWAddr()
                
                if 'LTSP_CLIENT' in env:
                    ctype = 'ltsp'
                else:
                    ctype = 'other'
                
                ukey = (user, client, display)
                try:
                    userobj = users[ukey] = self.users[ukey]
                except KeyError:
                    uenv = {}
                    for var in ('HOME', 'LANG', 'DISPLAY'):
                        uenv[var] = env[var]
                    name = getpw(user).pw_gecos.decode('utf-8', 'replace')
                    groups = getgroups(user)
                    
                    userobj = users[ukey] = User()
                    userobj.uid = getpw(user).pw_uid
                    userobj.gid = getpw(user).pw_gid
                    userobj.username = user
                    userobj.client = client
                    userobj.clientHWAddr = HWAddr
                    userobj.display = display
                    userobj.name = name
                    userobj.groups = groups
                    userobj.env = uenv
                    userobj.clientType = ctype
                    userobj.logintime = logintime
                
            except (IOError, OSError, KeyError, IndexError):
                log.err()
                log.err(env)
                continue
        
        self.users = users
        cbChanged(True)
    
    updateUsersProcesses = defer.deferredGenerator(updateUsersProcesses)
    
    def _maybeResolve(self, ipaddr):
        cfg = config.get()
        if not cfg.getboolean('Agent', 'resolve ips'):
            return defer.succeed(ipaddr)
        elif ipaddr in self._resolveCache:
            return defer.succeed(self._resolveCache[ipaddr])
        
        def cbSuccess(result):
            self._resolveCache[ipaddr] = result[0]
            return result[0]
        
        d = threads.deferToThread(socket.gethostbyaddr, ipaddr)
        d.addCallback(cbSuccess)
        return d
    
    def _getHWAddr(self, ipaddr):
        """
        Look up MAC address of IP address in ARP cache.
        Since this is presumably called short time after the user has logged
        in, it is assumed that the IP address is in the cache.
        """
        f = open('/proc/net/arp', 'r')
        skipped = f.readline() # skip header 
        for line in f:
            fields = line.split()
            if fields[0] == ipaddr:
                return fields[3]
        f.close()
        return ''
    
    def _getOwnHWAddr(self):
        """
        Get MAC address of this machine. Unfortunately it might have several
        interfaces, so simply sort the list of interfaces and return the
        MAC address of the first interface in the resulting list.
        """
        dir = '/sys/class/net'
        ifaces = os.listdir(dir)
        ifaces.sort()
        f = open(os.path.join(dir, ifaces[0], 'address'), 'r')
        addr = f.read().rstrip()
        f.close()
        return addr
    
    def _runCmdAsUser(self, user, cmdKey, subst):
        cfg = config.get()
        d = defer.Deferred()
        null = NullProtocol(d)
        
        argv = shlex.split(cfg.get('Commands', cmdKey))
        argv = [ Template(arg).substitute(subst) for arg in argv ]
        
        reactor.spawnProcess(null, argv[0],
                             args=argv,
                             env=user.env,
                             uid=user.uid, gid=user.gid)
        return d
    
    def getBootTime(self):
        uptime = float(open('/proc/uptime', 'r').read().split()[0])
        return int(time.time() - uptime)
    
    def getOS(self):
        return sys.platform
    
    def getLoad(self):
        return os.getloadavg()[0]
    
    def logoutUser(self, user):
        return self._runCmdAsUser(user, 'logout', {})
        
    def sendMessage(self, user, message):
        return self._runCmdAsUser(user, 'send message', {'message': message.encode('utf-8', 'replace')})
    
    def lockUser(self, user):
        return self._runCmdAsUser(user, 'lock screen', {})
    
    def openURL(self, user, url):
        return self._runCmdAsUser(user, 'open url', {'url': url.encode('utf-8', 'replace')})
    
    def getThumbnail(self, user):
        d = defer.Deferred()
        sc = SlurpProtocol(d)
        
        reactor.spawnProcess(sc, '/usr/bin/screenshoter',
                             args=['screenshoter', '-t', '10',
                                   '-w', '320', '-h', '240', '-q', '50', '-o', '-'],
                             env=user.env,
                             uid=user.uid, gid=user.gid)
        return d
    
    def killProcess(self, user, pid):
        try:
            os.kill(pid, signal.SIGTERM)
        except OSError:
            pass
    
    def getVNC(self, user):
        """
        Get VNC password and port for user.
        Returns a deferred which is called back with (port, password)
        """
        cfg = config.get()
        
        def getRandomPort():
            while True:
                p = random.randint(2000, 30000)
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.bind(('127.0.0.1', p))
                    s.close()
                    return p
                except socket.error:
                    pass
        
        def vncNotify():
            d = defer.Deferred()
            null = NullProtocol(d)
            
            argv = shlex.split(cfg.get('Commands', 'vnc notify'))            
            reactor.spawnProcess(null, argv[0],
                     args=argv,
                     env=user.env,
                     uid=user.uid, gid=user.gid)
        
        def vncPassword():
            from string import letters, digits
            return ''.join(random.sample((letters + digits), 8))
        
        def vncLtsp():
            def cbSuccess(password, port):
                return port, password
            
            t = Template(cfg.get('Commands', 'vnc proxy'))
            port = getRandomPort()
            cmd = str(t.substitute(lport=port, chost=user.client, cport=5900))
            
            argv = shlex.split(cmd)
            d = defer.Deferred()
            d.addCallback(cbSuccess, port)
            vp = VNCProxyProtocol(d, vncPassword())
            reactor.spawnProcess(vp, argv[0], args=argv, env=os.environ, uid=0, gid=0)
            return d
            
        def vncLocal():
            def cbVNC(x11vnc_output, password):
                # x11vnc writes PORT=N to stdout
                try:
                    port = int(x11vnc_output.strip().split('=')[1])
                    return port, password
                except (IndexError, ValueError):
                    raise Exception('didn\'t receive expected output from x11vnc: %s' % x11vnc_output)
            
            vncpw = vncPassword()
            import tempfile
            pwtmpf = tempfile.NamedTemporaryFile(prefix='.sepiida-agent-vnc')
            pwtmpf.write(vncpw)
            pwtmpf.flush()
            os.chown(pwtmpf.name, user.uid, user.gid)
            reactor.callLater(10, pwtmpf.close)
            
            deferred_vnc = defer.Deferred()
            deferred_vnc.addCallback(cbVNC, vncpw)
            slurp = SlurpProtocol(deferred_vnc)
            
            probe_port = random.randint(2000, 30000) # which port x11vnc should start probing at
            reactor.spawnProcess(slurp, '/usr/bin/x11vnc',
                                 args=['x11vnc', '-localhost', '-bg', '-quiet',
                                       '-autoport', str(probe_port), '-timeout', '10',
                                       '-passwdfile', pwtmpf.name],
                                 env=user.env,
                                 uid=user.uid, gid=user.gid
                                 )
            return deferred_vnc
        
        def cbNotify(data):
            vncNotify()
            return data
            
        if user.clientType == 'ltsp':
            d = vncLtsp()
        else:
            d = vncLocal()
        d.addCallback(cbNotify)
        return d
    
    def getLogin(self):
        """
        Return port and protocol for login screen.
        """
        return (5950, 'vnc')
    
    def shutdown(self):
        """
        Shutdown system.
        """
        utils.getProcessValue('/sbin/shutdown', ['-h', 'now'])
    
    def reboot(self):
        """
        Reboot system.
        """
        utils.getProcessValue('/sbin/shutdown', ['-r', 'now'])
    