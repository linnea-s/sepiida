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
import os
import signal
import random
import config

class NullProtocol(protocol.ProcessProtocol):
    def __init__(self, deferred):
        self.deferred = deferred
    
    def processEnded(self, status):
        self.deferred.callback(status.value.exitCode)

class X11VNCProtocol(protocol.ProcessProtocol):
    def __init__(self, deferred):
        self.deferred = deferred
        self.output = ''
        self.err = ''
        self.gotPort = False
    
    def connectionMade(self):
        pass
    
    def outReceived(self, data):
        import re
        self.output += data
        m = re.search(r'^PORT=(\d+)\n', self.output, re.MULTILINE)
        if m:
            self.deferred.callback(int(m.group(1)))
            self.gotPort = True
    
    def errReceived(self, data):
        self.err += data
    
    def processEnded(self, status):
        if not self.gotPort or status.value.exitCode != 0:
            try:
                self.deferred.errback(Exception('X11VNCProtocol failed: %s' % self.err))
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
        self._HWAddr = None
    
    @defer.deferredGenerator
    def updateUsersProcesses(self, cbChanged):
        """
        Update list of users and processes.
        """
        import re
        # What we're matching:
        # Mon May 25 19:59:23 2009 jss      23043 /bin/bash
        re_ps = re.compile(r'^(\S+\s*\S+\s*\S+\s*\S+\s*\S+)\s*(\S+)\s*(\S+)\s*(.+)$')
        re_number = re.compile(r'^\d+$')
        cmd_login = '/System/Library/CoreServices/loginwindow.app/Contents/MacOS/loginwindow'
        
        args = ['-ww', '-ax', '-o', 'lstart,user,pid,command']
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
        
        if not self._HWAddr:
            d = self._getOwnHWAddr()
            wait = defer.waitForDeferred(d)
            yield wait
            self._HWAddr = wait.getResult()
        
        log.debug('login processes: %s' % loginProcesses)
        users = {}
        for lstart, user, pid, commandline in loginProcesses:
            try:
                logintime = time.mktime(time.strptime(lstart))
            except ValueError:
                log.err('failed to parse lstart \'%s\'' % lstart)
                continue
        
            client = ''
            display = ''
            
            ukey = (user, client, display)
            try:
                userobj = users[ukey] = self.users[ukey]
            except KeyError:
                name = getpw(user).pw_gecos.decode('utf-8', 'replace')
                groups = getgroups(user)
                
                userobj = users[ukey] = User()
                userobj.uid = getpw(user).pw_uid
                userobj.gid = getpw(user).pw_gid
                userobj.username = user
                userobj.client = client
                userobj.clientHWAddr = self._HWAddr
                userobj.display = display
                userobj.name = name
                userobj.groups = groups
                userobj.env = {"PATH":"/bin:/sbin:/usr/bin:/usr/sbin"}
                userobj.logintime = logintime
        
        self.users = users
        log.debug(users)
        cbChanged(True)
    
    def _getOwnHWAddr(self):
        """
        Get MAC address of this machine.
        """
        def firstHWAddr(output):
            import re
            return re.findall(r'ether (\S+)', output)[0]
        d = utils.getProcessOutput('/sbin/ifconfig', [])
        d.addCallback(firstHWAddr)
        return d
        
    def _runCmdAsUser(self, user, argv):
        d = defer.Deferred()
        null = NullProtocol(d)
        
        reactor.spawnProcess(null, argv[0],
                             args=argv,
                             env=user.env,
                             uid=user.uid, gid=user.gid)
        return d
    
    def getBootTime(self):
        d = utils.getProcessOutput('/usr/sbin/sysctl', ['-n', 'kern.boottime'])
        d.addCallback(int)
        return d
    
    def getOS(self):
        return sys.platform
    
    def getLoad(self):
        return os.getloadavg()[0]
    
    def logoutUser(self, user):
        return self._runCmdAsUser(user,
                                  ['osascript', '-e', 'tell application "System Events" to log out'])
        
    def sendMessage(self, user, message):
        message = message.encode('macroman', 'replace').replace('"', '\\"')
        return self._runCmdAsUser(user,
                           ['osascript', '-e', 'tell application "Finder"', '-e',
                            'activate', '-e', 'display dialog "%s"' % message,
                            '-e', 'end tell'])
        
    def lockUser(self, user):
        cmd = (
        'tell application "Finder" to do shell script'
        '"\'/System/Library/CoreServices/Menu Extras/User.menu/Contents/Resources/CGSession\' -suspend"'
        )
        return self._runCmdAsUser(user, ['osascript', '-e', cmd])
    
    def openURL(self, user, url):
        url = url.encode('macroman', 'replace').replace('"', '\\"')
        return self._runCmdAsUser(user,
                           ['osascript', '-e', 'open location "%s"' % url])
        
    
    def getThumbnail(self, user):
        import tempfile
        tempdir = tempfile.mkdtemp()
        os.chown(tempdir, user.uid, user.gid)
        img = os.path.join(tempdir, 'screenshot.jpg')
        
        def resize(ignoredResult, img=img):
            def getImageContents(result):
                contents = open(img, 'rb').read()
                os.unlink(img)
                os.rmdir(tempdir)
                return contents
            d = utils.getProcessValue('/usr/bin/sips', ['sips', '-z', '240', '320',
                                                        '-s', 'formatOptions', '50%', img])
            d.addCallback(getImageContents)
            return d
        
        d = defer.Deferred()
        sc = NullProtocol(d)
        reactor.spawnProcess(sc, '/usr/sbin/screencapture',
                             args=['screencapture', '-m', '-tjpg', img],
                             env=user.env,
                             uid=user.uid, gid=user.gid)
        
        d.addCallback(resize)
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
        
        def vncPassword():
            from string import letters, digits
            return ''.join(random.sample((letters + digits), 8))
        
        def vncLocal():
            def cbVNC(port, password):
                return port, password
            
            vncpw = vncPassword()
            import tempfile
            pwtmpf = tempfile.NamedTemporaryFile(prefix='.sepiida-agent-vnc')
            pwtmpf.write(vncpw)
            pwtmpf.flush()
            os.chown(pwtmpf.name, user.uid, user.gid)
            reactor.callLater(10, pwtmpf.close)
            
            deferred_vnc = defer.Deferred()
            deferred_vnc.addCallback(cbVNC, vncpw)
            vncp = X11VNCProtocol(deferred_vnc)
            
            probe_port = random.randint(2000, 30000) # which port x11vnc should start probing at
            x11vncPath = '/usr/local/bin/x11vnc'
            reactor.spawnProcess(vncp, x11vncPath,
                                 args=[x11vncPath, '-localhost',
                                       '-autoport', str(probe_port), '-timeout', '10',
                                       '-passwdfile', pwtmpf.name],
                                 env=user.env,
                                 uid=user.uid, gid=user.gid
                                 )
            return deferred_vnc
        
        def cbNotify(data):
            self.sendMessage(user, cfg.get('Agent', 'vnc notification').decode('utf-8', 'replace'))
            return data
        
        d = vncLocal()
        d.addCallback(cbNotify)
        return d
    
    def getLogin(self):
        """
        Return port and protocol for login screen.
        """
        raise NotImplementedError('getLogin not implemented')
    
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

