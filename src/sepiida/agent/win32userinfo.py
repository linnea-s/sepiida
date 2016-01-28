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

from twisted.internet import defer, utils, threads
from twisted.python import log

import os
import config

# Hack to stop console windows popping up on XP when using utils.getProcessOutput*
import win32process
win32process.STARTF_USESTDHANDLES |= win32process.STARTF_USESHOWWINDOW

class User(object):
    def __init__(self):
        self.username = None
        self.client = None
        self.display = None
        self.name = None
        self.groups = None
        self.logintime = None
        self.clientHWAddr = None
    
    def __repr__(self):
        return 'User("%s@%s:%s")' % (self.username, self.client, self.display)

class UserInfo(object):
    def __init__(self):
        self.users = {} # {(username, client, display): User object}
        self.processes = {} # {"username": [ (pid, commandline)] }
        self._prevPIDList = []
        self._loginPIDs = []
        self._bootTime = 0
    
    def getBootTime(self):
        # FIXME: GetTickCount() wraps around after 49.7 days.
        import time
        import win32api
        if not self._bootTime:
            self._bootTime = int(time.time()) - (win32api.GetTickCount() / 1000)
        return self._bootTime
    
    def getLoad(self):
        return 0.0
    
    def getOS(self):
        import sys
        return sys.platform
    
    @defer.deferredGenerator
    def updateUsersProcesses(self, cbChanged):
        """
        Update list of users and processes.
        cbChanged is called with the value True if the list of users has
        changed, otherwise False.
        """
        import win32api
        import win32process
        import win32security
        import win32con
        
        pids = win32process.EnumProcesses()
        if pids == self._prevPIDList:
            cbChanged(False)
            return
        self._prevPIDList = pids
        
        def getUser(pid):
            hProcess = hProcessToken = None
            try:
                hProcess = win32api.OpenProcess(win32con.PROCESS_QUERY_INFORMATION | win32con.PROCESS_VM_READ, 0, pid)
                hProcessToken = win32security.OpenProcessToken(hProcess, win32security.TOKEN_READ)
                sid, n = win32security.GetTokenInformation(hProcessToken, win32security.TokenUser)
                name, domainName, type_ = win32security.LookupAccountSid(None, sid)
            finally:
                if hProcess:
                    win32api.CloseHandle(hProcess)
                if hProcessToken:
                    win32api.CloseHandle(hProcessToken)
            return sid, name, domainName, type_
        
        def getStartTime(pid):
            from time import strptime
            from calendar import timegm
            hProcess = win32api.OpenProcess(win32con.PROCESS_QUERY_INFORMATION | win32con.PROCESS_VM_READ, 0, pid)
            try:
                pyTime = win32process.GetProcessTimes(hProcess)['CreationTime']
                return timegm(strptime(pyTime.Format('%a %b %d %H:%M:%S %Y')))
            finally:
                win32api.CloseHandle(hProcess)
        
        def getprocesses():
            """
            Return deferred returning processes:
            [ (imagename, pid, sessnumber) ]
            """
            def cbSuccess(output):
                output = output.decode('ascii', 'replace').encode('ascii', 'replace')
                import csv
                reader = csv.reader(output.splitlines())
                processes = []
                for row in reader:
                    if not row:
                        continue
                    processes.append((row[0], int(row[1]), int(row[3])))
                return processes
            d = utils.getProcessOutput(os.path.join(os.getenv('WinDir'), 'system32', 'tasklist.exe'),
                                         ['/FI', 'USERNAME NE NT AUTHORITY\\SYSTEM', '/V', '/FO', 'CSV', '/NH'], errortoo=True)
            d.addCallback(cbSuccess)
            return d
        
        d = getprocesses()
        waitTasklist = defer.waitForDeferred(d)
        yield waitTasklist
        
        processes = {} # {user: [ (pid, commandline)] }
        loginProcesses = [] # [ (logintime, user, pid, commandline) ]
        for imagename, pid, sessnumber in waitTasklist.getResult():
            try:
                sid, username, dName, type_ = getUser(pid)
                startTime = getStartTime(pid)
            except win32api.error:
                continue
            username = '%s\\%s' % (dName, username)
            processes.setdefault(username, []).append((pid, imagename))
            
            if imagename.lower() == 'explorer.exe':
                loginProcesses.append((startTime, username, pid, sessnumber))
        
        self.processes = processes
        
        loginPIDs = [l[2] for l in loginProcesses]
        if loginPIDs == self._loginPIDs:
            cbChanged(False)
            return
        self._loginPIDs = loginPIDs
        
        import win32net
        cfg = config.get()
        domainServer = cfg.get('Agent', 'domain server')
        def getGroups(username):
            for srv in None, domainServer:
                try:
                    return [x[0] for x in win32net.NetUserGetGroups(srv, username)] + \
                           win32net.NetUserGetLocalGroups(srv, username)
                except win32net.error:
                    pass
            return []
        
        def getName(username):
            for srv in None, domainServer:
                try:
                    return win32net.NetUserGetInfo(srv, username, 2)['full_name']
                except win32net.error:
                    pass
            return u''
        
        wait = defer.waitForDeferred(self._getOwnHWAddr())
        yield wait
        HWAddr = wait.getResult()
        
        users = {}
        for logintime, username, pid, sessnumber in loginProcesses:
            display = str(sessnumber)
            client = ''
            
            ukey = (username, client, display)
            try:
                userobj = users[ukey] = self.users[ukey]
            except KeyError:
                shortname = username[username.index('\\')+1:]
                name = getName(shortname)
                groups = getGroups(shortname)
                
                userobj = users[ukey] = User()
                userobj.username = username
                userobj.client = client
                userobj.clientHWAddr = HWAddr
                userobj.display = display
                userobj.name = name
                userobj.groups = groups
                userobj.logintime = logintime
        
        self.users = users
        cbChanged(True)
    
    def _getOwnHWAddr(self):
        """
        Get MAC address of this machine. Unfortunately it might have several
        interfaces, so simply return the first listed by ipconfig.
        """
        def cbSuccess(output):
            import re
            digit = '[0-9A-Z]'
            re_hwaddr = re.compile('-'.join([digit + digit for i in xrange(6)]))
            return re_hwaddr.findall(output)[0]
        d = utils.getProcessOutput(os.path.join(os.getenv('WinDir'), 'system32', 'ipconfig.exe'), ['/ALL'])
        d.addCallback(cbSuccess)
        return d
    
    def _cmdAsUser(self, user, cmd):
        import win32api
        import win32process
        
        hUser = self.__getUserToken(user)
        try:
            cmdPath = os.getenv('ComSpec')
            startupInfo = win32process.STARTUPINFO()
            startupInfo.lpDesktop = r'winsta0\default'
            startupInfo.dwFlags = win32process.STARTF_USESTDHANDLES | win32process.STARTF_USESHOWWINDOW
            win32process.CreateProcessAsUser(hUser, cmdPath, r'/C %s' % cmd, None, None, False, 0, None, None, startupInfo)
        finally:
            win32api.CloseHandle(hUser)
    
    def __getUserToken(self, user):
        import win32ts
        import win32security
        import win32con
        import win32api
        
        hToken = win32ts.WTSQueryUserToken(int(user.display))
        try:
            return win32security.DuplicateTokenEx(hToken, win32security.SecurityIdentification,
                                       win32con.MAXIMUM_ALLOWED, win32security.TokenPrimary)
        finally:
            win32api.CloseHandle(hToken)
    
    def sendMessage(self, user, message):
        import win32ts
        import win32con
        win32ts.WTSSendMessage(win32ts.WTS_CURRENT_SERVER_HANDLE,
                               int(user.display), u'Message', message,
                               win32con.MB_OK, 0, False)
        
    def logoutUser(self, user):
        self._cmdAsUser(user, r'c:\sepiida\logout.py')
    
    def lockUser(self, user):
        self._cmdAsUser(user, r'rundll32.exe user32.dll,LockWorkStation')
    
    def openURL(self, user, url):
        raise NotImplementedError()
        #self._cmdAsUser(user, r'start %s' % url.encode('mbcs'))
        
    def _getThumbnailSync(self, user):
        import win32security
        import win32api
        import win32process
        import win32con
        import win32event
        import win32file
        from tempfile import mkstemp
        from msvcrt import open_osfhandle
        
        sAttrs = win32security.SECURITY_ATTRIBUTES()
        sAttrs.bInheritHandle = True
        
        tmpFd, tmpFname = mkstemp()
        os.close(tmpFd)
        
        hWrite = win32file.CreateFile(tmpFname, win32file.GENERIC_WRITE,
                                      win32file.FILE_SHARE_READ,
                                      sAttrs,
                                      win32file.TRUNCATE_EXISTING,
                                      win32file.FILE_ATTRIBUTE_TEMPORARY, 0)
        
        hRead = win32file.CreateFile(tmpFname, win32file.GENERIC_READ,
                                     win32file.FILE_SHARE_WRITE,
                                     None,
                                     win32file.OPEN_EXISTING,
                                     0, 0)
        
        startupInfo = win32process.STARTUPINFO()
        startupInfo.dwFlags = win32process.STARTF_USESTDHANDLES | win32process.STARTF_USESHOWWINDOW
        startupInfo.lpDesktop = r'winsta0\default'
        startupInfo.hStdOutput = hWrite
        startupInfo.hStdError = hWrite
        
        hUser = self.__getUserToken(user)
        try:
            hProcess, hThread, dwPid, dwTid = \
                win32process.CreateProcessAsUser(hUser, r'c:\sepiida\screenshot.exe',
                                             'screenshot.exe - 320x240 50',
                                             None, None, True, 0, None, None, startupInfo)
        finally:
            win32api.CloseHandle(hUser)
        
        win32event.WaitForSingleObject(hProcess, win32event.INFINITE)
        exitCode = win32process.GetExitCodeProcess(hProcess)
        win32api.CloseHandle(hProcess)
        win32api.CloseHandle(hThread)
        win32api.CloseHandle(hWrite)
        
        fd = open_osfhandle(hRead, os.O_RDONLY)
        f = os.fdopen(fd, 'rb')
        data = f.read()
        f.close()
        os.unlink(tmpFname)
        return data
    
    def getThumbnail(self, user):
        return threads.deferToThread(self._getThumbnailSync, user)
    
    def killProcess(self, user, pid):
        self._cmdAsUser(user, 'taskkill /PID %d' % pid)
    
    def getVNC(self, user):
        """
        Get VNC password and port for user.
        Returns a tuple of (port, password).
        """
        cfg = config.get()
        def getVncPw():
            command = cfg.get('Agent', 'cmd get vnc password')
            username = user.username.encode('mbcs')
            if '\\' in username:
                username = username[username.index('\\')+1:]
            cmdPath = os.getenv('ComSpec')
            # run command using cmd.exe to take advantage of the support for
            # running python scripts as programs.
            return utils.getProcessOutputAndValue(cmdPath, ['/C', command, username])
        
        def cbGotPw(result):
            out, err, code = result
            port = 5900 + int(user.display)
            if code == 0:
                return port, out.strip()
            else:
                raise Exception('failed to get VNC password for %s: %s' % (user.username, err))
        
        d = getVncPw()
        d.addCallback(cbGotPw)
        return d
    
    def getLogin(self):
        """
        Return port and protocol for login screen.
        """
        return (3389, 'rdp')
    
    def shutdown(self):
        """
        Shutdown system.
        """
        raise NotImplementedError()
    
    def reboot(self):
        """
        Reboot system.
        """
        raise NotImplementedError()
    
    
