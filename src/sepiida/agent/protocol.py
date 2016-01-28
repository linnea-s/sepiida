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

from twisted.internet import reactor, defer, task
from twisted.protocols import basic
from twisted.python import log
try:
    import json
except ImportError:
    import simplejson as json

import config
from userinfo import UserInfo

class AgentProtocol(basic.Int32StringReceiver):
    MAX_LENGTH = 10000000
    def __init__(self):
        self.userInfo = UserInfo()
    
    def connectionMade(self):
        config.reload()
        # Send hello (info) message
        self._sendInfo(hello=True)
        
        self.update_loop = task.LoopingCall(self._sendUpdatedUserInfo)
        self.update_info_loop = task.LoopingCall(self._sendInfo)        
        def startLooping():
            # Check periodically if anything has changed, and send updated
            # information if necessary
            self.update_loop.start(8.0, True)
            # Send info, e.g. uptime and load every 10 seconds
            self.update_info_loop.start(10.0, False)
        # To avoid PotentialZombieWarning due to the reactor not running,
        # only start looping after the reactor has been started.
        reactor.callWhenRunning(startLooping)
    
    def requestReceived(self, data):
        log.debug('got request: %s' % data)
        req = 'error'
        reqid = 0
        try:
            request = json.loads(data)
            req = request['request']
            args = request['args']
            reqid = request['requestID']
            
            def sendResponse(data):
                self.sendResponse(req, reqid, data)
            
            handler = getattr(self, '_handle' + req.capitalize())
            deferred = defer.Deferred()
            deferred.addCallback(sendResponse)
        except (KeyError, ValueError, AttributeError):
            log.err()
            self.sendResponse(req, reqid, '', 'invalid request')
            return
        handler(deferred, args)
    
    stringReceived = requestReceived
    
    def sendResponse(self, request, requestID, data, error=''):
        response = json.dumps(
                              {'requestID': requestID,
                               'response': request,
                               'data': data,
                               'error': error
                              }
        )
        log.debug('sending response %s' % response)
        self.sendString(response)
    
    def _sendUpdatedUserInfo(self):
        """
        Called by a LoopingCall.
        Check if anything has changed, send updated list of users if necessary.
        """
        def cb(changed):
            if not changed:
                return
            def cbUsers(data):
                self.sendResponse('users', -1, data)
            d = defer.Deferred()
            d.addCallback(cbUsers)
            self._handleUsers(d, [])
            
        self.userInfo.updateUsersProcesses(cb)
    
    def _sendInfo(self, hello=False):
        """
        Called when agent is started and by a LoopingCall.
        Sends updated system information (see _handleInfo).
        """
        if hello:
            reqid = 0
        else:
            reqid = -2
        def cbInfo(data):
            self.sendResponse('info', reqid, data)
        
        d = defer.Deferred()
        d.addCallback(cbInfo)
        self._handleInfo(d, [])
        
    def _dictToUkey(self, udict):
        d = udict
        return (d['username'], d['client'], d['display'])
    
    def _genHandleArgs(self, args):
        """
        Generator which returns a tuple of ukey_dict and corresponding user object or None
        for each ukey in args.
        """
        for ukey_dict in args:
            try:
                ukey = self._dictToUkey(ukey_dict)
                user = self.userInfo.users[ukey]
                yield (ukey_dict, user)
            except KeyError:
                ukey_dict['error'] = 'notfound'
                yield (ukey_dict, None)
    
    def _genericUserRequestHandler(self, deferred, args, cbUser):
        """
        Generic request handler for user requests.
        cbUser is called with the user object and user data (user dict + optional fields)
        for each user, and should return user data or a deferred. 
        """
        def ebFailed(failure, udict):
            log.msg('unhandled failure: %s' % failure)
            udict['error'] = 'failed'
            return udict
        
        deferreds = []
        for udict, user in self._genHandleArgs(args):
            # if user is not found, user is None and udict['error'] is set
            d = defer.maybeDeferred(cbUser, user, udict)
            d.addErrback(ebFailed, udict)
            deferreds.append(d)
        
        def cbSuccess(result):
            deferred.callback([t[1] for t in result])
        
        dl = defer.DeferredList(deferreds)
        dl.addCallback(cbSuccess)
    
    # Request handlers 
    
    def _handleUsers(self, deferred, args):
        """
        Handle request for list of users.
        """
        def genData():
            for user in self.userInfo.users.itervalues():
                yield {'username': user.username, 'client': user.client,
                       'display': user.display, 'name': user.name,
                       'groups': user.groups, 'time': user.logintime,
                       'hwaddr': user.clientHWAddr}

        deferred.callback(list(genData()))
    
    def _handleInfo(self, deferred, args):
        """
        Handle info request, currently this returns uptime and load and OS.
        """
        def reply(bootTime):
            deferred.callback({'uptime': bootTime,
                               'load': self.userInfo.getLoad(),
                               'os': self.userInfo.getOS()})
        db = defer.maybeDeferred(self.userInfo.getBootTime)
        db.addCallback(reply)
        
    def _handleProcesses(self, deferred, args):
        def get(user, udata):
            if user:
                udata['processes'] = self.userInfo.processes[user.username]
            else:
                udata['processes'] = []
            return udata
        
        def cbChanged(changed):
            self._genericUserRequestHandler(deferred, args, get)
        
        self.userInfo.updateUsersProcesses(cbChanged)
    
    def _handleKillprocesses(self, deferred, args):
        """
        Handle request to kill processes.
        """
        user_pid = {}
        def get(user, udata):
            if user:
                pid = int(udata['pid'])
                if pid in user_pid[user.username]:
                    self.userInfo.killProcess(user, pid)
            del udata['pid']
            return udata
        
        def cbChanged(changed):
            for user in self.userInfo.users.itervalues():
                for pid, cmd in self.userInfo.processes[user.username]:
                    user_pid.setdefault(user.username, {})[pid] = 0
            self._genericUserRequestHandler(deferred, args, get)
        self.userInfo.updateUsersProcesses(cbChanged)
    
    def _handleThumbnails(self, deferred, args):
        """
        Handle thumbnails request.
        """
        def get(user, udata):
            def cbSuccess(thumbnail):
                from base64 import b64encode
                udata['thumbnail'] = b64encode(thumbnail)
                return udata
            
            if user:
                d = self.userInfo.getThumbnail(user)
                d.addCallback(cbSuccess)
                return d
            else:
                return udata
        
        self._genericUserRequestHandler(deferred, args, get)
    
    def _handleVnc(self, deferred, args):
        """
        Handle VNC request.
        """
        
        def get(user, udata):
            def errorHandler(failure):
                log.msg('getVNC failed: %s' % failure)
                udata['error'] = 'failed'
                return udata
            def cbSuccess(result):
                port, password = result
                udata['port'] = port
                udata['password'] = password
                return udata
            if not user:
                return udata
            d = self.userInfo.getVNC(user)
            d.addCallback(cbSuccess)
            d.addErrback(errorHandler)
            return d
        
        self._genericUserRequestHandler(deferred, args, get)
    
    def _handleLogin(self, deferred, args):
        """
        Handle login request (e.g. VNC + XDMCP on linux or RDP on windows)
        """
        port, protocol = self.userInfo.getLogin()
        deferred.callback({'port': port, 'protocol': protocol})
    
    def _handleMessage(self, deferred, args):
        def get(user, udata):
            if user:
                self.userInfo.sendMessage(user, udata['message'])
            return udata
        
        self._genericUserRequestHandler(deferred, args, get)
    
    def _handleLogout(self, deferred, args):
        def get(user, udata):
            if user:
                self.userInfo.logoutUser(user)
            return udata
        
        self._genericUserRequestHandler(deferred, args, get)
    
    def _handleLock(self, deferred, args):
        def get(user, udata):
            if user:
                self.userInfo.lockUser(user)
            return udata
        
        self._genericUserRequestHandler(deferred, args, get)
    
    def _handleOpenurl(self, deferred, args):
        def get(user, udata):
            if user:
                try:
                    self.userInfo.openURL(user, udata['url'])
                except NotImplementedError:
                    udata['error'] = 'notimplemented'
            return udata
        
        self._genericUserRequestHandler(deferred, args, get)
    
    def _handleShutdown(self, deferred, args):
        """
        Handle shutdown request
        """
        action = args['action']
        try:
            if action == 'poweroff':
                self.userInfo.shutdown()
            else:
                self.userInfo.reboot()
        except NotImplementedError:
            deferred.callback({'error': 'notimplemented'})
        else:                   
            deferred.callback({})
    