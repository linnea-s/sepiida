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

from twisted.application import internet, service
from twisted.internet import protocol, reactor, task, defer
from twisted.protocols import basic
from twisted.python import log
import time
import exceptions
try:
    import json
except:
    import simplejson as json

from poller import PollerFactory
import config

class ServerProtocol(basic.Int32StringReceiver):
    MAX_LENGTH = 10000000
    acl = None
    username = None
    
    def connectionMade(self):
        import struct
        import socket
        import pwd
        
        self._nextRID = 0
        
        SO_PEERCRED = 17
        pid, uid, gid = struct.unpack('3i',
            self.transport.socket.getsockopt(
                socket.SOL_SOCKET, SO_PEERCRED,
                        struct.calcsize('3i')))
        
        try:
            self.username = pwd.getpwuid(uid).pw_name
            self.acl = self.factory.getACL(self.username)
        finally:
            if self.acl:
                self._sendResponse('', 'hello', 0)
            else: # no matching ACL for user
                self._sendResponse('', 'hello', 0, 'notauthorized')
                self.transport.loseConnection()
    
    def _getLocations(self):
        """
        Get list of locations for the user connected to Sepiida.
        Note that it is assumed that the usernames refer to the same user,
        if this isn't the case sameLocation shouldn't be used.
        """
        return [user.location for user in self._users() if \
                     user.username == self.username]
    
    def _preFilter(self, handler, reqID, req, args):
        """
        Check if connected user is allowed access to the request
        and the users it applies to.
        Returns False if request is not allowed.
        """
        if not self.acl.requestAllowed(req):
            self._sendResponse([], req, reqID, 'notauthorized')
            return False
        
        assert self.username
        if handler.reqType == 'user':
            # list of udicts sorted by _preProcessArgs
            locations = self._getLocations()
            for server in args:
                if server is None:
                    continue
                for udict in args[server]:
                    user = server.users[self._dictToUkey(udict)]
                    if not self.acl.requestAllowed(req, self.username, locations, user):
                        udict['error'] = 'notfound'
        else:
            locations = self._getLocations()
            for d in args:
                try:
                    server = self.factory.servers[d['server']]
                except KeyError:
                    d['error'] = 'notfound'
                    continue
                if not self.acl.requestAllowedServer(req, self.username, locations, server):
                    d['error'] = 'notfound'
        return True
    
    def _postFilter(self, data, reqName, reqType):
        """
        Filter returned data.
        """
        
        if reqType == 'user':
            locations = self._getLocations()
            def gen():
                for udict in data:
                    user = self.factory.servers[udict['server']].users[self._dictToUkey(udict)]
                    if self.acl.requestAllowed(reqName, self.username, locations, user):
                        yield udict
            return list(gen())
        elif reqType == 'server':
            locations = self._getLocations()
            def gen():
                for d in data:
                    server = self.factory.servers[d['server']]
                    if self.acl.requestAllowedServer(reqName, self.username, locations, server):
                        yield d
            return list(gen())
        
        return data
    
    def _sortUserArgs(self, args):
        """
        Sort userRequest args into a dict indexed by server object, for easy
        forwarding to agent. Unknown servers/users are added to dict[None].
        """
        if not args:
            return args
        args_d = {None: []} # {server: args }
        
        for ukey_dict in args:
            try:
                server = self.factory.servers[ukey_dict['server']]
                ukey = self._dictToUkey(ukey_dict)
                user = server.users[ukey]
                args_d.setdefault(server, []).append(ukey_dict)
            except KeyError: # user offline
                ukey_dict['error'] = 'notfound'
                args_d[None].append(ukey_dict)
        
        return args_d
    
    def _parseRequest(self, jsonString):
        """
        Check if request is valid.
        Returns (handler, reqName, args) or throws ValueError on error.
        """
        try:
            request = json.loads(jsonString)
            reqName = request['request']
            args = request['args']
            handler = getattr(self, '_handle' + reqName.capitalize())
        except (ValueError, KeyError, AttributeError):
            raise ValueError('invalid request')
        
        def ensure(b):
            if not b:
                raise ValueError('invalid request')
        
        ensure(isinstance(args, list))
        required = ('username', 'server', 'client', 'display')
        if args and handler.reqType == 'user':
            for item in args:
                for attr in required:
                    ensure(item.has_key(attr))
                    ensure(isinstance(item[attr], (str, unicode)))
                ensure(not item.has_key('error'))
                for attr in handler.reqAttrs:
                    ensure(item.has_key(attr))
        elif args and handler.reqType == 'server':
            ensure(isinstance(args, list))
            for item in args:
                ensure(isinstance(item, dict))
                ensure(item.has_key('server'))
                ensure(isinstance(item['server'], (str, unicode)))
        return handler, reqName, args
    
    def _requestReceived(self, string):
        self._nextRID += 1
        reqID = self._nextRID
        try:
            handler, reqName, args = self._parseRequest(string)
        except ValueError, ve:
            log.msg('invalid request: %s' % string)
            log.msg(str(ve))
            self._sendResponse([], '', reqID, 'invalid')
            return
        
        deferred = defer.Deferred()
        if handler.postFilter:
            deferred.addCallback(self._postFilter, reqName, handler.reqType)
        deferred.addCallback(self._sendResponse, reqName, reqID)
        
        if handler.reqType == 'user':
            args = self._sortUserArgs(args)
        if self._preFilter(handler, reqID, reqName, args):
            handler(deferred, reqID, reqName, args)
        else: # request not authorized
            pass # preFilter takes care of sending error 
        
    def _sendResponse(self, data, request, requestID, error=''):
        response = json.dumps(
          {'request': request, 'requestID': requestID,
           'data': data,
           'error': error}
        )
        log.debug('Sending response: %s' % response)
        self.sendString(response)
    
    stringReceived = _requestReceived
    
    def _getUkey(self, user):
        """
        Return 'ukey' for a user.
        The ukey is a dict identifying a user.
        """
        return {'username': user.username, 'server': user.server,
                'client': user.client, 'display': user.display }
        
    def _dictToUkey(self, ukey_dict):
        d = ukey_dict
        return (d['username'], d['server'], d['client'], d['display'])
    
    def _users(self):
        """
        Generator which loops through each PollerFactory
        yielding users.
        """
        for poller in self.factory.servers.itervalues():
            if not poller.connected:
                continue
            for user in poller.users.itervalues():
                yield user
    
    def userRequest(attrs=[], postFilter=False):
        def wrapper(func):
            func.reqAttrs = attrs
            func.reqType = 'user'
            func.postFilter = postFilter
            return func
        return wrapper
    
    def serverRequest(attrs=[], postFilter=False):
        def wrapper(func):
            func.reqAttrs = attrs
            func.reqType = 'server'
            func.postFilter = postFilter
            return func
        return wrapper
    
    # request handlers
    @userRequest(attrs=[], postFilter=True)
    def _handleListusers(self, deferred, requestID, request, args):
        """
        Handle listUsers request.
        Returned data is in format:
        [ {'username': .., 'server': .., 'client': .., 'display': ..,
        'name': .., 'groups': [], 'time': 1234567890 } ]
        """
        
        def gen():
            for user in self._users():
                d = self._getUkey(user)
                d['name'] = user.name
                d['groups'] = user.groups
                d['time'] = user.time
                d['location'] = user.location
                yield d
                
        deferred.callback(list(gen()))
    
    @serverRequest(attrs=[], postFilter=True)
    def _handleListservers(self, deferred, requestID, request, args):
        """
        Handle listServers request.
        Returned data is in format:
        [ {'server': 'hostname', 'users': N} ]
        """
        def gen():
            for poller in self.factory.servers.itervalues():
                if not poller.connected:
                    continue
                yield {'server': poller.hostname, 'users': len(poller.users),
                       'uptime': poller.uptime, 'load': poller.load,
                       'os': poller.os, 'location': poller.location}
        
        deferred.callback(list(gen()))        
    
    def _genericHandleRequest(self, reqDeferred, requestID, request, args, ensure, fn_sendreq):
        """
        Generic request handler.
        Args:
         * reqDeferred
         * requestID
         * request
         * args
         * ensure - A tuple of (name, value) to set for offline users
         * fn_sendrequest - Function which should take care of sending the
          request to the server. Called with server object and args.
        """
        
        ret_data = []
        deferreds = []
        
        for server, args in args.iteritems():
            def cbHandleResponse(resp_data, server=server):
                log.debug('cbHandleResponse: %s' % resp_data)
                for ukey_d in resp_data:
                    ukey_d['server'] = server.hostname # expected by client
                ret_data.extend(resp_data)
            
            srv_args = []
            for ukey_d in args:
                # error may be set if the arg has been filtered
                if server is None or 'error' in ukey_d:
                    for var, val in ensure:
                        ukey_d[var] = val
                    ret_data.append(ukey_d)
                else:
                    del ukey_d['server'] # not used by agent
                    srv_args.append(ukey_d)
            if srv_args:     
                deferred = fn_sendreq(server, srv_args)
                deferred.addCallback(cbHandleResponse)
                deferreds.append(deferred)
        
        def cbSendResponse(result):
            log.debug('cbSendResponse: %s' % result)
            reqDeferred.callback(ret_data)
        
        deferredList = defer.DeferredList(deferreds)
        deferredList.addCallback(cbSendResponse)
    
    @userRequest()
    def _handleListprocesses(self, deferred, requestID, request, args):
        """
        Handle listProcesses request.
        Args: ukeys
        Response: [ {ukey + 'processes': [[pid, command]] ]
        """
        def sendRequest(server, args):
            return server.agentProtocol.getProcesses(args)
        self._genericHandleRequest(deferred, requestID, request, args,
                                          [('processes', [])],
                                          sendRequest)
    
    @userRequest(attrs=['pid'])
    def _handleKillprocesses(self, deferred, requestID, request, args):
        """
        Handle killProcesses request.
        Args: [ {ukey, 'pid':} ]
        Response: [ {ukey} ]
        """
        def sendRequest(server, args):
            return server.agentProtocol.killProcesses(args)
        self._genericHandleRequest(deferred, requestID, request, args, [], sendRequest)
    
    @userRequest()
    def _handleGetthumbnails(self, deferred, requestID, request, args):
        """
        Handle getThumbnails request.
        Args: ukeys
        Response: [ {ukey + 'thumbnail': base64 enc. jpg} ]
        """
        def sendRequest(server, args):
            return server.agentProtocol.getThumbnails(args)
        self._genericHandleRequest(deferred, requestID, request, args, [('thumbnail', '')], sendRequest)
    
    @userRequest()
    def _handleVnc(self, deferred, requestID, request, args):
        """
        Handle VNC request.
        Args: ukeys
        Response: [ {ukey + 'port': forwarded TCP port number} ]
        """
        def sendRequest(server, args):
            return server.agentProtocol.Vnc(args)
        self._genericHandleRequest(deferred, requestID, request, args, [('port', '')], sendRequest)
    
    @userRequest(attrs=['message'])
    def _handleSendmessage(self, deferred, requestID, request, args):
        """
        Handle sendMessage request.
        Args: [ {ukey, 'message':} ]
        Response: [ {ukey} ]
        """
        def sendRequest(server, args):
            return server.agentProtocol.sendMessage(args)
        self._genericHandleRequest(deferred, requestID, request, args, [], sendRequest)
    
    @userRequest()
    def _handleLogout(self, deferred, requestID, request, args):
        """
        Handle logout request.
        Args: [ {ukey} ]
        Response: [ {ukey} ]
        """
        def sendRequest(server, args):
            return server.agentProtocol.Logout(args)
        self._genericHandleRequest(deferred, requestID, request, args, [], sendRequest)
    
    @userRequest()
    def _handleLockscreen(self, deferred, requestID, request, args):
        """
        Handle lockScreen request.
        Args: [ {ukey} ]
        Response: [ {ukey} ]
        """
        def sendRequest(server, args):
            return server.agentProtocol.lock(args)
        self._genericHandleRequest(deferred, requestID, request, args, [], sendRequest)
    
    @userRequest(attrs=['url'])
    def _handleOpenurl(self, deferred, requestID, request, args):
        """
        Handle openURL request.
        Args: [ {ukey, 'url': ''} ]
        Response: [ {ukey} ]
        """
        def sendRequest(server, args):
            return server.agentProtocol.openURL(args)
        self._genericHandleRequest(deferred, requestID, request, args, [], sendRequest)
    
    def _genericHandleServerRequest(self, reqDeferred, requestID, request, args, fn_sendrequest):
        """
        Generic server request handler.
        Args:
         * reqDeferred
         * requestID
         * request
         * args
         * fn_sendrequest - Function which should take care of sending the
          request to the server. Called with server object and args.
        """
        
        data = []
        deferreds = []
        for d in args: # {'server': ..., }
            if d.get('error', None):
                data.append(d)
                continue
            try:
                server = self.factory.servers[d['server']]
            except KeyError:
                d['error'] = 'notfound'
                data.append(d)
                continue
            if not server.connected:
                d['error'] = 'notfound'
                data.append(d)
                continue
            
            def cbRequest(rd, server):
                rd['server'] = server.hostname 
                data.append(rd)
            
            del d['server'] # not used by agent
            deferred = fn_sendrequest(server, d)
            deferred.addCallback(cbRequest, server)
            deferreds.append(deferred)
        
        def cbSendResponse(result):
            reqDeferred.callback(data)
        
        deferredList = defer.DeferredList(deferreds)
        deferredList.addCallback(cbSendResponse)
    
    @serverRequest(attrs=['action'])
    def _handleShutdown(self, deferred, requestID, request, args):
        """
        Handle shutdown request.
        Args: [ {'server': server, 'action': 'poweroff' or 'reboot'} ]
        Response: [ {'server': server} ]
        """
        def sendRequest(server, args):
            if args['action'] not in ('poweroff', 'reboot'):
                return defer.succeed({'error': 'invalid'})
            return server.agentProtocol.shutdown(args)
        self._genericHandleServerRequest(deferred, requestID, request, args, sendRequest)
    
    @serverRequest()
    def _handleLogin(self, deferred, requestID, request, args):
        """
        Handle login request, e.g. VNC login screen.
        Args: [ {'server': ..} ]
        Response: [ {'server': .., 'port': forwarded TCP port number} ]
        """
        def sendRequest(server, args):
            return server.agentProtocol.Login(args)
        self._genericHandleServerRequest(deferred, requestID, request, args, sendRequest)
    

class ServerFactory(protocol.ServerFactory):
    protocol = ServerProtocol
    
    def __init__(self):
        # { hostname: PollerFactory }
        self.servers = {}
    
    def startFactory(self):
        cfg = config.configuration
        connect_frequency = cfg.getint('Server', 'connect frequency')
        self.retry_loop = task.LoopingCall(self.retryServers)
        self.retry_loop.start(connect_frequency, True)
        
        self.reload_loop = task.LoopingCall(self.reloadConfig)
        self.reload_loop.start(30.0, False)
    
    def reloadConfig(self):
        """Reload configuration if necessary."""
        if not config.updated():
            return
        
        try:
            config.reload()
            log.msg('reloaded configuration')
        except:
            log.err()
            log.msg('failed to reload configuration')
    
    def retryServers(self):
        """Try/retry connection to servers"""
        cfg = config.configuration
        def hosts():
            for key, hosts in cfg.getHosts():
                if key[0] == '@': # Host key alias
                    alias = key[1:]
                else:
                    alias = None
                
                for host in hosts:
                    yield host, alias
        
        for hostname, alias in hosts():
            try:
                poller = self.servers[hostname]
            except KeyError:
                poller = self.servers[hostname] = PollerFactory(hostname, alias)
                poller.notified_error = False
            
            if poller.connected or poller.connecting:
                continue
            poller.connecting = True
            
            def cbConnected(factory, poller=poller):
                log.msg('connected to server/workstation %s' % poller.hostname)
                
            def ebFailed(reason, poller=poller):
                # Try to keep the size of the logfile down by only notifying
                # of the same error once.
                if not poller.notified_error:
                    log.err('failed to connect to %s: %s' % (poller.hostname, reason))
                    poller.notified_error = True
            
            deferred = poller.deferred = defer.Deferred()                            
            deferred.addCallback(cbConnected)
            deferred.addErrback(ebFailed)
            
            # Delay in order to space out connection attempts
            import random
            reactor.callLater(random.uniform(0.0, 10.0),
                              reactor.connectTCP, poller.hostname, 22, poller)
    
    def getACL(self, username):
        """
        Return the first matching ACL for uid.
        Called by ServerProtocol.connectionMade. If None is returned,
        the connection should be dropped.
        """
        acl = config.configuration.getACL()
        for a in acl:
            if a.appliesTo(username):
                return a
        return None
