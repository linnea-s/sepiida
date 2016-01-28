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

from twisted.internet import protocol, reactor, defer, task, utils
from twisted.python import log
from twisted.protocols import basic
from twisted.conch import error
from twisted.conch.ssh import transport
from twisted.conch.ssh import keys, userauth
from twisted.conch.ssh import connection
from twisted.conch.ssh import channel, common, forwarding
from twisted.conch.client.default import isInKnownHosts
from twisted.application import service
import sys
try:
    import json
except:
    import simplejson as json
import time
import config

class ClientTransport(transport.SSHClientTransport):
    def verifyHostKey(self, pubkey, fingerprint):
        cfg = config.configuration
        name = self.factory.alias or self.factory.hostname
        options = {'known-hosts': cfg.get('Server', 'known hosts')}
        found = isInKnownHosts(name, pubkey, options)
        if found == 0:
            log.err('host key for %s not found' % name)
            return defer.fail(error.ConchError('host key for %s not found' % name))
        elif found == 2:
            log.err('host key for %s has changed' % name)
            return defer.fail(error.ConchError('host key for %s has changed' % name))
        else:
            return defer.succeed(1)
    
    def connectionSecure(self):
        conn = ClientConnection()
        conn.factory = self.factory
        self.requestService(ClientUserAuth(self.factory.username, conn))
    
class ClientUserAuth(userauth.SSHUserAuthClient):

    def getPassword(self, prompt = None):
        return None

    def getPublicKey(self):
        if self.lastPublicKey:
            return
        return keys.Key.fromFile(filename=self.instance.factory.privkey+'.pub')
    
    def getPrivateKey(self):
        return defer.succeed(keys.Key.fromFile(self.instance.factory.privkey))

class ClientConnection(connection.SSHConnection):

    def serviceStarted(self):
        self.openChannel(AgentChannel(conn = self))
    
    def channelClosed(self, channel):
        connection.SSHConnection.channelClosed(self, channel)
        if not self.channels.keys():
            self.transport.loseConnection()


class AgentChannel(channel.SSHChannel):

    name = 'session'
    
    def channelOpen(self, data):
        self.agentprotocol = AgentProtocol(self.conn)
        self.dataReceived = self.agentprotocol.dataReceived
        d = self.conn.sendRequest(self, 'exec', common.NS(self.conn.factory.agentcmd),
                                  wantReply = True)
        d.addCallback(self._cbProtocol)
        d.addErrback(self._ebProtocol)

    def _cbProtocol(self, ignored):
        self.agentprotocol.makeConnection(self)
        
    def _ebProtocol(self, ignored):
        log.err('request failed')
    
    def closed(self):
        self.agentprotocol.connectionLost()

class AgentProtocol(basic.Int32StringReceiver):
    MAX_LENGTH = 10000000
    
    def __init__(self, conn):
        self._nextid = 0 # next request ID
        self._requests = {} # dict mapping request ID to deferred/callback
        self.conn = conn
        
        # There are three special request IDs:
        #  0: hello (contains "info", e.g. uptime and load)
        # -1: updated user info
        # -2: updated info
        
        def cbHello(data):
            self._requests[-1] = self.conn.factory.userInfoReceived
            self._requests[-2] = self.conn.factory.infoReceived
            self.conn.factory.connectionMade(self)
            self.conn.factory.infoReceived(data)
            
        self._requests[0] = cbHello
    
    def _responseReceived(self, response):
        """
        Called when a response is received.
        Calls back the deferred corresponding to the requestID returned
        with the data returned.
        """
        log.debug('Response received: %s' % response)
        agent_response = json.loads(response)
        
        try:
            requestID = agent_response['requestID']
        except KeyError:
            log.err('Received response not containing a requestID')
            return
        
        try:
            if requestID < 0:
                cbOrDeferred = self._requests[requestID]
            else:
                cbOrDeferred = self._requests.pop(requestID)
        except KeyError:
            log.err('Received invalid requestID')
            return
        
        try:
            data = agent_response['data']
        except KeyError:
            log.err('Received response not containing data')
            return
        
        try:
            err = agent_response['error']
            if err:
                log.err('received an error: %s' % err)
        except KeyError:
            err = ''        
        
        self._receivedResponse = True
        if callable(cbOrDeferred):
            cbOrDeferred(data)
        else:
            cbOrDeferred.callback(agent_response['data'])
            
    stringReceived = _responseReceived
    
    def connectionMade(self):
        pass
    
    def connectionLost(self):
        pass
        
    def _sendRequest(self, request, args=[]):
        """
        Send request to agent containing a requestID.
        Return deferred which is called back when a response is received
        containing the requestID.
        """
        deferred = defer.Deferred()
        self._requests[self._nextid] = deferred
        agent_request = json.dumps(
          {'request': request, 'requestID': self._nextid,
           'args': args}
        )
        log.debug('Sending request: %s' % agent_request)
        self.sendString(agent_request)
        self._nextid += 1
        return deferred
    
    def getUsers(self):
        """
        Send request for users.
        """
        deferred = self._sendRequest('users')
        return deferred
    
    def getProcesses(self, args):
        """
        Send request for processes.
        """
        deferred = self._sendRequest('processes', args)
        return deferred
    
    def killProcesses(self, args):
        """
        Send request to kill processes.
        """
        deferred = self._sendRequest('killProcesses', args)
        return deferred
    
    def getThumbnails(self, args):
        """
        Send request to get thumbnails.
        """
        return self._sendRequest('thumbnails', args)
    
    def openSSHForwarding(self, port):
        """
        Open SSH forwarding which is closed after 10 seconds if no connection
        is made.
        Arguments:
         port - remote port number
        Returns: local port number
        """
        class Scope(object):
            pass
        def createFwdChannel(scope):
            class FwdChannel(forwarding.SSHListenClientForwardingChannel):
                def loseConnection(self):
                    scope.tcpPort.loseConnection()
                    forwarding.SSHListenClientForwardingChannel.loseConnection(self)
                    
                def channelOpen(self, specificData):
                    forwarding.SSHListenClientForwardingChannel.channelOpen(self, specificData)
                    scope.connected = True
            return FwdChannel
            

        # TODO: check the UID of the user connecting to the forwarded port?
        scope = Scope()
        sshListenFwdFactory = \
            forwarding.SSHListenForwardingFactory(self.conn,
                                                  ('127.0.0.1', port),
                                                  createFwdChannel(scope))
        p = reactor.listenTCP(0, sshListenFwdFactory, interface='127.0.0.1')
        scope.tcpPort = p
        scope.connected = False
        def closePort(scope=scope):
            # if no connection has been made, stop listening
            if not scope.connected:
                scope.tcpPort.loseConnection()
        reactor.callLater(10.0, closePort)
        return p.getHost().port
    
    def Vnc(self, args):
        """
        Send VNC request. The agent returns local ports, a SSH forwarding
        needs to be created for each port.
        """
        
        class Scope(object):
            pass
        def createFwdChannel(scope):
            class FwdChannel(forwarding.SSHListenClientForwardingChannel):
                def loseConnection(self):
                    scope.tcpPort.loseConnection()
                    forwarding.SSHListenClientForwardingChannel.loseConnection(self)
                    
                def channelOpen(self, specificData):
                    forwarding.SSHListenClientForwardingChannel.channelOpen(self, specificData)
                    scope.connected = True
            return FwdChannel
            
        
        def openSSHForwardings(data):
            # data is in format:
            # { ukey_d, 'port': 123 }
            
            for ukey_d in data:
                if ukey_d.get('error', ''):
                    continue
                ukey_d['port'] = self.openSSHForwarding(ukey_d['port'])
            return data      
        
        deferred = self._sendRequest('vnc', args)
        deferred.addCallback(openSSHForwardings)
        return deferred
    
    def Login(self, args):
        """
        Send login (e.g. Xvnc + XDMCP) request.
        Args: []
        Returns: { 'port': 1234 }
        """
        def cbLogin(d):
            if d.get('error', ''):
                return d
            else:
                d['port'] = self.openSSHForwarding(d['port'])
                return d              
                
        deferred = self._sendRequest('login', args)
        deferred.addCallback(cbLogin)
        return deferred
    
    def sendMessage(self, args):
        """
        Send request to send message to users.
        """
        return self._sendRequest('message', args)
    
    def Logout(self, args):
        """
        Send request to logout users.
        """
        return self._sendRequest('logout', args)
    
    def lock(self, args):
        """
        Send request to lock screen.
        """
        return self._sendRequest('lock', args)
    
    def openURL(self, args):
        """
        Send request to open URL.
        """
        return self._sendRequest('openURL', args)
    
    def shutdown(self, args):
        """
        Send shutdown request.
        """
        return self._sendRequest('shutdown', args)

class User(object):
    def __init__(self):
        self.username = None
        self.server = None
        self.client = None
        self.clientHWAddr = None
        self.display = None
        self.time = None
        self.processes = None
        self.name = None
        self.groups = None
        self.location = None
    
    def __repr__(self):
        return 'User("%s@%s@%s:%s")' % (self.username, self.client, self.server, self.display)   

class PollerFactory(protocol.ClientFactory):
    protocol = ClientTransport
    
    def __init__(self, hostname, alias):
        self.deferred = None
        self.hostname = hostname
        self.alias = alias # host key alias
        self.stopped = False
        self.connected = False
        self.connecting = False
        self.username = config.configuration.get('Server', 'agent user')
        self.agentcmd = config.configuration.get('Server', 'agent cmd')
        self.privkey = config.configuration.get('Server', 'SSH key')
        self.users = {}
        
        self.uptime = None
        self.load = None
        self.os = None
        self.location = None
        self.lastResponse = None
        self._watchdogCall = task.LoopingCall(self._watchdog)
    
    def userInfoReceived(self, userinfo):
        users = {}
        # [ {'username': user, 'client': client, 'display': display, 'name': name, 'groups': ['group1']}) ]
        for udict in userinfo:
            username = udict['username']
            client = udict['client']
            clientHWAddr = udict['hwaddr']
            display = udict['display']
            name = udict['name']
            groups = udict['groups']
            ltime = udict['time']
            
            ukey = (username, self.hostname, client, display)
            try:
                user = users[ukey] = self.users[ukey]
            except KeyError:
                user = User()
                user.username = username
                user.server = self.hostname
                user.client = client
                user.clientHWAddr = clientHWAddr
                user.display = display
                user.name = name
                user.groups = groups
                user.time = ltime
                user.location = ''
                users[ukey] = user
            
            def cbGotLocation(location, user=user):
                user.location = location
            
            d = self._getLocation(self.hostname, client, clientHWAddr)
            d.addCallback(cbGotLocation)
            
        self.users = users
    
    def _getLocation(self, servername, clientname, hwaddr):
        def cbSuccess(data):
            out, err, retval = data
            if retval == 0:
                return out.rstrip().decode('utf-8', 'replace')
            else:
                return u''
            
        args = [x.encode('utf-8', 'replace') for x in 
                (servername, clientname, hwaddr)]
        d = utils.getProcessOutputAndValue('/usr/bin/sepiida-get-location', args)
        d.addCallback(cbSuccess)
        return d
        
    def infoReceived(self, data):
        # {'uptime': 1234567890, 'load': 0.50, 'os': 'linux2'}
        self.uptime = int(data['uptime'])
        self.load = float(data['load'])
        self.lastResponse = time.time()
        self.os = data['os']
        
    def connectionMade(self, agentProtocol):
        self.agentProtocol = agentProtocol
        self.users.clear()
        self.connected = True
        self.deferred.callback(self)
        self._watchdogCall.start(10.0, False)
    
    def clientConnectionFailed(self, connector, reason):
        #log.err('%s: connection failed: %s' % (self, reason))
        try:
            self.deferred.errback(reason)
        except defer.AlreadyCalledError:
            pass
    
    def clientConnectionLost(self, connector, reason):
        log.msg('%s: lost connection: %s' % (self, reason))
    
    def __repr__(self):
        return 'PollerFactory("%s")' % self.hostname
    
    def startFactory(self):
        self.stopped = False
        self.connected  = False
        
        def cbLocation(location):
            self.location = location
        d = self._getLocation(self.hostname, '', '')
        d.addCallback(cbLocation)
    
    def stopFactory(self):
        self.stopped = True
        self.connected = False
        self.connecting = False
        if self._watchdogCall.running:
            self._watchdogCall.stop()
    
    def _watchdog(self):
        now = time.time()
        if (now - self.lastResponse) > 15:
            log.err('%s: no response, closing connection' % self)
            self.agentProtocol.conn.transport.loseConnection()
            self.stopFactory()
