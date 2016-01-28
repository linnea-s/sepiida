from twisted.cred import portal
from twisted.conch import avatar
from twisted.conch.checkers import SSHPublicKeyDatabase
from twisted.conch.ssh import factory, userauth, connection, keys, session, forwarding
from twisted.internet import reactor
from twisted.python import log
from zope.interface import implements
import sys
import os
from protocol import AgentProtocol

class ExampleAvatar(avatar.ConchUser):

    def __init__(self, username):
        avatar.ConchUser.__init__(self)
        self.username = username
        self.channelLookup.update({'session': session.SSHSession, 'direct-tcpip': forwarding.openConnectForwardingClient})

class ExampleRealm:
    implements(portal.IRealm)

    def requestAvatar(self, avatarId, mind, *interfaces):
        return interfaces[0], ExampleAvatar(avatarId), lambda: None

class InMemoryPublicKeyChecker(SSHPublicKeyDatabase):
    def __init__(self, authorizedKeysFilename):
        self.authorizedKeysFilename = authorizedKeysFilename
        
    def checkKey(self, credentials):
        import base64, binascii
        if credentials.username != 'sepiida-agent':
            return False
        # based on checkers.SSHPublicKeyDatabase.checkKey
        f = open(self.authorizedKeysFilename, 'r')
        for l in f:
            l2 = l.split()
            if len(l2) < 2:
                continue
            try:
                if base64.decodestring(l2[1]) == credentials.blob:
                    return True
            except binascii.Error:
                log.msg('invalid key: %s' % l)
                continue
        f.close()
        return False

class ExampleSession:
    
    def __init__(self, avatar):
        """
        We don't use it, but the adapter is passed the avatar as its first
        argument.
        """
        
    def getPty(self, term, windowSize, attrs):
        pass
    
    def execCommand(self, proto, cmd):
        ap = AgentProtocol()
        ap.makeConnection(proto)
        proto.makeConnection(session.wrapProtocol(ap))
        
    def openShell(self, trans):
        ap = AgentProtocol()
        ap.makeConnection(trans)
        trans.makeConnection(session.wrapProtocol(ap))
        
    def eofReceived(self):
        pass

    def closed(self):
        pass

from twisted.python import components
components.registerAdapter(ExampleSession, ExampleAvatar, session.ISession)

class ExampleFactory(factory.SSHFactory):
    def __init__(self, privKeyFilename, pubKeyFilename):
        self.publicKeys = {
            'ssh-rsa': keys.Key.fromFile(filename=pubKeyFilename)
        }
        self.privateKeys = {
            'ssh-rsa': keys.Key.fromFile(filename=privKeyFilename)
        }
        self.services = {
            'ssh-userauth': userauth.SSHUserAuthServer,
            'ssh-connection': connection.SSHConnection
        }
