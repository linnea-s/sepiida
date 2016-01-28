from twisted.trial import unittest
from sepiida.agent import protocol
from twisted.internet import reactor, defer
from twisted.python import log

log.debug = lambda s: None
#import sys
#log.startLogging(sys.stderr)

try:
    import json
except ImportError:
    import simplejson as json

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

class DummyUserInfo(object):
    def __init__(self):
        self.users = {}
        self.processes = {} # {"username": [ (pid, commandline)] }
        
    def updateUsersProcesses(self, cbChanged):
        user = User()
        user.username = 'testuser'
        user.client = ''
        user.display = ':10'
        user.name = 'Test User'
        user.groups = ['test']
        user.logintime = 0
        user.clientHWAddr = '00:01:02:03:04:05'
        users = {(user.username, user.client, user.display): user}
        self.users = users
        self.processes[user.username] = [(0, 'testprocess')]
        cbChanged(True)
    
    def getBootTime(self):
        return 0
    
    def getOS(self):
        return 'test'
    
    def getLoad(self):
        return 0.0
    
    def logoutUser(self, user):
        pass
        
    def sendMessage(self, user, message):
        pass
    
    def lockUser(self, user):
        pass
    
    def openURL(self, user, url):
        pass
    
    def getThumbnail(self, user):
        return defer.succeed('')
    
    def killProcess(self, user, pid):
        pass
    
    def getVNC(self, user):
        return defer.succeed((0, 'password'))
    
    def getLogin(self):
        return (0, 'test')

class DummyTransport(object):
    def __init__(self):
        self.written = ''
    def write(self, s):
        self.written += s

class TestAgentProtocol(unittest.TestCase):
    def setUp(self):
        self.ap = protocol.AgentProtocol()
        self.ap.userInfo = DummyUserInfo()
        self.ap.transport = DummyTransport()
        self.ap.connectionMade()
        def stopLooping():
            self.ap.update_loop.stop()
            self.ap.update_info_loop.stop()
        reactor.callWhenRunning(stopLooping)
    
    def _testRequestHandler(self, handler, expect, args):
        def test(result):
            key, value = expect
            if key is None:
                return
            if isinstance(result, list):
                result = result[0]
            if not result.has_key(key) or not result[key] == value:
                raise Exception('got %s, expected %s' % (result, expect))
            
        d = defer.Deferred()
        d.addCallback(test)
        reactor.callWhenRunning(handler, d, args)
        return d
    
    _testRequests = [('processes', 'processes', [(0, 'testprocess')], None),
                     ('killProcesses', None, None, [{'username': 'testuser', 'client': '', 'display': ':10', 'pid': 0}]),
                     ('thumbnails', 'thumbnail', '', None),
                     ('vnc', 'port', 0, None),
                     ('login', 'port', 0, []),
                     ('message', None, None, [{'username': 'testuser', 'client': '', 'display': ':10', 'message': 'test'}]),
                     ('logout', None, None, None),
                     ('lock', None, None, None),
                     ('openurl', None, None, [{'username': 'testuser', 'client': '', 'display': ':10', 'url': 'http://test'}])]
    
    def test_handlers(self):
        deferreds = []
        for reqName, expectKey, expectVal, args in self._testRequests:
            if args is None:
                args = [{'username': 'testuser', 'client': '', 'display': ':10'}] 
            handler = getattr(self.ap, '_handle%s' % reqName.capitalize())
            deferreds.append(self._testRequestHandler(handler, (expectKey, expectVal), args))
        return defer.DeferredList(deferreds)
    
    def test_handlers_notfound(self):
        deferreds = []
        args = [{'username': 'nonexisting', 'client': '', 'display': ':10'}]
        for reqName, expectKey, expectVal, unusedargs in self._testRequests[0:1]:
            handler = getattr(self.ap, '_handle%s' % reqName.capitalize())
            deferreds.append(self._testRequestHandler(handler, ('error', 'notfound'), args))
        return defer.DeferredList(deferreds)
     
    
    def test_connectionMade(self):
        """
        The agent protocol should write system information when a connection
        is made.
        """
        infoWritten = json.loads(self.ap.transport.written[4:])
        self.assert_(isinstance(infoWritten, dict))
        self.assertIn('data', infoWritten)
        self.assertIn('uptime', infoWritten['data'])
        
        d = defer.Deferred()
        def checkUpdateUsersProcessesCalled():
            assert self.ap.userInfo.users
            d.callback('')
        reactor.callLater(0.1, checkUpdateUsersProcessesCalled)
        return d
    
    def test_handleUsers(self):
        d = defer.Deferred()
        def check(result):
            assert result == [{'username': 'testuser', 'name': 'Test User',
                               'client': '', 'groups':['test'], 'time': 0, 'hwaddr': '00:01:02:03:04:05', 'display': ':10'}]
            
        d.addCallback(check)
        reactor.callWhenRunning(self.ap._handleUsers, d, [])
        return d
    
    def test_requestReceived(self):
        req = {'request': 'users',
               'args': [],
               'requestID': 1}
        expected_response = {
                             'response': 'users', 'data': [{'username':'testuser','name': 'Test User',
                             'client': '', 'groups': ['test'], 'time': 0, 'hwaddr': '00:01:02:03:04:05', 'display': ':10'}], 'requestID': 1, 'error': ''
        }
        d = defer.Deferred()
        def check():
            result = json.loads(self.ap.transport.written[4:])
            if result == expected_response:
                d.callback('')
            else:
                d.errback(Exception('got %s, expected %s' % (result, expected_response)))

        def test():
            self.ap.transport.written = ''
            self.ap.requestReceived(json.dumps(req))
            reactor.callLater(0.1, check)
        reactor.callWhenRunning(test)
        return d
