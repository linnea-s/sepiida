from twisted.trial import unittest
from twisted.python import log
from twisted.internet import defer
from sepiida.server import ServerFactory, ServerProtocol, AclFilter, config
import minimock
log.debug = lambda *args: ''

config.reload()

class Transport(object):
    def __init__(self):
        self.written = ''
        self.socket = minimock.Mock('socket', tracker=None)
        self.lostConnection = False
        
    def write(self, s):
        self.written += s
    
    def loseConnection(self):
        self.lostConnection = True

class Server(object):
    pass

class User(object):
    pass

class TestServerProtocol(unittest.TestCase):
    def setUp(self):
        import pwd
        import struct
        pwd.getpwuid = minimock.Mock('pwd.getpwuid', tracker=None)
        pwd.getpwuid.mock_returns = pwd.struct_passwd(('fakeuser', 'x', 123, 123, 'gecos', 'homedir', 'shell'))
        
        struct.unpack = minimock.Mock('struct.unpack', tracker=None)
        struct.unpack.mock_returns = 0, 123, 123 # pid, uid, gid
        
        config.configuration.remove_section('ACL')
        config.configuration.add_section('ACL')
        # force ACLs to be reloaded
        config.configuration._acl = ()
        
        sp = self.sp = ServerProtocol()
        sp.factory = ServerFactory()
        
        self.testUser = testUser = User()
        testUser.name = 'Test User'
        testUser.time = 0
        testUser.username = 'testuser'
        testUser.groups = ['testgroup']
        testUser.client = 'ltsp200'
        testUser.server = 'ltspserver00'
        testUser.display = ':1234'
        testUser.location = 'room0'
        testServer = Server()
        
        self.testServer = s = Server()
        s.hostname = 'ltspserver00'
        s.uptime = 0
        s.load = 0.0
        s.os = 'linux2'
        s.users = {(testUser.username, testUser.server, testUser.client, testUser.display): testUser}
        s.connected = True
        s.location = u'room0'
        s.agentProtocol = minimock.Mock('agentProtocol', tracker=None)
        
        for f in 'getProcesses killProcesses getThumbnails Vnc sendMessage' \
        ' Logout lock openURL'.split():
            m = s.agentProtocol.__dict__[f] = minimock.Mock(f, tracker=None)
            m.mock_returns = defer.succeed(
                                           [{'username': 'testuser', 'client': 'ltsp200', 'display': ':1234',
                                             'mock': 1}]
                                           )
        s.agentProtocol.Login = minimock.Mock('Login', tracker=None)
        s.agentProtocol.Login.mock_returns = defer.succeed({'port': 123})
        
        s.agentProtocol.shutdown = minimock.Mock('shutdown', tracker=None)
        s.agentProtocol.shutdown.mock_returns = defer.succeed({})
        
        sp.factory.servers = {'ltspserver00': s}
        sp.transport = Transport()
    
    def tearDown(self):
        minimock.restore()
    
    def test_NoAcl(self):
        self.sp.connectionMade()
        self.assertTrue(self.sp.transport.lostConnection)
    
    def test_Acl(self):
        config.configuration.set('ACL', 'fakeuser', 'ALL: ALL')
        self.sp.connectionMade()
        self.assertFalse(self.sp.transport.lostConnection)
    
    def test_preFilter(self):
        config.configuration.set('ACL', 'fakeuser', '@testgroup: listUsers sendMessage listServers')
        self.sp.connectionMade()
        self.assertTrue(self.sp._preFilter(self.sp._handleListusers, 0, 'listusers', []))
        self.assertFalse(self.sp._preFilter(self.sp._handleLogin, 0, 'login', []))
        
        udict = self.sp._getUkey(self.testUser)
        args = {self.testServer: [udict]}
        self.sp._preFilter(self.sp._handleSendmessage, 0, 'sendmessage', args)
        self.assertFalse('error' in udict)
        
        self.testUser.groups = ['anothergroup']
        self.assertTrue(self.sp._preFilter(self.sp._handleSendmessage, 0, 'sendmessage', args))
        self.assertTrue('error' in udict)
        
        args = {None: [udict]}
        self.assertTrue(self.sp._preFilter(self.sp._handleSendmessage, 0, 'sendmessage', args))
        
        # specifying a nonexisting server, error should be set
        args = [{'server': 'nonexisting'}]
        self.assertTrue(self.sp._preFilter(self.sp._handleListservers, 0, 'listservers', args))
        self.assertTrue('error' in args[0])
        
        # request not allowed on the user logged in on ltspserver00, error
        # should be set
        args = [{'server': 'ltspserver00'}]
        self.assertTrue(self.sp._preFilter(self.sp._handleListservers, 0, 'listservers', args))
        self.assertTrue('error' in args[0])
        
        # no users on server, therefore OK
        self.testServer.users = {}
        args = [{'server': 'ltspserver00'}]
        self.assertTrue(self.sp._preFilter(self.sp._handleListservers, 0, 'listservers', args))
        self.assertFalse('error' in args[0])
    
    def test_postFilter(self):
        config.configuration.set('ACL', 'fakeuser', '@testgroup: listUsers listServers')
        self.sp.connectionMade()
        
        # allowed to see members of testgroup, shouldn't be filtered
        data = [self.sp._getUkey(self.testUser)]
        data = self.sp._postFilter(data, 'listusers', 'user')
        self.assert_(len(data) == 1)
        
        # allowed to see the one user on ltspserver00, shouldn't be filtered
        data = [{'server': 'ltspserver00'}]
        data = self.sp._postFilter(data, 'listservers', 'server')
        self.assert_(len(data) == 1)
        
        # but not members of anothergroup, should be filtered
        self.testUser.groups = ['anothergroup']
        data = [self.sp._getUkey(self.testUser)]
        data = self.sp._postFilter(data, 'listusers', 'user')
        self.assert_(len(data) == 0)
        
        # not allowed to see the one user on ltspserver00, should be filtered
        data = [{'server': 'ltspserver00'}]
        data = self.sp._postFilter(data, 'listservers', 'server')
        self.assert_(len(data) == 0)
    
    def test_sortUserArgs(self):
        udict = self.sp._getUkey(self.testUser)
        args = self.sp._sortUserArgs([udict])
        self.assert_(args.has_key(self.testServer))
        self.assertEquals(args[self.testServer][0], udict)
        
        udict['server'] = 'nonexisting'
        args = self.sp._sortUserArgs([udict])
        self.assert_(None in args)
        self.assertEqual(args[None][0], udict)
    
    def test_parseRequest(self):
        invalidReq0 = '{}'
        self.assertRaises(ValueError, self.sp._parseRequest, invalidReq0)
        invalidReq1 = '{"args": {}, "request": "listProcesses"}'
        self.assertRaises(ValueError, self.sp._parseRequest, invalidReq1)
        
        # missing server argument
        invalidReq2 = '''{"args": [{"username": "a", "client": "", "display":
        ":0"}], "request": "listProcesses"}'''
        self.assertRaises(ValueError, self.sp._parseRequest, invalidReq2)
        
        # missing url argument
        invalidReq3 = '''{"args": [{"username": "a", "client": "", "display":
        ":0", "server": "b"}], "request": "openUrl"}'''
        self.assertRaises(ValueError, self.sp._parseRequest, invalidReq3)
        
        luReq = '{"args": [], "request": "listUsers"}'
        handler, reqName, args = self.sp._parseRequest(luReq)
        self.assertEqual(handler, self.sp._handleListusers)
        self.assertEqual(reqName.lower(), 'listusers')
        self.assertEqual(args, [])
        
        lpReq = '''{"args": [{"username": "a", "client": "", "display": ":0",
        "server": "b"}], "request": "listProcesses"}'''
        handler, reqName, args = self.sp._parseRequest(lpReq)
        self.assertEqual(handler, self.sp._handleListprocesses)
        self.assertEqual(reqName.lower(), 'listprocesses')
        self.assertEqual(args, [{"username": "a", "client": "", "display":
                                 ":0", "server": "b"}])
    
    def test_requestReceived(self):
        config.configuration.set('ACL', 'fakeuser', '@testgroup: listUsers listProcesses')
        self.sp.connectionMade()
        
        invalidReq0 = ''
        self.sp.transport.written = ''
        self.sp._requestReceived(invalidReq0)
        self.assertEqual(self.sp.transport.written[4:],
                         '{"data": [], "request": "", "requestID": 1, "error": "invalid"}')
        
        # check that preFilter is called, and the request denied
        self.sp.transport.written = ''
        lReq = '{"args": [{"server": "b"}], "request": "login"}'
        self.sp._requestReceived(lReq)
        self.assertEqual(self.sp.transport.written[4:],
                         '{"data": [], "request": "login", "requestID": 2, "error": "notauthorized"}')
        
        # ditto
        self.sp.transport.written = ''
        lpReq = '''{"args": [{"username": "testuser", "client": "ltsp200", "display": ":1234",
        "server": "ltspserver00"}], "request": "listProcesses"}'''
        self.testUser.groups = ['anothergroup'] # so that the ACL won't match
        self.sp._requestReceived(lpReq)
        self.assertIn('"error": "notfound"', self.sp.transport.written)
        
        # check that the handler is called
        self.sp.transport.written = ''
        self.testUser.groups = ['testgroup'] # now the ACL will match
        self.sp._requestReceived(lpReq)
        self.assertIn('"error": ""', self.sp.transport.written)
        
        # now to check that postFilter is called
        # should now see testuser
        self.sp.transport.written = ''
        luReq = '{"args": [], "request": "listUsers"}'
        self.sp._requestReceived(luReq)
        self.assertIn('"username": "testuser"', self.sp.transport.written)
        
        # testuser should be filtered, as the ACL is changed not to match
        self.sp.transport.written = ''
        self.testUser.groups = ['anothergroup']
        self.sp._requestReceived(luReq)
        self.assertNotIn('"username": "testuser"', self.sp.transport.written)
    
    def test_handleListusers(self):
        d = defer.Deferred()
        self.sp._handleListusers(d, 1, 'listusers', [])
        def cbSuccess(result):
            self.assertEqual(result, [{'username': 'testuser', 'name': 'Test User',
                                       'server': 'ltspserver00', 'client': 'ltsp200',
                                       'location': 'room0', 'groups': ['testgroup'],
                                       'time': 0, 'display': ':1234'}])
        d.addCallback(cbSuccess)
        return d
    
    def test_handleListservers(self):
        d = defer.Deferred()
        self.sp._handleListservers(d, 1, 'listservers', [])
        def cbSuccess(result):
            self.assertEqual(result, [{'load': 0.0, 'uptime': 0, 'os':
                                       'linux2', 'users': 1,
                                       'server': 'ltspserver00', 'location': 'room0'}])
        d.addCallback(cbSuccess)
        return d
    
    def test_user_handlers(self):
        userRequests = '''listProcesses killProcesses getThumbnails vnc
        sendMessage logout lockScreen openURL'''.split()
        deferreds = []
        for req in userRequests:
            args = [{"username": "testuser", "client": "ltsp200", "display": ":1234",
                     "server": "ltspserver00"}]
            args = self.sp._sortUserArgs(args)
            def cbSuccess(result, req=req):
                self.assertIn('mock', result[0], req)
            handler = getattr(self.sp, '_handle%s' % req.capitalize())
            d = defer.Deferred()
            d.addCallback(cbSuccess)
            deferreds.append(d)
            handler(d, 0, req.lower(), args)
        return defer.DeferredList(deferreds)
    
    def test_handleLogin(self):
        d = defer.Deferred()
        def cbSuccess(result):
            self.assertEqual(result, [{'port': 123, 'server': 'ltspserver00'}])
        d.addCallback(cbSuccess)
        self.sp._handleLogin(d, 1, 'login', [{'server': 'ltspserver00'}])
        return d
    
    def test_handleShutdown(self):
        d = defer.Deferred()
        def cbSuccess(result):
            self.assertEqual(result, [{'server': 'ltspserver00'}])
        d.addCallback(cbSuccess)
        self.sp._handleShutdown(d, 1, 'shutdown', [{'server': 'ltspserver00', 'action': 'poweroff'}])
        return d
    
    def test_handleShutdown_invalidAction(self):
        d = defer.Deferred()
        def cbSuccess(result):
            self.assertEqual(result, [{'error': 'invalid', 'server': 'ltspserver00'}])
        d.addCallback(cbSuccess)
        self.sp._handleShutdown(d, 1, 'shutdown', [{'server': 'ltspserver00', 'action': 'erroneous'}])
        return d
    