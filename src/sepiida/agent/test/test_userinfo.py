# encoding: utf-8
from twisted.trial import unittest
from sepiida.agent import userinfo, config
from twisted.internet import reactor, defer
from twisted.python import log

config.reload()

class TestUserInfo(unittest.TestCase):
    """
    Test the userInfo class.
    Assumes that the configuration is set up correctly,
    and that there is a logged-in user named sutest.
    """
    def setUp(self):
        self.deferredUpdate = defer.Deferred()
        def cbChanged(changed):
            self.deferredUpdate.callback(changed)
        self.userInfo = userinfo.UserInfo()
        reactor.callWhenRunning(self.userInfo.updateUsersProcesses, cbChanged)
    
    def _getTestUser(self):
        for ukey, user in self.userInfo.users.iteritems():
            if user.username == 'sutest':
                return user
        raise Exception('sutest not found in users')
    
    def test_users_processes(self):
        """Check that the userInfo.users and processes
        variables are non-empty."""
        
        def test(result):
            self.assert_(self.userInfo.users)
            self.assert_(self.userInfo.processes)
        self.deferredUpdate.addCallback(test)
        return self.deferredUpdate
    
    def test_getBootTime(self):
        self.assertIsInstance(self.userInfo.getBootTime(), int)
    
    def test_getOS(self):
        self.assertIsInstance(self.userInfo.getOS(), str)
    
    def test_getLoad(self):
        self.assertIsInstance(self.userInfo.getLoad(), float)
    
    def test_getLogin(self):
        def test(result):
            self.assertIsInstance(result, tuple)
            self.assert_(len(result) == 2)
            self.assertIsInstance(result[0], int)
            self.assertIsInstance(result[1], str)
        d = defer.maybeDeferred(self.userInfo.getLogin)
        d.addCallback(test)
        return d
    
    def _testRequest(self, func, *args):
        def test(result):
            user = self._getTestUser()
            return func(user, *args)
        self.deferredUpdate.addCallback(test)
        return self.deferredUpdate
    
    def test_sendMessage(self):
        """
        Test sending a message. sendMessage may return a deferred which doesn't
        return until the user (tester) has clicked the OK button. 
        """
        return self._testRequest(self.userInfo.sendMessage, u'Æøå')
    
    def test_OpenURL(self):
        return self._testRequest(self.userInfo.openURL, u'http://www.example.com')
    
    def test_getThumbnail(self):
        def checkThumbnail(thumbnail):
            self.assert_('JFIF' in thumbnail, 'not valid JPEG')
            
        d = self._testRequest(self.userInfo.getThumbnail)
        d.addCallback(checkThumbnail)
        return d
    
    def test_killProcess(self):
        """
        Test killing a nonexisting process. killProcess should ignore
        errors in such cases.
        """
        return self._testRequest(self.userInfo.killProcess, -123)
    
    def test_getVNC(self):
        def test(result):
            self.assertIsInstance(result, tuple)
            self.assert_(len(result) == 2)
            self.assertIsInstance(result[0], int)
            self.assertIsInstance(result[1], str)
            port, password = result
            self.assert_(password)
            import socket
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect(('127.0.0.1', port))
            data = s.recv(3)
            self.assertEqual(data, 'RFB')
            s.close()
            
            # wait 10 seconds so that any DelayedCalls will have run
            d2 = defer.Deferred()
            reactor.callLater(10.0, d2.callback, '')
            return d2
            
        d = self._testRequest(self.userInfo.getVNC)
        d.addCallback(test)
        return d
        
    def test_lockUser(self):
        return self._testRequest(self.userInfo.lockUser)
    
    def test_xlogoutUser(self):
        """
        Named xlogoutUser so it will run last.
        """
        d = self._testRequest(self.userInfo.logoutUser)
        d2 = defer.Deferred()
        def testLoggedout(changed):
            try:
                self._getTestUser()
                d2.errback(Exception('testuser still logged in'))
            except Exception:
                d2.callback('') # OK, the user has been logged out
        
        def test(result):
            reactor.callLater(10.0, self.userInfo.updateUsersProcesses, testLoggedout)
            return d2
        d.addCallback(test)
        return d
    
