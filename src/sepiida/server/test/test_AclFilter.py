from twisted.trial import unittest
from sepiida.server import AclFilter
from pyparsing import ParseException
import minimock

class TestAclFilter(unittest.TestCase):
    """
    Test AclFilter class.
    Syntax reminder:
    <who> = <filter>: <requests>
    """
    def setUp(self):
        import grp
        grp.getgrnam = minimock.Mock('grp.getgrnam', tracker=None)
        grp.getgrnam.mock_returns = grp.struct_group(('fakegroup', 'x', -1, ['fakeuser']))
        self.acl = AclFilter.ACL()
    
    def tearDown(self):
        minimock.restore()
    
    def test_parse_empty_who(self):
        self.assertRaises(ParseException, self.acl.parse, '', 'ALL: ALL')
    
    def test_parse_empty_filter(self):
        self.assertRaises(ParseException, self.acl.parse, 'root', '')
    
    def test_parse_empty_requests(self):
        self.assertRaises(ParseException, self.acl.parse, 'root', 'ALL: ')
    
    def test_parse_username_filter(self):
        self.assertRaises(ParseException, self.acl.parse, 'user', 'test: ALL')
    
    def test_parse_incompatible(self):
        """
        parse should raise an exception if @group and ALL are mixed or if
        requestName and ALL are mixed.
        """
        self.assertRaises(ParseException, self.acl.parse, 'user', '@test ALL: ALL')
        self.assertRaises(ParseException, self.acl.parse, 'user', 'ALL: listUsers ALL')
    
    def test_parse_only_sameLocation(self):
        self.acl.parse('user', 'sameLocation: ALL')
    
    def test_appliesTo_user(self):
        self.acl.parse('fakeuser', 'ALL: ALL')
        self.assertTrue(self.acl.appliesTo('fakeuser'))
        self.assertFalse(self.acl.appliesTo('anotherfakeuser'))
    
    def test_appliesTo_group(self):
        self.acl.parse('@fakegroup', 'ALL: ALL')
        self.assertTrue(self.acl.appliesTo('fakeuser'))
        self.assertFalse(self.acl.appliesTo('anotherfakeuser'))
    
    def test_requestAllowed_only_request(self):
        self.acl.parse('fakeuser', 'ALL: listUsers')
        self.assertTrue(self.acl.requestAllowed('listusers'))
        self.assertFalse(self.acl.requestAllowed('listservers'))
    
    def test_requestAllowed(self):
        class User(object):
            location = 'room0'
            groups = ['testgroup']
        subjUser = User()
        
        self.acl.parse('fakeuser', 'ALL: listUsers listProcesses')
        self.assertTrue(self.acl.requestAllowed('listProcesses', 'sepiidauser', ['room0'], subjUser))
        self.assertFalse(self.acl.requestAllowed('listServers', 'sepiidauser', ['room0'], subjUser))
        
        self.acl.parse('fakeuser', 'sameLocation: listUsers listProcesses')
        self.assertTrue(self.acl.requestAllowed('listProcesses', 'sepiidauser', ['room0'], subjUser))
        self.assertFalse(self.acl.requestAllowed('listProcesses', 'sepiidauser', ['room1'], subjUser))
        
        self.acl.parse('fakeuser', '@testgroup: listUsers listProcesses')
        self.assertTrue(self.acl.requestAllowed('listProcesses', 'sepiidauser', ['room0'], subjUser))
        subjUser.groups = ['anothergroup']
        self.assertFalse(self.acl.requestAllowed('listProcesses', 'sepiidauser', ['room0'], subjUser))
    
    def test_requestAllowedServer(self):
        class User(object):
            location = 'room0'
            groups = ['testgroup']
        class Server(object):
            users = {'': User()}
        self.acl.parse('fakeuser', 'ALL: listUsers listServers')
        # allowed: filter is ALL and listServers is in requests
        self.assertTrue(self.acl.requestAllowedServer('listServers', 'sepiidauser', ['room0'], Server()))
        # denied: login is not in requests
        self.assertFalse(self.acl.requestAllowedServer('login', 'sepiidauser', ['room0'], Server()))
        
        self.acl.parse('fakeuser', 'sameLocation: ALL')
        # allowed: the server has one user with the same location as the sepiida user 
        self.assertTrue(self.acl.requestAllowedServer('listServers', 'sepiidauser', ['room0'], Server()))
        # denied: the server has no user with the same location as the sepiida user 
        self.assertFalse(self.acl.requestAllowedServer('listServers', 'sepiidauser', ['room1'], Server()))
        
        self.acl.parse('fakeuser', '@testgroup: listUsers listServers')
        # allowed: the server has one user in the group testgroup
        self.assertTrue(self.acl.requestAllowedServer('listServers', 'sepiidauser', ['room0'], Server()))
        # denied: the server has no user in the group testgroup2
        User.groups = ['testgroup2']
        self.assertFalse(self.acl.requestAllowedServer('listServers', 'sepiidauser', ['room0'], Server()))
        
        Server.users = {}
        # allowed: listServers is in requests and there are no users on server
        self.assertTrue(self.acl.requestAllowedServer('listServers', 'sepiidauser', ['room0'], Server()))
        # denied: login is not in requests
        self.assertFalse(self.acl.requestAllowedServer('login', 'sepiidauser', ['room0'], Server()))
    
    