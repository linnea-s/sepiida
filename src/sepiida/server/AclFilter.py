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

import grp
from pyparsing import Word, CaselessKeyword, Combine, Group, OneOrMore, \
    Literal, stringEnd, Suppress, ParseBaseException, alphanums, NoMatch

class ACL(object):
    """
    ACL/filter class.
    """

    def __init__(self):
        self._who = []
        self._filter = []
        self._allowedRequests = []
        
    def parse(self, key, value):
        """
        Parse the ACL/filters in the [ACL] section.
        They have the following format:
        <who> = <filter>: <requests>
        
        Where:
         who is one or more of: @group or a username (user connecting to Sepiida)
         filter is one or more of: ALL or @group or sameLocation
         requests is one or more of: ALL or request name (not currently checked)
        """
        def failToken(s):
            """
            pyparsing hack to give better error messages,
            "a or b expected" rather than "b expected". 
            """
            t = NoMatch()
            t.setName(s)
            return t
        identifierChars = alphanums + '_-'
        group = Word('@', identifierChars)
        kwAll = CaselessKeyword('ALL')
        kwSameLocation = CaselessKeyword('sameLocation')
        # make sure the case is always the same after parsing
        kwAll.setParseAction(lambda tokens: 'ALL')
        kwSameLocation.setParseAction(lambda tokens: 'sameLocation')
        
        user = ~(kwAll | kwSameLocation) + Word(identifierChars)
        request = ~(kwAll | kwSameLocation) + Word(identifierChars)
        request.setParseAction(lambda tokens: tokens[0].lower())
        
        who = Group(OneOrMore(failToken("@group or username") | group | user)).setResultsName('who')
        filter_ = Group(failToken("ALL or sameLocation or @group") | kwAll | OneOrMore(group | kwSameLocation)).setResultsName('filter')
        requests = Group(failToken("ALL or request name") | kwAll | OneOrMore(request)).setResultsName('requests')
        
        lhs = who + stringEnd
        rhs = filter_ + Suppress(':') + requests + stringEnd
        
        r1 = lhs.parseString(key)
        r2 = rhs.parseString(value)
        
        self._who = r1.who.asList()
        self._filter = r2.filter.asList()
        self._allowedRequests = r2.requests.asList()
    
    def appliesTo(self, username):
        """
        Return True if this ACL applies to username, otherwise False
        """
        if username in self._who:
            return True
        groups = [g[1:] for g in self._who if g.startswith('@')]
        for group in groups:
            if username in grp.getgrnam(group).gr_mem:
                return True
        return False
    
    def requestAllowed(self, request, reqUser=None, reqUserLoc=None, subjUser=None):
        """
        Return True if the ACL allows the request, otherwise False.
        Arguments:
         * request     - the Sepiida request, only required argument
         * reqUser     - username of the (Sepiida) user making the request
         * reqUserLoc  - list of locations for user making the request
         * subjUser    - user object for the user the request applies to
        """
        if 'ALL' not in self._allowedRequests:
            if request.lower() not in self._allowedRequests:
                return False
        
        if reqUser is None:
            return True
        
        if 'ALL' in self._filter:
            return True
        
        if reqUserLoc and 'sameLocation' in self._filter:
            if not [loc for loc in reqUserLoc if loc == subjUser.location]:
                return False
        
        # Return True if subjUser is member of any groups in filter,
        # or if no groups have been specified (only ALL or sameLocation)
        groups = [g[1:] for g in self._filter if g.startswith('@')]
        if not groups or [g for g in groups if g in subjUser.groups]:
            return True
        return False
    
    def requestAllowedServer(self, request, reqUser, reqUserLoc, server):
        """
        Return True if requestAllowed returns True for any of the users on server,
        otherwise False.
        If no users are logged in on the server, return requestAllowed(request).
        """
        if server.users:
            for user in server.users.itervalues():
                if self.requestAllowed(request, reqUser, reqUserLoc, user):
                    return True
        else:
            return self.requestAllowed(request)
        return False
