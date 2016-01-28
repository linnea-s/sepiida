#!/usr/bin/python
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

from ConfigParser import RawConfigParser
from twisted.python import log
import os
import time

config_file = '/etc/sepiida/server.conf'
read_at = 0

class SepiidaConfigParser(RawConfigParser):
    def __init__(self):
        RawConfigParser.__init__(self)
        self._hosts = ()
        self._acl = ()
        
    def _expandRange(self, host):
        """
        Expand ranges of the form ws00-50 or ws00-50.example.org
        """
        import re
        re_range = re.compile('^(.*?)(\d+)-(\d+)(\.[\w\.]+)?$')
        m = re_range.match(host)
        if m:
            base, begin, end, domain = m.groups()
            formatstr = '%s%0' + str(len(begin)) + 'd' + '%s'
            for n in xrange(int(begin), int(end)+1):
                yield formatstr % (base, n, domain or '')
        else:
            yield host
        
    def getHosts(self):
        if not self._hosts:
            hosts = []
            for key, value in self.items('Hosts'):
                key_hosts = []
                for host in value.split():
                    key_hosts.extend(self._expandRange(host))
                hosts.append( (key, tuple(key_hosts)) )
            self._hosts = tuple(hosts)
            
        return self._hosts
    
    def getACL(self):
        import AclFilter
        if self._acl:
            return self._acl
        
        acl = []
        for key, value in self.items('ACL'):
            if key == 'allow groups':
                log.msg('Warning: option [ACL] allow groups is no longer used')
                continue
            
            try:
                a = AclFilter.ACL()
                a.parse(key, value)
                acl.append(a)
            except AclFilter.ParseBaseException, exc:
                log.msg('invalid ACL line: %s = %s' % (key, value))
                continue
        
        self._acl = tuple(acl)
        return self._acl

configuration = SepiidaConfigParser()

def updated():
    """
    Check if configuration file has been modified since the last time
    it was read.
    """
    return os.stat(config_file).st_mtime > read_at

def reload():
    global configuration
    config = SepiidaConfigParser()
    
    global read_at
    read_at = time.time()
    config.readfp(open(config_file))
    
    required = { 'Server':
                ('unix socket', 'poll frequency',
                 'connect frequency', 'agent user',
                 'agent cmd', 'log debug',
                 'SSH key', 'known hosts'),
                 
                 'Hosts': (),
                 'ACL': ()
                }
    
    for section in required:
        for key in required[section]:
            test = config.get(section, key) # throws exception if missing
    
    test = config.getHosts()
    test = config.getACL()
    
    configuration = config
