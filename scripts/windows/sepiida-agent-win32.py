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

import site
site.addsitedir(r'c:\sepiida\lib')

from twisted.internet import reactor
from twisted.python import log
from sepiida.agent import sshserver
from twisted.cred import portal
import os
import sys
from sepiida.agent import config

if __name__ == '__main__':
    log.startLogging(sys.stderr)
    log.msg('For testing only, must be run as System for all features to work.')
    def noop(s):
        pass
    log.debug = noop
    
    config.reload()
    p = portal.Portal(sshserver.ExampleRealm())
    p.registerChecker(sshserver.InMemoryPublicKeyChecker(os.path.join(r'c:\sepiida', 'authorized_keys.txt')))
    privKeyFn = os.path.join(r'c:\sepiida', 'ssh_host_rsa_key')
    pubKeyFn = privKeyFn + '.pub'
    factory = sshserver.ExampleFactory(privKeyFn, pubKeyFn)
    factory.portal = p
    reactor.listenTCP(22, factory)
    reactor.run()