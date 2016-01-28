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

import win32service, win32serviceutil
from twisted.internet import reactor
from twisted.python import log
import sshserver
from twisted.cred import portal
import os
import config

# Ensure basic thread support is enabled for twisted
from twisted.python import threadable
threadable.init(1)

class Service(win32serviceutil.ServiceFramework):
    _svc_name_ = 'sepiida-agent'
    _svc_display_name_ = 'Sepiida agent'
    
    def SvcStop(self):
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        log.msg('Stopping service...')
        reactor.callFromThread(reactor.stop)

    def SvcDoRun(self):
        log.startLogging(open(r'c:\sepiida\sepiida-agent.log', 'w'))
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
        reactor.run(installSignalHandlers=0)
        
if __name__ == "__main__":
    win32serviceutil.HandleCommandLine(Service)
