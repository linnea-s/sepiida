#!/usr/bin/env python
from distutils.core import setup

setup(name='sepiida-server',
      version='0.5',
      description='Sepiida server',
      author='Linnea Skogtvedt',
      author_email='linnea@linuxavdelingen.no',
      url='http://sepiida.linuxavdelingen.no',
      packages=['sepiida.server'],
      package_dir={'sepiida': 'src/sepiida'},
      scripts=['scripts/sepiida-connect', 'scripts/sepiida-connect-port', 'scripts/sepiida-server', 'scripts/sepiida-get-location']
     )

