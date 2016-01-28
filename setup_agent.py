#!/usr/bin/env python
from distutils.core import setup

setup(name='sepiida-agent',
      version='0.5',
      description='Sepiida agent',
      author='Linnea Skogtvedt',
      author_email='linnea@linuxavdelingen.no',
      url='http://sepiida.linuxavdelingen.no',
      packages=['sepiida.agent'],
      package_dir={'sepiida': 'src/sepiida'},
      scripts=['scripts/sepiida-agent', 'scripts/sepiida-agent-connect', 'scripts/sepiida-vnc-proxy-ssh']
     )  
