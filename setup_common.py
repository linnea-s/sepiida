#!/usr/bin/env python
from distutils.core import setup

setup(name='sepiida-common',
      version='0.5',
      description='Sepiida common',
      author='Linnea Skogtvedt',
      author_email='linnea@linuxavdelingen.no',
      url='http://sepiida.linuxavdelingen.no',
      packages=['sepiida'],
      package_dir={'sepiida': 'src/sepiida'},
      scripts=['scripts/sepiida-shclient']
     )

