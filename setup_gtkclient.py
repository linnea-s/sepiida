#!/usr/bin/env python
from distutils.core import setup
from DistUtilsExtra.command import *

setup(name='sepiida-gtk',
      version='0.5',
      description='Sepiida GTK+ client',
      author='Linnea Skogtvedt',
      author_email='linnea@linuxavdelingen.no',
      url='http://sepiida.linuxavdelingen.no',
      packages=['sepiida.gtkclient'],
      package_dir={'sepiida': 'src/sepiida'},
      scripts=['scripts/sepiida-gtk'],
      cmdclass = {
                  'build': build_extra.build_extra,
                  'build_i18n': build_i18n.build_i18n
                  },
      data_files = []
     )

