#!/usr/bin/env python
from distutils.core import setup
from glob import glob

# opj and find_data_files are from http://wiki.python.org/moin/Distutils/Tutorial
import os, fnmatch
def opj(*args):
    path = os.path.join(*args)
    return os.path.normpath(path)

def find_data_files(srcdir, *wildcards, **kw):
    # get a list of all files under the srcdir matching wildcards,
    # returned in a format to be used for install_data
    def walk_helper(arg, dirname, files):
        if '.svn' in dirname:
            return
        names = []
        lst, wildcards = arg
        for wc in wildcards:
            wc_name = opj(dirname, wc)
            for f in files:
                filename = opj(dirname, f)

                if fnmatch.fnmatch(filename, wc_name) and not os.path.isdir(filename):
                    names.append(filename)
        if names:
            lst.append( (os.path.join(target, dirname), names ) )

    file_list = []
    recursive = kw.get('recursive', True)
    target = kw.get('target', '')
    if recursive:
        os.path.walk(srcdir, walk_helper, (file_list, wildcards))
    else:
        walk_helper((file_list, wildcards),
                    srcdir,
                    [os.path.basename(f) for f in glob.glob(opj(srcdir, '*'))])
    return file_list



setup(name='sepiida-agent-windows',
      version='0.5',
      description='Sepiida agent for windows',
      author='Linnea Skogtvedt',
      author_email='linnea@linuxavdelingen.no',
      url='http://sepiida.linuxavdelingen.no',
      packages=['sepiida', 'sepiida.agent'],
      package_dir={'sepiida': 'src/sepiida'},
      data_files=[(r'c:\sepiida', glob('scripts/windows/*') + glob('conf/windows/*'))
                  ] + find_data_files('lib', '*', target=r'c:\sepiida')
     )  
