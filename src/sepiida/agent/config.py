import sys
if sys.platform.startswith('win'):
    from win32config import *
elif sys.platform.startswith('linux'):
    from linuxconfig import *
elif sys.platform == 'darwin':
    from darwinconfig import *
else:
    assert False
