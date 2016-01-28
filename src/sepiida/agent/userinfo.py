import sys
if sys.platform.startswith('win'):
    from win32userinfo import UserInfo
elif sys.platform.startswith('linux'):
    from linuxuserinfo import UserInfo
elif sys.platform == 'darwin':
    from darwinuserinfo import UserInfo
else:
    assert False
