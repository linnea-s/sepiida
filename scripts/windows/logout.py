import win32api
import win32con
win32api.ExitWindowsEx(win32con.EWX_LOGOFF, 0)
