import os
import ctypes
import platform

def is_admin():
    """
    Checks if the current process has administrative/root privileges.
    """
    try:
        if platform.system().lower() == 'windows':
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:
            return os.getuid() == 0
    except AttributeError:
        # Fallback if os.getuid() is not available (some platforms)
        return False
