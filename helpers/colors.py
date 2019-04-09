"""Escape codes for UNIX terminal colors"""
import sys

def get_platform():
    """Return current machine OS name"""
    platforms = {
        'linux1' : 'Linux',
        'linux2' : 'Linux',
        'darwin' : 'OS X',
        'win32' : 'Windows'
    }

    if sys.platform not in platforms:
        return sys.platform
    
    return platforms[sys.platform]

class bcolors:
    """Set escape code for UNIX terminal color if it's not Windows"""
    HEADER = '\033[95m' if get_platform() != 'Windows' else ''
    OKBLUE = '\033[94m' if get_platform() != 'Windows' else ''
    OKGREEN = '\033[92m' if get_platform() != 'Windows' else ''
    WARNING = '\033[93m' if get_platform() != 'Windows' else ''
    FAIL = '\033[91m' if get_platform() != 'Windows' else ''
    ENDC = '\033[0m' if get_platform() != 'Windows' else ''
    BOLD = '\033[1m' if get_platform() != 'Windows' else ''
    UNDERLINE = '\033[4m' if get_platform() != 'Windows' else ''
    RESET =  '\u001b[0m' if get_platform() != 'Windows' else ''
