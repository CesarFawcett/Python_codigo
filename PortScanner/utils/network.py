import socket
import subprocess
import platform

def resolve_hostname(target):
    """
    Resolves a hostname to an IP address.
    """
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        return None

def is_host_alive(target, timeout=2):
    """
    Check if a host is alive using ping (ICMP).
    Note: Some hosts may block ICMP.
    """
    param = '-n' if platform.system().lower() == 'windows' else '-c'
    command = ['ping', param, '1', '-w', str(timeout * 1000), target]
    
    try:
        # We use shell=False for security
        output = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout + 1)
        return output.returncode == 0
    except subprocess.TimeoutExpired:
        return False
    except Exception:
        # Fallback to a simple TCP check on common ports if ping fails or is blocked
        return False

def get_service_name(port, protocol='tcp'):
    """
    Gets the service name for a given port.
    """
    try:
        return socket.getservbyport(port, protocol)
    except (socket.error, OverflowError):
        return "unknown"
