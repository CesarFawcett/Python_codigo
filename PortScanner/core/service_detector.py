import socket
from utils.network import get_service_name

def grab_banner(host, port, timeout=2):
    """
    Attempts to grab a banner from a service.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((host, port))
            # Some services require a basic probe to send a banner
            # For HTTP, we might need a request, but let's try a simple read first
            banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
            return banner
    except Exception:
        return None

def identify_service(host, port, timeout=2):
    """
    Identifies the service running on a port.
    Returns a dictionary with 'service' and 'version' (if available).
    """
    service_name = get_service_name(port)
    banner = grab_banner(host, port, timeout)
    
    version = banner if banner else "Unknown"
    
    return {
        "service": service_name,
        "version": version
    }
