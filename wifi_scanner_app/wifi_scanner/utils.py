import socket
import ipaddress
import logging
from typing import Optional
from mac_vendor_lookup import MacLookup, InvalidMacError

log = logging.getLogger("wifi_scanner.utils")

# Initialize MAC vendor lookup (local database)
_mac_lookup = MacLookup()

def get_vendor(mac_address: str) -> str:
    """
    Looks up the hardware vendor/manufacturer from a MAC address
    using the local IEEE OUI database.

    Args:
        mac_address: A MAC address string (e.g., '00:11:22:33:44:55').

    Returns:
        Vendor name string, or 'Unknown' if not found.
    """
    try:
        return _mac_lookup.lookup(mac_address)
    except (InvalidMacError, KeyError, Exception):
        return "Unknown"

def get_hostname(ip_address: str) -> str:
    """
    Attempts to resolve the hostname for a given IP address.

    Args:
        ip_address: IPv4 address string.

    Returns:
        Hostname string, or 'Unknown' if resolution fails.
    """
    try:
        hostname, _, _ = socket.gethostbyaddr(ip_address)
        return hostname
    except (socket.herror, socket.gaierror):
        return "Unknown"

def get_local_network() -> Optional[str]:
    """
    Detects the local IPv4 network range of the primary interface.

    Returns:
        CIDR notation (e.g., 192.168.1.0/24) or None if detection fails.
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0.1)
        s.connect(("1.1.1.1", 80))
        local_ip = s.getsockname()[0]
        s.close()
        network = ipaddress.IPv4Network(f"{local_ip}/24", strict=False)
        return str(network)
    except Exception as e:
        log.error(f"Network detection failed: {e}")
        return None

def validate_ip_range(ip_range: str) -> bool:
    """
    Validates if the provided string is a valid IPv4 network/range.

    Args:
        ip_range: CIDR IP range string.

    Returns:
        True if valid, False otherwise.
    """
    try:
        ipaddress.IPv4Network(ip_range, strict=False)
        return True
    except ValueError:
        return False

# Top common ports to scan with their service names
COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 135: "RPC",
    139: "NetBIOS", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    3389: "RDP", 5900: "VNC", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
    3306: "MySQL", 5432: "PostgreSQL", 6379: "Redis", 27017: "MongoDB"
}

def scan_ports(ip_address: str, timeout: float = 0.5) -> list:
    """
    Scans a set of common TCP ports on the given IP address.

    Uses a fast socket connect approach with a configurable timeout.
    Checks the top 20 most commonly exploited/used service ports.

    Args:
        ip_address: IPv4 address string to scan.
        timeout: Socket connection timeout per port in seconds.

    Returns:
        A list of dicts with 'port' (int) and 'service' (str) for each open port.
    """
    open_ports = []
    for port, service in COMMON_PORTS.items():
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip_address, port))
            sock.close()
            if result == 0:
                open_ports.append({'port': port, 'service': service})
        except Exception:
            pass
    return open_ports
