import logging
import shutil
import os
from typing import List, Dict, Any

log = logging.getLogger("wifi_scanner.nmap")

# Common Nmap installation paths on Windows
NMAP_WINDOWS_PATHS = [
    r"C:\Program Files (x86)\Nmap\nmap.exe",
    r"C:\Program Files\Nmap\nmap.exe",
]

def find_nmap() -> str | None:
    """
    Finds the Nmap executable path, checking both system PATH
    and common Windows installation directories.

    Returns:
        Full path to nmap.exe or 'nmap' if found in PATH, else None.
    """
    # Check system PATH first
    in_path = shutil.which("nmap")
    if in_path:
        return in_path
    # Check common Windows install locations
    for path in NMAP_WINDOWS_PATHS:
        if os.path.isfile(path):
            return path
    return None

def is_nmap_installed() -> bool:
    """Returns True if Nmap binary is found."""
    return find_nmap() is not None

def run_nmap_scan(ip_list: List[str], arguments: str = "-sV -O --open -T4") -> List[Dict[str, Any]]:
    """
    Runs an Nmap scan on a list of IP addresses using python-nmap.

    Performs service version detection (-sV), OS detection (-O),
    shows only open ports (--open) and uses aggressive timing (-T4).

    Args:
        ip_list: List of IPv4 address strings to scan.
        arguments: Nmap argument string. Default runs a comprehensive scan.

    Returns:
        List of dicts per host containing:
            - ip (str): Target IP
            - hostname (str): Nmap-resolved hostname
            - state (str): Host state (up/down)
            - os_guess (str): OS detection guess
            - ports (list): List of dicts with port, state, service, version
    """
    try:
        import nmap
    except ImportError:
        log.error("python-nmap is not installed. Run: pip install python-nmap")
        return []

    if not is_nmap_installed():
        log.error("Nmap binary not found. Install from: https://nmap.org/download.html")
        return []

    nmap_path = find_nmap()
    nmap_dir = os.path.dirname(nmap_path)
    log.info(f"Nmap found at: {nmap_path}")

    # Inject nmap directory into PATH for the entire scan duration
    old_path = os.environ.get("PATH", "")
    os.environ["PATH"] = nmap_dir + os.pathsep + old_path

    try:
        nm = nmap.PortScanner()
        # Directly set the full path so subprocess always finds nmap.exe
        nm._nmap_path = nmap_path
        results = []

        for ip in ip_list:
            log.info(f"Nmap scanning: {ip}")
            try:
                nm.scan(hosts=ip, arguments=arguments)
            except Exception as e:
                log.warning(f"Nmap scan failed for {ip}: {e}")
                results.append({'ip': ip, 'error': str(e)})
                continue

            if ip not in nm.all_hosts():
                results.append({'ip': ip, 'state': 'down', 'ports': [], 'os_guess': 'N/A', 'hostname': 'N/A'})
                continue

            host = nm[ip]

            # OS Detection
            os_guess = "Unknown"
            if 'osmatch' in host and host['osmatch']:
                top = host['osmatch'][0]
                os_guess = f"{top['name']} ({top['accuracy']}%)"

            # Hostname
            hostname = "Unknown"
            if host.hostnames():
                hostname = host.hostnames()[0].get('name', 'Unknown') or 'Unknown'

            # Open Ports
            ports = []
            for proto in host.all_protocols():
                for port in sorted(host[proto].keys()):
                    port_info = host[proto][port]
                    if port_info['state'] == 'open':
                        ports.append({
                            'port': port,
                            'proto': proto.upper(),
                            'service': port_info.get('name', 'unknown'),
                            'version': f"{port_info.get('product', '')} {port_info.get('version', '')}".strip() or "-"
                        })

            results.append({
                'ip': ip,
                'hostname': hostname,
                'state': host.state(),
                'os_guess': os_guess,
                'ports': ports
            })

    finally:
        # Always restore original PATH
        os.environ["PATH"] = old_path

    return results
