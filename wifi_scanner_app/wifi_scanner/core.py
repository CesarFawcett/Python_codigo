import logging
from datetime import datetime
from typing import List, Dict, Any
from scapy.all import ARP, Ether, srp
from .utils import get_hostname, get_vendor, scan_ports

log = logging.getLogger("wifi_scanner.core")

class NetworkScanner:
    """
    Core class responsible for executing network scans using Scapy,
    followed by a TCP port scan on each discovered device.
    """
    def __init__(self, interface: str = None):
        self.interface = interface
        self.devices: List[Dict[str, Any]] = []

    def scan_network(self, ip_range: str) -> List[Dict[str, Any]]:
        """
        Phase 1: ARP scan to discover devices on the network.
        Phase 2: TCP port scan on each discovered device.

        Args:
            ip_range: CIDR notation (e.g., 192.168.1.0/24)

        Returns:
            List of dicts with IP, MAC, Vendor, Hostname, First Seen, and Open Ports.
        """
        log.info(f"Scanning range: {ip_range} using interface: {self.interface or 'auto'}")

        # --- Phase 1: ARP Scan ---
        arp = ARP(pdst=ip_range)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp

        try:
            result = srp(packet, timeout=3, verbose=False, iface=self.interface)[0]
        except Exception as e:
            log.error(f"Scapy ARP scan failed: {e}")
            return []

        devices_found = []
        scan_time = datetime.now()

        for sent, received in result:
            ip = received.psrc
            mac = received.hwsrc
            hostname = get_hostname(ip)
            vendor = get_vendor(mac)
            devices_found.append({
                'ip': ip,
                'mac': mac,
                'vendor': vendor,
                'hostname': hostname,
                'first_seen': scan_time.strftime("%H:%M:%S"),
                'open_ports': []  # to be filled in Phase 2
            })

        self.devices = devices_found
        return devices_found

    def scan_all_ports(self) -> None:
        """
        Phase 2: Scans common TCP ports on all previously discovered devices.
        Mutates self.devices in-place by populating 'open_ports' per device.
        """
        for device in self.devices:
            ip = device['ip']
            log.info(f"Port scanning: {ip}")
            device['open_ports'] = scan_ports(ip)
