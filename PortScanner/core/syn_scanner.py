import socket
import struct
import array
import time
from utils.permissions import is_admin

class SYNScanner:
    def __init__(self, target, ports, timeout=2):
        self.target = target
        self.ports = ports
        self.timeout = timeout
        self.results = []
        self.src_ip = socket.gethostbyname(socket.gethostname())

    def _checksum(self, msg):
        if len(msg) % 2 == 1:
            msg += b'\0'
        s = sum(array.array('H', msg))
        s = (s >> 16) + (s & 0xffff)
        s += s >> 16
        s = ~s & 0xffff
        return s

    def _create_packet(self, dst_port):
        # TCP Header
        src_port = 12345
        seq = 0
        ack_seq = 0
        doff = 5
        # Flags: SYN
        flags = 2
        window = socket.htons(5840)
        check = 0
        urg_ptr = 0

        offset_res = (doff << 4) + 0
        tcp_header = struct.pack('!HHLLBBHHH', src_port, dst_port, seq, ack_seq, offset_res, flags, window, check, urg_ptr)

        # Pseudo header for checksum
        source_address = socket.inet_aton(self.src_ip)
        dest_address = socket.inet_aton(self.target)
        placeholder = 0
        protocol = socket.IPPROTO_TCP
        tcp_length = len(tcp_header)

        psh = struct.pack('!4s4sBBH', source_address, dest_address, placeholder, protocol, tcp_length)
        psh = psh + tcp_header

        tcp_checksum = self._checksum(psh)
        # Pack again with correct checksum
        tcp_header = struct.pack('!HHLLBBH', src_port, dst_port, seq, ack_seq, offset_res, flags, window) + \
                     struct.pack('H', tcp_checksum) + \
                     struct.pack('!H', urg_ptr)

        return tcp_header

    def scan(self, progress_callback=None):
        if not is_admin():
            raise PermissionError("SYN scan requires administrative privileges.")

        # On Windows, raw sockets for TCP are highly restricted.
        # This implementation follows standard raw socket patterns but may fail on modern Windows
        # without specialized drivers like Npcap.
        
        try:
            # Create raw socket
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            s.settimeout(self.timeout)
        except socket.error as e:
            raise PermissionError(f"Could not create raw socket: {e}")

        for port in self.ports:
            packet = self._create_packet(port)
            s.sendto(packet, (self.target, 0))
            
            start_time = time.time()
            opened = False
            while (time.time() - start_time) < self.timeout:
                try:
                    data, addr = s.recvfrom(1024)
                    if addr[0] == self.target:
                        # Parse TCP header (min 20 bytes)
                        # We are looking for SYN/ACK (flags = 18 = 0x12)
                        # The TCP header starts after the IP header (at least 20 bytes)
                        # This is a simplified check
                        tcp_header = data[20:40]
                        if len(tcp_header) >= 20:
                            _, _, _, _, _, flags, _, _, _ = struct.unpack('!HHLLBBHHH', tcp_header)
                            if flags & 0x12 == 0x12: # SYN-ACK
                                self.results.append({
                                    "port": port,
                                    "protocol": "tcp",
                                    "state": "open",
                                    "service": "unknown",
                                    "version": "N/A"
                                })
                                opened = True
                                break
                            elif flags & 0x04: # RST
                                break
                except socket.timeout:
                    break
                except Exception:
                    break
            
            if progress_callback:
                progress_callback()

        s.close()
        return sorted(self.results, key=lambda x: x["port"])
