import socket
import threading
from queue import Queue

class UDPScanner:
    def __init__(self, target, ports, timeout=2, threads=50):
        self.target = target
        self.ports = ports
        self.timeout = timeout
        self.threads = threads
        self.results = []
        self.queue = Queue()
        self.lock = threading.Lock()

    def _worker(self, progress_callback=None):
        while not self.queue.empty():
            port = self.queue.get()
            try:
                # UDP is tricky because it's connectionless.
                # If we get an ICMP Port Unreachable, it's closed.
                # If we get no response, it's open|filtered.
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                    s.settimeout(self.timeout)
                    s.sendto(b'', (self.target, port))
                    try:
                        data, addr = s.recvfrom(1024)
                        # If we get data back, it's definitely open
                        with self.lock:
                            self.results.append({
                                "port": port,
                                "protocol": "udp",
                                "state": "open",
                                "service": "unknown",
                                "version": "N/A"
                            })
                    except socket.timeout:
                        # This is the most common result for open UDP ports
                        # without specific probe responses. 
                        # In a real scanner, we'd mark as open|filtered.
                        # For simplicity, we'll mark as open if no ICMP error is received.
                        # Note: Detecting ICMP errors requires raw sockets and is complex.
                        pass
            except Exception:
                pass
            finally:
                if progress_callback:
                    progress_callback()
                self.queue.task_done()

    def scan(self, progress_callback=None):
        for port in self.ports:
            self.queue.put(port)

        thread_list = []
        for _ in range(min(self.threads, len(self.ports))):
            t = threading.Thread(target=self._worker, args=(progress_callback,))
            t.daemon = True
            t.start()
            thread_list.append(t)

        for t in thread_list:
            t.join()

        return sorted(self.results, key=lambda x: x["port"])
