import socket
import threading
from queue import Queue
from core.service_detector import identify_service

class TCPScanner:
    def __init__(self, target, ports, timeout=1, threads=100):
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
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(self.timeout)
                    result = s.connect_ex((self.target, port))
                    if result == 0:
                        service_info = identify_service(self.target, port, self.timeout)
                        with self.lock:
                            self.results.append({
                                "port": port,
                                "protocol": "tcp",
                                "state": "open",
                                "service": service_info["service"],
                                "version": service_info["version"]
                            })
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
