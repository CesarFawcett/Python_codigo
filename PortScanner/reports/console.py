from datetime import datetime

class ConsoleReporter:
    def __init__(self, target, ports, technique, start_time):
        self.target = target
        self.ports = ports
        self.technique = technique
        self.start_time = start_time

    def print_banner(self, version="1.0"):
        print("\n" + "="*40)
        print(f"🔍 PORT SCANNER v{version}")
        print("="*40)
        print(f"Target      : {self.target}")
        print(f"Port Range  : {min(self.ports)}-{max(self.ports) if self.ports else 'N/A'}")
        print(f"Technique   : {self.technique}")
        print(f"Start Time  : {self.start_time.strftime('%Y-%m-%d %H:%M:%S')}")
        print("-" * 40)

    def print_results(self, results, total_time):
        print("\n📊 SCAN RESULTS")
        print("="*40)
        print(f"Host: {self.target}")
        print(f"Open Ports: {len(results)}")
        print(f"Total Time: {total_time:.2f} seconds")
        print("\n" + "─"*50)
        print(f"{'PORT':<8} {'STATE':<10} {'SERVICE':<12} {'VERSION'}")
        print("─"*50)
        
        if not results:
            print("No open ports found.")
        else:
            for res in results:
                port_proto = f"{res['port']}/{res['protocol']}"
                print(f"{port_proto:<8} {res['state']:<10} {res['service']:<12} {res['version']}")
        
        print("─"*50)
        print("\n✅ Scan completed\n")
