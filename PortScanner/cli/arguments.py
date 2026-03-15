import argparse

def parse_arguments():
    parser = argparse.ArgumentParser(description="Professional TCP/UDP Port Scanner")
    
    # Target options
    parser.add_argument("-t", "--target", required=True, help="Target IP address or hostname")
    parser.add_argument("-p", "--ports", default="1-1024", help="Port range (e.g. '80', '1-1024', '22,80,443')")
    
    # Technique options
    group = parser.add_mutually_exclusive_group()
    group.add_argument("-sT", "--tcp", action="store_true", help="TCP CONNECT scan (default)")
    group.add_argument("-sS", "--syn", action="store_true", help="TCP SYN scan (stealth)")
    group.add_argument("-sU", "--udp", action="store_true", help="UDP scan")
    
    # Speed and performance
    parser.add_argument("--timeout", type=float, default=1.0, help="Timeout for each port in seconds (default: 1.0)")
    parser.add_argument("--threads", type=int, default=100, help="Number of concurrent threads (default: 100)")
    
    # Modes
    parser.add_argument("--fast", action="store_true", help="Scan only top 100 common ports")
    parser.add_argument("-sV", "--service-version", action="store_true", help="Attempt to detect service version")
    
    # Output options
    parser.add_argument("-o", "--output", choices=["json", "csv", "html"], help="Export results to a file format")
    parser.add_argument("-f", "--file", help="Filename for the exported report")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show detailed progress")
    
    return parser.parse_args()
