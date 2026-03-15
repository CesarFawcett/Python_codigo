import sys
from datetime import datetime
from cli.arguments import parse_arguments
from cli.banner import print_welcome
from utils.validators import validate_target, parse_ports, validate_timeout
from utils.network import resolve_hostname
from utils.progress import ProgressBar
from core.tcp_scanner import TCPScanner
from core.udp_scanner import UDPScanner
from core.syn_scanner import SYNScanner
from reports.console import ConsoleReporter
from reports import export_json, export_csv, export_html

# Top 100 common ports (simplified)
TOP_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080
] # In a real app, this would be a full list of 100

def main():
    args = parse_arguments()
    print_welcome()

    # Validate target
    if not validate_target(args.target):
        print(f"[-] Error: Invalid target '{args.target}'")
        sys.exit(1)

    target_ip = resolve_hostname(args.target)
    if not target_ip:
        print(f"[-] Error: Could not resolve hostname '{args.target}'")
        sys.exit(1)

    # Determine ports to scan
    if args.fast:
        ports = TOP_PORTS
    else:
        ports = parse_ports(args.ports)
        if not ports:
            print(f"[-] Error: Invalid port range '{args.ports}'")
            sys.exit(1)

    # Validate timeout
    if not validate_timeout(args.timeout):
        print(f"[-] Error: Invalid timeout value '{args.timeout}'")
        sys.exit(1)

    # Select scanning technique
    technique = "TCP CONNECT"
    scanner_class = TCPScanner
    if args.syn:
        technique = "TCP SYN"
        scanner_class = SYNScanner
    elif args.udp:
        technique = "UDP"
        scanner_class = UDPScanner

    start_time = datetime.now()
    reporter = ConsoleReporter(args.target, ports, technique, start_time)
    reporter.print_banner()

    # Initialize scanner
    scanner = scanner_class(target_ip, ports, timeout=args.timeout)
    if not args.syn: # SYN scanner might not support thread param in the same way
        scanner.threads = args.threads

    # Progress Bar
    progress = ProgressBar(len(ports), prefix='Scanning', suffix='Complete', length=40)
    
    print(f"[*] Scanning {len(ports)} ports on {target_ip} ({args.target})...")
    
    try:
        results = scanner.scan(progress_callback=progress.update)
    except PermissionError as e:
        print(f"\n[-] Permission Error: {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user.")
        sys.exit(0)

    end_time = datetime.now()
    total_time = (end_time - start_time).total_seconds()

    # Show results
    reporter.print_results(results, total_time)

    # Export if requested
    if args.output and args.file:
        print(f"[*] Exporting results to {args.file} ({args.output})...")
        if args.output == "json":
            export_json(results, args.target, args.file)
        elif args.output == "csv":
            export_csv(results, args.target, args.file)
        elif args.output == "html":
            export_html(results, args.target, args.file)
        print("[+] Export complete.")

if __name__ == "__main__":
    main()
