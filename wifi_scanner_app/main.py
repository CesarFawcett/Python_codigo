# Main entry point for the Wi-Fi Scanner application.
import logging
import sys
from typing import Optional, List
import typer
from rich.console import Console
from rich.logging import RichHandler
from wifi_scanner.core import NetworkScanner
from wifi_scanner.utils import get_local_network, validate_ip_range, scan_ports
from wifi_scanner.nmap_scanner import run_nmap_scan, is_nmap_installed
from wifi_scanner.ui import (
    render_scan_results,
    render_port_results,
    render_nmap_results,
    scan_progress,
    port_scan_progress
)

# Configure Professional Logging
logging.basicConfig(
    level="INFO",
    format="%(message)s",
    datefmt="[%X]",
    handlers=[RichHandler(rich_tracebacks=True)]
)

log = logging.getLogger("wifi_scanner")
console = Console()
app = typer.Typer(help="Wi-Fi Network Scanner - Identify devices on your network.")

@app.command()
def scan(
    interface: Optional[str] = typer.Option(None, "--interface", "-i", help="Network interface (e.g., wlan0, eth0)"),
    range: Optional[str] = typer.Option(None, "--range", "-r", help="IP range in CIDR (e.g., 192.168.1.0/24). Auto-detected if omitted."),
    no_ports: bool = typer.Option(False, "--no-ports", help="Skip TCP port scanning phase."),
    no_nmap: bool = typer.Option(False, "--no-nmap", help="Skip Nmap deep scan phase.")
):
    """
    Full network intelligence scan:
      Phase 1: ARP device discovery
      Phase 2: TCP port scan (top 20 ports)
      Phase 3: Nmap deep scan (service/OS detection)
    """
    console.print("\n[bold blue]Wi-Fi Network Scanner[/bold blue]\n")

    # -- Determine Target Range ------------------------------------------
    target_range = range
    if not target_range:
        log.info("Autodetecting local network range...")
        target_range = get_local_network()
        if not target_range:
            console.print("[bold red]Failed to detect local network. Use --range.[/bold red]")
            raise typer.Exit(1)
        log.info(f"Target range: [cyan]{target_range}[/cyan]")

    if not validate_ip_range(target_range):
        console.print(f"[bold red]Invalid IP range: {target_range}[/bold red]")
        raise typer.Exit(1)

    # -- Phase 1: ARP Device Discovery -----------------------------------
    scanner = NetworkScanner(interface=interface)

    with scan_progress("Phase 1: Discovering devices via ARP...") as progress:
        progress.add_task(description="Scanning...", total=None)
        devices = scanner.scan_network(target_range)

    render_scan_results(devices, target_range)

    if not devices:
        console.print("[yellow]No devices found. Exiting.[/yellow]")
        raise typer.Exit(0)

    ip_list: List[str] = [d['ip'] for d in scanner.devices]

    # -- Phase 2: TCP Port Scan ------------------------------------------
    if not no_ports:
        console.print("[bold yellow]Phase 2: Scanning open ports...[/bold yellow]\n")
        with port_scan_progress(total=len(devices)) as progress:
            task = progress.add_task("Port scanning...", total=len(devices))
            for device in scanner.devices:
                progress.update(task, description=f"Scanning {device['ip']}...")
                device['open_ports'] = scan_ports(device['ip'])
                progress.advance(task)
        render_port_results(scanner.devices)
    else:
        console.print("[dim]- Port scan skipped (--no-ports)[/dim]\n")

    # -- Phase 3: Nmap Deep Scan -----------------------------------------
    if not no_nmap:
        if not is_nmap_installed():
            console.print(
                "[bold red]Nmap not found.[/bold red] "
                "Install from [link=https://nmap.org/download.html]nmap.org[/link] "
                "and add it to PATH, then re-run."
            )
        else:
            console.print("[bold red]Phase 3: Running Nmap deep scan...[/bold red]\n")
            with scan_progress("Running Nmap...") as progress:
                progress.add_task(description="Nmap scanning...", total=None)
                nmap_data = run_nmap_scan(ip_list)
            render_nmap_results(nmap_data)
    else:
        console.print("[dim]- Nmap scan skipped (--no-nmap)[/dim]\n")


if __name__ == "__main__":
    try:
        app()
    except KeyboardInterrupt:
        console.print("\n[bold red]Scan aborted by user.[/bold red]")
        sys.exit(0)
    except Exception as e:
        log.exception(f"An unexpected error occurred: {e}")
        sys.exit(1)
