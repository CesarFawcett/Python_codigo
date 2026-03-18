from rich.table import Table
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.text import Text
from rich.rule import Rule
from typing import List, Dict, Any

console = Console()

def render_scan_results(devices: List[Dict[str, Any]], target_range: str):
    """
    Renders the ARP scan results in a premium Rich table with 6 columns,
    including device numbering and all enriched fields.
    """
    table = Table(
        title=f"Network Scan Results - [bold cyan]{target_range}[/bold cyan]",
        show_header=True,
        header_style="bold magenta",
        border_style="bright_blue",
        show_lines=True
    )

    table.add_column("#", style="bold white", min_width=3, justify="center")
    table.add_column("IP Address", style="bold cyan", min_width=15)
    table.add_column("MAC Address", style="bold green", min_width=20)
    table.add_column("Vendor / Manufacturer", style="yellow", min_width=22)
    table.add_column("Hostname", style="dim white", min_width=18)
    table.add_column("First Seen", justify="center", style="magenta", min_width=12)

    if not devices:
        console.print(Panel(
            "[bold yellow]No devices discovered.[/bold yellow]\n"
            "Try running as Administrator/Root for raw packet access.",
            border_style="yellow"
        ))
        return

    for idx, device in enumerate(devices, start=1):
        hostname = device.get("hostname", "Unknown")
        vendor = device.get("vendor", "Unknown")

        if hostname == "Unknown":
            hostname = Text("Unknown", style="dim")
        if vendor == "Unknown":
            vendor = Text("Unknown", style="dim")

        table.add_row(
            str(idx),
            device.get("ip", "N/A"),
            device.get("mac", "N/A"),
            vendor,
            hostname,
            device.get("first_seen", "N/A")
        )

    console.print()
    console.print(table)
    console.print(
        f"\n[bold green]Total: {len(devices)} device(s) found.[/bold green]\n"
    )

def render_port_results(devices: List[Dict[str, Any]]):
    """
    Renders a port scan summary table for each device.
    Lists all open ports with their associated service names.
    """
    console.print("\n[bold magenta]Port Scan Results[/bold magenta]\n")

    for idx, device in enumerate(devices, start=1):
        ip = device.get("ip", "N/A")
        open_ports = device.get("open_ports", [])

        if not open_ports:
            console.print(
                f"  [dim]#{idx} {ip}[/dim] - [dim]No open ports found[/dim]"
            )
            continue

        port_table = Table(
            title=f"#{idx} [bold cyan]{ip}[/bold cyan] - {device.get('hostname', 'Unknown')}",
            show_header=True,
            header_style="bold cyan",
            border_style="green",
            show_lines=False,
            min_width=40
        )
        port_table.add_column("Port", style="bold green", justify="right", min_width=6)
        port_table.add_column("Service", style="white", min_width=16)

        for p in sorted(open_ports, key=lambda x: x['port']):
            port_table.add_row(str(p['port']), p['service'])

        console.print(port_table)
        console.print()

def scan_progress(description: str = "Scanning network..."):
    """
    Returns a Rich progress context manager with spinner for scan animation.
    """
    return Progress(
        SpinnerColumn(),
        TextColumn(f"[progress.description]{description}"),
        console=console,
        transient=True
    )

def port_scan_progress(total: int):
    """
    Returns a Rich progress bar for multi-device port scanning.
    """
    return Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        console=console,
        transient=True
    )

def render_nmap_results(nmap_results: List[Dict[str, Any]]):
    """
    Renders a detailed Nmap report for each scanned device.
    Shows OS detection, service versions, and open ports per host.
    """
    console.print()
    console.print(Rule("[bold red]Nmap Deep Scan Results[/bold red]", style="red"))
    console.print()

    if not nmap_results:
        console.print(Panel("[yellow]No Nmap data available.[/yellow]", border_style="yellow"))
        return

    for result in nmap_results:
        ip = result.get('ip', 'N/A')

        if 'error' in result:
            console.print(f"  [red]Error on {ip}[/red] - {result['error']}")
            continue

        state = result.get('state', 'unknown')
        os_guess = result.get('os_guess', 'Unknown')
        hostname = result.get('hostname', 'Unknown')
        ports = result.get('ports', [])

        # Host header panel
        console.print(Panel(
            f"[bold cyan]{ip}[/bold cyan]  |  "
            f"[dim]Hostname:[/dim] [white]{hostname}[/white]  |  "
            f"[dim]State:[/dim] [green]{state}[/green]  |  "
            f"[dim]OS:[/dim] [yellow]{os_guess}[/yellow]",
            border_style="blue",
            expand=False
        ))

        if not ports:
            console.print("  [dim]  No open ports detected by Nmap.[/dim]\n")
            continue

        nmap_table = Table(
            show_header=True,
            header_style="bold white",
            border_style="dim blue",
            show_lines=False,
            min_width=60
        )
        nmap_table.add_column("Port", style="bold green", justify="right", min_width=7)
        nmap_table.add_column("Proto", style="cyan", min_width=6)
        nmap_table.add_column("Service", style="yellow", min_width=12)
        nmap_table.add_column("Version / Product", style="dim white", min_width=25)

        for p in ports:
            nmap_table.add_row(
                str(p['port']),
                p.get('proto', 'TCP'),
                p.get('service', 'unknown'),
                p.get('version', '-')
            )

        console.print(nmap_table)
        console.print()
