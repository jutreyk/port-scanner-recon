import argparse
import asyncio
import json
import sys
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn
from .scanner import AsyncScanner
from .probes import COMMON_PORTS

console = Console()

def parse_ports(port_arg: str) -> list[int]:
    if port_arg == "top":
        return sorted(list(COMMON_PORTS.keys()))

    ports = set()
    parts = port_arg.split(",")
    for p in parts:
        p = p.strip()
        if "-" in p:
            start, end = map(int, p.split("-"))
            ports.update(range(start, end + 1))
        elif p.isdigit():
            ports.add(int(p))
    return sorted(list(ports))

def display_report(report):
    console.print(Panel.fit(
        f"[bold cyan]Target:[/bold cyan] {report.target} ({report.ip})\n"
        f"[bold cyan]Scan Duration:[/bold cyan] {report.duration_sec}s | [bold green]Open Ports:[/bold green] {report.open_ports_count}",
        title="[bold white]Port Scanner Reconnaissance Report[/bold white]",
        border_style="cyan"
    ))

    if not report.results:
        console.print("[yellow]No open ports discovered in specified range.[/yellow]")
        return

    table = Table(show_header=True, header_style="bold magenta", border_style="dim")
    table.add_column("PORT", style="cyan", width=8)
    table.add_column("SERVICE", style="green", width=14)
    table.add_column("LATENCY", style="yellow", width=10)
    table.add_column("BANNER / DETAILS", style="white")

    for r in report.results:
        details = []
        if r.banner:
            details.append(f"[dim]Banner:[/dim] {r.banner}")
        if r.tls:
            details.append(f"[blue]TLS CN:[/blue] {r.tls.subject} ([green]{r.tls.days_left}d left[/green], {r.tls.issuer})")

        detail_str = " | ".join(details) if details else "[dim]—[/dim]"
        table.add_row(f"{r.port}/tcp", r.service, f"{r.latency_ms} ms", detail_str)

    console.print(table)

def main():
    parser = argparse.ArgumentParser(
        description="Async Port & TLS Reconnaissance Scanner",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument("target", help="Domain or IP address to scan")
    parser.add_argument("-p", "--ports", default="top", help="Ports to scan: 'top', '80,443,8080' or range '1-1024'")
    parser.add_argument("-c", "--concurrency", type=int, default=150, help="Max concurrent connections")
    parser.add_argument("-t", "--timeout", type=float, default=1.5, help="Socket connect timeout (seconds)")
    parser.add_argument("-o", "--output", help="Save JSON report to file")

    args = parser.parse_args()

    try:
        ports = parse_ports(args.ports)
    except Exception as e:
        console.print(f"[bold red]Error parsing ports:[/bold red] {e}")
        sys.exit(1)

    scanner = AsyncScanner(args.target, concurrency=args.concurrency, timeout=args.timeout)

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        console=console
    ) as progress:
        task = progress.add_task(f"Scanning {args.target} ({len(ports)} ports)...", total=len(ports))

        def on_progress(done, total):
            progress.update(task, completed=done)

        try:
            report = asyncio.run(scanner.scan(ports, progress_cb=on_progress))
        except Exception as e:
            console.print(f"[bold red]Scan failed:[/bold red] {e}")
            sys.exit(1)

    display_report(report)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(report.to_dict(), f, indent=2)
        console.print(f"\n[green]Saved JSON report to[/green] [bold]{args.output}[/bold]")

if __name__ == "__main__":
    main()
