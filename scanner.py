import argparse
import asyncio
import json
import socket
import ssl
import sys
import time
from dataclasses import dataclass, asdict
from datetime import datetime
from typing import Optional, List, Callable, Dict, Any
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn

console = Console()

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 465: "SMTPS",
    993: "IMAPS", 995: "POP3S", 3306: "MySQL", 5432: "PostgreSQL",
    6379: "Redis", 8000: "HTTP-Alt", 8080: "HTTP-Proxy", 8443: "HTTPS-Alt"
}

@dataclass
class CertInfo:
    subject: str
    issuer: str
    valid_from: str
    valid_until: str
    days_left: int

@dataclass
class PortResult:
    port: int
    service: str
    state: str
    banner: Optional[str] = None
    tls: Optional[CertInfo] = None
    latency_ms: float = 0.0

@dataclass
class ScanReport:
    target: str
    ip: str
    scan_time: str
    duration_sec: float
    open_ports_count: int
    results: List[PortResult]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

def inspect_tls(host: str, port: int) -> Optional[CertInfo]:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=2.0) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert(binary_form=False)
                if not cert:
                    return None
                subject = dict(x[0] for x in cert.get('subject', []))
                issuer = dict(x[0] for x in cert.get('issuer', []))
                not_after = cert.get('notAfter')
                days_left = 0
                if not_after:
                    expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                    days_left = (expiry - datetime.utcnow()).days
                return CertInfo(
                    subject=subject.get('commonName', 'Unknown'),
                    issuer=issuer.get('organizationName', issuer.get('commonName', 'Unknown')),
                    valid_from=cert.get('notBefore', ''),
                    valid_until=not_after or '',
                    days_left=days_left
                )
    except Exception:
        return None

def grab_banner(host: str, port: int) -> Optional[str]:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1.5)
            s.connect((host, port))
            if port in (80, 8080, 8000):
                s.sendall(b"HEAD / HTTP/1.0\r\nHost: " + host.encode() + b"\r\n\r\n")
            data = s.recv(256)
            if data:
                clean = "".join(chr(b) for b in data if 32 <= b <= 126)
                return clean[:70].strip() or None
    except Exception:
        pass
    return None

class Scanner:
    def __init__(self, target: str, concurrency: int = 150, timeout: float = 1.5):
        self.target = target
        self.timeout = timeout
        self.semaphore = asyncio.Semaphore(concurrency)

    async def scan_port(self, host: str, port: int) -> PortResult:
        async with self.semaphore:
            start_time = time.perf_counter()
            conn = asyncio.open_connection(host, port)
            try:
                reader, writer = await asyncio.wait_for(conn, timeout=self.timeout)
                latency = (time.perf_counter() - start_time) * 1000.0
                writer.close()
                await writer.wait_closed()

                service = COMMON_PORTS.get(port, "Unknown")
                loop = asyncio.get_running_loop()
                banner = await loop.run_in_executor(None, grab_banner, host, port)
                
                tls_info = None
                if port in (443, 8443, 465, 993, 995):
                    tls_info = await loop.run_in_executor(None, inspect_tls, host, port)

                return PortResult(
                    port=port,
                    service=service,
                    state="open",
                    banner=banner,
                    tls=tls_info,
                    latency_ms=round(latency, 2)
                )
            except Exception:
                return PortResult(port=port, service=COMMON_PORTS.get(port, "Unknown"), state="closed")

    async def run(self, ports: List[int], progress_cb: Optional[Callable[[int, int], None]] = None) -> ScanReport:
        try:
            ip = socket.gethostbyname(self.target)
        except socket.gaierror as e:
            raise RuntimeError(f"Не удалось разрешить хост '{self.target}': {e}")

        start_time = time.perf_counter()
        completed = 0
        total = len(ports)

        async def wrap_scan(p: int):
            nonlocal completed
            res = await self.scan_port(ip, p)
            completed += 1
            if progress_cb:
                progress_cb(completed, total)
            return res

        results = await asyncio.gather(*(wrap_scan(p) for p in ports))
        open_ports = sorted([r for r in results if r.state == "open"], key=lambda r: r.port)
        duration = round(time.perf_counter() - start_time, 2)

        return ScanReport(
            target=self.target,
            ip=ip,
            scan_time=time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
            duration_sec=duration,
            open_ports_count=len(open_ports),
            results=open_ports
        )

def parse_ports(port_arg: str) -> List[int]:
    if port_arg == "top":
        return sorted(list(COMMON_PORTS.keys()))
    ports = set()
    for part in port_arg.split(","):
        p = part.strip()
        if "-" in p:
            start, end = map(int, p.split("-"))
            ports.update(range(start, end + 1))
        elif p.isdigit():
            ports.add(int(p))
    return sorted(list(ports))

def display_report(report: ScanReport):
    console.print(Panel.fit(
        f"[bold cyan]Цель:[/bold cyan] {report.target} ({report.ip})\n"
        f"[bold cyan]Время сканирования:[/bold cyan] {report.duration_sec}с | [bold green]Открыто портов:[/bold green] {report.open_ports_count}",
        title="[bold white]Результаты сканирования портов[/bold white]",
        border_style="cyan"
    ))

    if not report.results:
        console.print("[yellow]Открытых портов не обнаружено.[/yellow]")
        return

    table = Table(show_header=True, header_style="bold magenta", border_style="dim")
    table.add_column("Порт", style="cyan", width=8)
    table.add_column("Сервис", style="green", width=14)
    table.add_column("Задержка", style="yellow", width=10)
    table.add_column("Информация / Баннер / Сертификат", style="white")

    for r in report.results:
        details = []
        if r.banner:
            details.append(f"Баннер: {r.banner}")
        if r.tls:
            details.append(f"TLS: {r.tls.subject} ({r.tls.days_left} дней, {r.tls.issuer})")
        table.add_row(f"{r.port}/tcp", r.service, f"{r.latency_ms} ms", " | ".join(details) or "—")

    console.print(table)

def main():
    parser = argparse.ArgumentParser(description="Асинхронный сканер портов и TLS-сертификатов")
    parser.add_argument("target", help="Хост или IP-адрес для сканирования")
    parser.add_argument("-p", "--ports", default="top", help="Порты: 'top', '80,443' или диапазон '1-1024'")
    parser.add_argument("-c", "--concurrency", type=int, default=150, help="Количество параллельных соединений")
    parser.add_argument("-t", "--timeout", type=float, default=1.5, help="Таймаут подключения (сек)")
    parser.add_argument("-o", "--output", help="Путь для сохранения отчета в формате JSON")

    args = parser.parse_args()
    ports = parse_ports(args.ports)
    scanner = Scanner(args.target, concurrency=args.concurrency, timeout=args.timeout)

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        console=console
    ) as progress:
        task = progress.add_task(f"Сканирование {args.target} ({len(ports)} портов)...", total=len(ports))
        report = asyncio.run(scanner.run(ports, progress_cb=lambda d, t: progress.update(task, completed=d)))

    display_report(report)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(report.to_dict(), f, indent=2, ensure_ascii=False)
        console.print(f"\n[green]Отчет сохранен в[/green] {args.output}")

if __name__ == "__main__":
    main()
