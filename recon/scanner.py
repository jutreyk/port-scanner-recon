import asyncio
import socket
import time
from typing import List, Callable, Optional
from .models import PortResult, ScanReport
from .probes import get_service_name, inspect_tls_certificate, grab_service_banner

class AsyncScanner:
    def __init__(self, target: str, concurrency: int = 100, timeout: float = 1.5):
        self.target = target
        self.concurrency = concurrency
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

                service = get_service_name(port)
                
                # Secondary probes (run in thread pool to avoid blocking event loop)
                loop = asyncio.get_running_loop()
                banner = await loop.run_in_executor(None, grab_service_banner, host, port, 1.5)
                
                tls_info = None
                if port in (443, 8443, 465, 993, 995):
                    tls_info = await loop.run_in_executor(None, inspect_tls_certificate, host, port, 2.0)

                return PortResult(
                    port=port,
                    service=service,
                    state="open",
                    banner=banner,
                    tls=tls_info,
                    latency_ms=round(latency, 2)
                )

            except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                return PortResult(
                    port=port,
                    service=get_service_name(port),
                    state="closed"
                )

    async def scan(self, ports: List[int], progress_cb: Optional[Callable[[int, int], None]] = None) -> ScanReport:
        try:
            resolved_ip = socket.gethostbyname(self.target)
        except socket.gaierror as e:
            raise RuntimeError(f"Could not resolve host '{self.target}': {e}")

        start_time = time.perf_counter()
        tasks = []

        total = len(ports)
        completed = 0

        async def wrap_scan(p: int):
            nonlocal completed
            res = await self.scan_port(resolved_ip, p)
            completed += 1
            if progress_cb:
                progress_cb(completed, total)
            return res

        for p in ports:
            tasks.append(asyncio.create_task(wrap_scan(p)))

        results = await asyncio.gather(*tasks)
        open_results = [r for r in results if r.state == "open"]
        open_results.sort(key=lambda r: r.port)

        duration = time.perf_counter() - start_time

        return ScanReport(
            target=self.target,
            ip=resolved_ip,
            scan_time=time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
            duration_sec=round(duration, 2),
            open_ports_count=len(open_results),
            results=open_results
        )
