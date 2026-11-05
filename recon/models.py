from dataclasses import dataclass, asdict
from typing import Optional, Dict, Any
from datetime import datetime

@dataclass
class CertInfo:
    subject: str
    issuer: str
    valid_from: str
    valid_until: str
    days_left: int
    version: int

@dataclass
class PortResult:
    port: int
    service: str
    state: str  # "open" | "closed" | "filtered"
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
    results: list[PortResult]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
