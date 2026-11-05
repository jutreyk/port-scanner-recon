import socket
import ssl
from datetime import datetime
from typing import Optional
from .models import CertInfo

COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    465: "SMTPS",
    993: "IMAPS",
    995: "POP3S",
    3306: "MySQL",
    5432: "PostgreSQL",
    6379: "Redis",
    8000: "HTTP-Alt",
    8080: "HTTP-Proxy",
    8443: "HTTPS-Alt",
    9092: "Kafka"
}

def get_service_name(port: int) -> str:
    return COMMON_PORTS.get(port, "Unknown")

def inspect_tls_certificate(host: str, port: int, timeout: float = 3.0) -> Optional[CertInfo]:
    """Inspects and parses x509 SSL/TLS certificate for https/tls endpoints."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert(binary_form=False)
                if not cert:
                    # Der format fallback
                    der = ssock.getpeercert(binary_form=True)
                    if not der:
                        return None
                    return None

                subject = dict(x[0] for x in cert.get('subject', []))
                issuer = dict(x[0] for x in cert.get('issuer', []))

                not_after = cert.get('notAfter')
                not_before = cert.get('notBefore')

                days_left = 0
                if not_after:
                    expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                    days_left = (expiry - datetime.utcnow()).days

                return CertInfo(
                    subject=subject.get('commonName', 'Unknown'),
                    issuer=issuer.get('organizationName', issuer.get('commonName', 'Unknown')),
                    valid_from=not_before or '',
                    valid_until=not_after or '',
                    days_left=days_left,
                    version=cert.get('version', 3)
                )
    except Exception:
        return None

def grab_service_banner(host: str, port: int, timeout: float = 2.0) -> Optional[str]:
    """Attempts lightweight TCP banner grab."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((host, port))

            # Send probe for HTTP
            if port in (80, 8080, 8000):
                s.sendall(b"HEAD / HTTP/1.0\r\nHost: " + host.encode() + b"\r\n\r\n")

            data = s.recv(512)
            if data:
                # Clean readable ascii chars
                clean = "".join(chr(b) for b in data if 32 <= b <= 126)
                return clean[:80].strip() or None
    except Exception:
        pass
    return None
