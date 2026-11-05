# port-scanner-recon

Asynchronous network reconnaissance & port scanner written in Python 3.10+ using `asyncio` and `rich`. Performs non-blocking TCP socket discovery, service banner extraction, and SSL/TLS x509 certificate inspections with structured JSON outputs.

## Features

- **High-Throughput Async Concurrency**: Powered by `asyncio.Semaphore` with configurable workers (defaults to 150 concurrent workers) to scan thousands of ports in seconds.
- **Service & Banner Grabbing**: Identifies active daemons and extracts response banners (SSH versions, Web server headers).
- **SSL/TLS Certificate Inspection**: Parses x509 certificates to report Issuer, Subject Common Name (CN), validity windows, and remaining expiration days.
- **Rich Terminal UI**: Styled terminal output with progress indicators, formatted data tables, and latency measurements.
- **Machine-Readable Reports**: Supports exporting full scan audits to JSON via `--output`.

## Installation

```bash
pip install rich cryptography pytest
```

## Usage

```bash
# Scan common ports on target
python -m recon.cli scanme.nmap.org

# Scan specific ports or port ranges
python -m recon.cli example.com -p "22,80,443,8000-8080"

# High-concurrency sweep with JSON report export
python -m recon.cli target.internal -p "1-1024" -c 300 -o report.json
```

## Testing

```bash
python -m pytest
```

## License

MIT © [Arkadiy Gazizov](https://arkadiygazizov.ru)
