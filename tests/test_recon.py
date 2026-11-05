import pytest
from recon.cli import parse_ports
from recon.probes import get_service_name

def test_parse_ports_presets():
    top = parse_ports("top")
    assert 80 in top
    assert 443 in top
    assert 22 in top

def test_parse_ports_range():
    ports = parse_ports("80,443,8000-8002")
    assert ports == [80, 443, 8000, 8001, 8002]

def test_service_naming():
    assert get_service_name(443) == "HTTPS"
    assert get_service_name(5432) == "PostgreSQL"
    assert get_service_name(9999) == "Unknown"
