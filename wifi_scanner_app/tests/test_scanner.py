import pytest
from unittest.mock import MagicMock, patch
from wifi_scanner.utils import validate_ip_range, get_hostname
from wifi_scanner.core import NetworkScanner

def test_validate_ip_range():
    assert validate_ip_range("192.168.1.0/24") is True
    assert validate_ip_range("10.0.0.0/8") is True
    assert validate_ip_range("invalid-ip") is False
    assert validate_ip_range("256.256.256.256/24") is False

@patch("socket.gethostbyaddr")
def test_get_hostname_success(mock_gethost):
    mock_gethost.return_value = ("my-device", [], [])
    assert get_hostname("192.168.1.1") == "my-device"

@patch("socket.gethostbyaddr")
def test_get_hostname_failure(mock_gethost):
    import socket
    mock_gethost.side_effect = socket.herror
    assert get_hostname("192.168.1.1") == "Unknown"

@patch("wifi_scanner.core.srp")
@patch("wifi_scanner.core.get_hostname")
def test_scanner_logic(mock_hostname, mock_srp):
    # Mock Scapy response
    # srp returns a tuple (answered, unanswered)
    # answered is a list of (sent_packet, received_packet)
    mock_received = MagicMock()
    mock_received.psrc = "192.168.1.5"
    mock_received.hwsrc = "00:11:22:33:44:55"
    
    mock_srp.return_value = ([(None, mock_received)], [])
    mock_hostname.return_value = "TestDevice"
    
    scanner = NetworkScanner()
    results = scanner.scan_network("192.168.1.0/24")
    
    assert len(results) == 1
    assert results[0]['ip'] == "192.168.1.5"
    assert results[0]['mac'] == "00:11:22:33:44:55"
    assert results[0]['hostname'] == "TestDevice"
