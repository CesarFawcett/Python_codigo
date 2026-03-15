import pytest
from utils.validators import validate_target, parse_ports, validate_timeout

def test_validate_target():
    assert validate_target("192.168.1.1") == True
    assert validate_target("scanme.nmap.org") == True
    assert validate_target("localhost") == True
    assert validate_target("google.com") == True
    assert validate_target("invalid@target") == False
    assert validate_target("123.123.123.123.123") == False

def test_parse_ports():
    assert parse_ports("80") == [80]
    assert parse_ports("1-5") == [1, 2, 3, 4, 5]
    assert parse_ports("22,80,443") == [22, 80, 443]
    assert parse_ports("1-3,22,80") == [1, 2, 3, 22, 80]
    assert parse_ports("70000") == None
    assert parse_ports("abc") == None

def test_validate_timeout():
    assert validate_timeout("1.0") == True
    assert validate_timeout(5) == True
    assert validate_timeout(0) == False
    assert validate_timeout(-1) == False
    assert validate_timeout("abc") == False
