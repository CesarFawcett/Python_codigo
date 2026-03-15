import ipaddress
import re

def validate_target(target):
    """
    Validates if the target is a valid IP address or hostname.
    """
    # Check if it's a valid IP
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        pass

    # Basic hostname regex
    hostname_regex = r'^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$'
    if re.match(hostname_regex, target):
        return True
    
    return False

def parse_ports(port_str):
    """
    Parses port string (e.g., '80', '1-1024', '22,80,443') into a list of integers.
    """
    ports = []
    if not port_str:
        return None
    
    subsets = port_str.split(',')
    for s in subsets:
        if '-' in s:
            try:
                start, end = map(int, s.split('-'))
                if 1 <= start <= 65535 and 1 <= end <= 65535 and start <= end:
                    ports.extend(range(start, end + 1))
                else:
                    return None
            except ValueError:
                return None
        else:
            try:
                p = int(s)
                if 1 <= p <= 65535:
                    ports.append(p)
                else:
                    return None
            except ValueError:
                return None
    
    return sorted(list(set(ports)))

def validate_timeout(timeout):
    """
    Validates timeout value.
    """
    try:
        t = float(timeout)
        return t > 0
    except (ValueError, TypeError):
        return False
