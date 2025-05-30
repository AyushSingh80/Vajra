# scanner/utils.py
import ipaddress
import socket
import logging
import re
from typing import List, Optional, Iterable, Union

logger = logging.getLogger(__name__)

# Predefined common ports for top N scans (expand as needed)
TOP_PORTS = {
    10: [80, 443, 22, 21, 25, 110, 445, 3389, 139, 53],
    100: [80, 443, 22, 21, 25, 110, 445, 3389, 139, 53, 3306, 8080, 5900, 53, 23, 135, 143, 995, 1723, 111, 993, 8443, 1025, 1110, 1521, 5432, 8000, 32768, 32769, 49152, 49153, 49154, 49155, 49156, 49157, 49158, 49159, 49160, 49161, 49162, 49163, 49164, 49165, 49166, 49167, 49168, 49169, 49170, 49171, 49172, 49173, 49174, 49175, 49176, 49177, 49178, 49179, 49180, 49181, 49182, 49183, 49184, 49185, 49186, 49187, 49188, 49189, 49190, 49191, 49192, 49193, 49194, 49195, 49196, 49197, 49198, 49199, 49200, 49201, 49202, 49203, 49204, 49205, 49206, 49207, 49208, 49209, 49210, 49211, 49212, 49213, 49214, 49215, 49216],
    # 1000: Default top 1000 ports (simplified as 1-1024 in this implementation)
    1000: [i for i in range(1, 1025)],
}

def validate_target(target: str) -> bool:
    """
    Validate if the target is a valid IP address, hostname, CIDR notation, or IP range.
    
    Args:
        target: Target to validate (IP, hostname, CIDR, or range)
        
    Returns:
        bool: True if target is valid, False otherwise
    """
    try:
        # Check for CIDR notation
        if '/' in target:
            ipaddress.ip_network(target, strict=False)
            return True
            
        # Check for IP range (e.g., 192.168.1.1-10)
        if '-' in target:
            start, end = target.split('-')
            try:
                start_ip = ipaddress.ip_address(start)
                # If end is just a number, append it to the start IP's network
                if end.isdigit():
                    end_ip = ipaddress.ip_address(f"{'.'.join(start.split('.')[:-1])}.{end}")
                else:
                    end_ip = ipaddress.ip_address(end)
                return start_ip < end_ip
            except ValueError:
                return False
                
        # Check for single IP
        try:
            ipaddress.ip_address(target)
            return True
        except ValueError:
            pass
            
        # Check for valid hostname
        if re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$', target):
            return True
            
        return False
        
    except Exception:
        return False

def validate_ip(ip: str) -> bool:
    """Validates if a string is a valid IP address."""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def validate_port(port: Union[int, str]) -> bool:
    """Validates if an integer is a valid port number (1-65535)."""
    try:
        port_num = int(port)
        return 0 < port_num < 65536
    except (ValueError, TypeError):
        return False

def resolve_target(target_str: str) -> List[str]:
    """
    Resolves a single target string (IP, CIDR, range, or hostname) to a list of unique IP addresses.
    Raises ValueError for invalid formats or socket.gaierror for unresolvable hostnames.
    """
    ips = []
    
    # Try CIDR block
    try:
        network = ipaddress.ip_network(target_str, strict=False)
        # If it's a /32 or /128, only the network address is the host
        if network.num_addresses == 1:
            ips.append(str(network.network_address))
        else:
            for ip_obj in network.hosts(): # .hosts() excludes network and broadcast addresses
                ips.append(str(ip_obj))
        return ips
    except ValueError:
        pass # Not a CIDR, continue to next check

    # Try IP range (e.g., 192.168.1.1-100 or 192.168.1.1-192.168.1.100)
    if '-' in target_str:
        try:
            start_ip_str, end_ip_str = target_str.split('-', 1)
            start_ip = ipaddress.ip_address(start_ip_str)

            if '.' not in end_ip_str and ':' not in end_ip_str:  # e.g., 192.168.1.1-100
                if start_ip.version == 4:
                    end_octet_val = int(end_ip_str)
                    if not (0 <= end_octet_val <= 255):
                        raise ValueError("Invalid last octet in IP range.")
                    base_ip_parts = list(start_ip.packed)
                    end_ip = ipaddress.ip_address(bytes(base_ip_parts[:-1] + [end_octet_val]))
                else: # IPv6 ranges like 2001:db8::1-100 are not supported by this shorthand
                    raise ValueError("IPv6 ranges require full IP addresses (e.g., fe80::1-fe80::100).")
            else: # e.g., 192.168.1.1-192.168.1.100 or fe80::1-fe80::100
                end_ip = ipaddress.ip_address(end_ip_str)

            if start_ip.version != end_ip.version:
                raise ValueError("Start and end IP must be the same version (IPv4 or IPv6).")
            if int(start_ip) > int(end_ip):
                raise ValueError("Start IP must be less than or equal to end IP in range.")

            current_ip_int = int(start_ip)
            end_ip_int = int(end_ip)
            while current_ip_int <= end_ip_int:
                ips.append(str(ipaddress.ip_address(current_ip_int)))
                current_ip_int += 1
            return ips
        except ValueError as e:
            # Re-raise with context for clarity if range parsing fails
            raise ValueError(f"Invalid IP range format '{target_str}': {e}") from e
    
    # Try single IP
    try:
        ip_obj = ipaddress.ip_address(target_str)
        return [str(ip_obj)]
    except ValueError:
        pass # Not a single IP, continue

    # Try Hostname
    try:
        addr_info = socket.getaddrinfo(target_str, None)
        # Filter for unique IP addresses, preserving order as much as possible if important
        # Using a set to ensure uniqueness then converting to list
        resolved_ips = list(dict.fromkeys(info[4][0] for info in addr_info if validate_ip(info[4][0])))
        if not resolved_ips:
            # Raise a specific socket error if hostname resolves but no valid IPs are found
            raise socket.gaierror(f"Hostname '{target_str}' resolved but no valid IP addresses found.")
        return resolved_ips
    except socket.gaierror as e:
        # Re-raise socket.gaierror for unresolvable hostnames
        raise e
    except Exception as e:
        logger.error(f"An unexpected error occurred during resolution of '{target_str}': {e}")
        return [] # Return empty list on unexpected errors

def parse_targets(target_args: Iterable[str], input_file: Optional[str]) -> List[str]:
    """
    Parses all target specifications (CLI args and input file) into a flat list of unique IP addresses.
    Logs errors for invalid targets but continues processing others.
    """
    all_ips: set[str] = set()
    raw_targets = list(target_args)

    if input_file:
        try:
            with open(input_file, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        raw_targets.append(line)
        except FileNotFoundError:
            logger.error(f"Error: Input file '{input_file}' not found.")
            return [] # Critical error, cannot proceed without input file
        except Exception as e:
            logger.error(f"Error reading input file '{input_file}': {e}")
            return [] # Critical error

    if not raw_targets:
        logger.warning("No targets specified for scanning.")
        return []

    for target_str in raw_targets:
        try:
            resolved = resolve_target(target_str)
            for ip in resolved:
                if validate_ip(ip):
                    all_ips.add(ip)
                else:
                    logger.warning(f"Skipping invalid IP '{ip}' resolved from '{target_str}'.")
        except (ValueError, socket.gaierror) as e:
            logger.warning(f"Could not resolve target '{target_str}': {e}")
        except Exception as e:
            logger.warning(f"An unexpected error occurred while processing target '{target_str}': {e}")

    if not all_ips:
        logger.error("No valid IP addresses could be parsed from the provided targets. Exiting.")

    return sorted(list(all_ips))

def parse_ports(port_str: Optional[str] = None, top_n_ports_count: Optional[int] = None) -> List[int]:
    """
    Parses port string (e.g., '22,80-100,443') or top N into a list of unique integers.
    If neither is specified, defaults to TOP_PORTS[1000].
    Raises ValueError for invalid port specifications.
    """
    ports: set[int] = set()

    if top_n_ports_count:
        if top_n_ports_count in TOP_PORTS:
            ports.update(TOP_PORTS[top_n_ports_count])
        else:
            logger.warning(f"No predefined list for top {top_n_ports_count} ports. Falling back to top 1000.")
            ports.update(TOP_PORTS.get(1000, []))
        return sorted(list(ports))

    if not port_str:
        # Default behavior: if no ports or top-ports specified, use top 1000
        logger.info("No ports specified. Defaulting to top 1000 common ports.")
        return sorted(TOP_PORTS.get(1000, []))

    components = port_str.split(',')
    for comp in components:
        comp = comp.strip()
        if not comp:
            continue
        try:
            if '-' in comp:
                start_str, end_str = comp.split('-')
                start = int(start_str)
                end = int(end_str)
                if not (validate_port(start) and validate_port(end) and start <= end):
                    raise ValueError(f"Invalid port range: {comp}. Ports must be between 1 and 65535, and start <= end.")
                ports.update(range(start, end + 1))
            else:
                port = int(comp)
                if not validate_port(port):
                    raise ValueError(f"Invalid port: {port}. Port must be between 1 and 65535.")
                ports.add(port)
        except ValueError as e:
            raise ValueError(f"Error parsing port component '{comp}': {e}") from e

    if not ports:
        raise ValueError("No valid ports could be parsed from the input.")

    return sorted(list(ports))