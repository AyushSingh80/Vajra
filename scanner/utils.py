#scanner/utils.py
import ipaddress
import socket

# Predefined common ports for top N scans (expand as needed)
TOP_PORTS = {
    10: [80, 443, 22, 21, 25, 110, 445, 3389, 139, 53],
    100: [80, 443, 22, 21, 25, 110, 445, 3389, 139, 53, 3306, 8080, 5900, 53, 23, 135, 143, 995, 1723, 111, 993, 8443, 1025, 1110, 1521, 5432, 8000, 32768, 32769, 49152, 49153, 49154, 49155, 49156, 49157, 49158, 49159, 49160, 49161, 49162, 49163, 49164, 49165, 49166, 49167, 49168, 49169, 49170, 49171, 49172, 49173, 49174, 49175, 49176, 49177, 49178, 49179, 49180, 49181, 49182, 49183, 49184, 49185, 49186, 49187, 49188, 49189, 49190, 49191, 49192, 49193, 49194, 49195, 49196, 49197, 49198, 49199, 49200, 49201, 49202, 49203, 49204, 49205, 49206, 49207, 49208, 49209, 49210, 49211, 49212, 49213, 49214, 49215, 49216],
    1000: [i for i in range(1, 1025)],  # Default top 1000 ports (simplified)
}

def validate_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def validate_port(port):
    return isinstance(port, int) and 0 < port <= 65535

def resolve_target(target_str):
    """Resolves a single target string to a list of IP addresses."""
    ips = []
    try:
        # CIDR block?
        network = ipaddress.ip_network(target_str, strict=False)
        for ip_obj in network.hosts():
            ips.append(str(ip_obj))
        if not ips and network.num_addresses == 1:  # /32
            ips.append(str(network.network_address))
        return ips
    except ValueError:
        pass

    try:
        # IP range (e.g., 192.168.1.1-100 or 192.168.1.1-192.168.1.100)
        if '-' in target_str:
            start_ip_str, end_ip_str = target_str.split('-', 1)
            start_ip = ipaddress.ip_address(start_ip_str)

            if '.' not in end_ip_str:  # e.g., 192.168.1.1-100
                end_ip_val = int(end_ip_str)
                if not (0 <= end_ip_val <= 255):
                    raise ValueError("Invalid last octet in IP range.")
                base_ip_parts = list(start_ip.packed)
                end_ip = ipaddress.ip_address(bytes(base_ip_parts[:-1] + [end_ip_val]))
            else:
                end_ip = ipaddress.ip_address(end_ip_str)

            if start_ip.version != end_ip.version:
                raise ValueError("Start and end IP must be same version.")
            if int(start_ip) > int(end_ip):
                raise ValueError("Start IP must be <= end IP in range.")

            current_ip_int = int(start_ip)
            end_ip_int = int(end_ip)
            while current_ip_int <= end_ip_int:
                ips.append(str(ipaddress.ip_address(current_ip_int)))
                current_ip_int += 1
            return ips
    except ValueError:
        pass

    try:
        # Single IP?
        ip_obj = ipaddress.ip_address(target_str)
        return [str(ip_obj)]
    except ValueError:
        pass

    try:
        # Hostname
        addr_info = socket.getaddrinfo(target_str, None)
        resolved_ips = list(set(info[4][0] for info in addr_info))
        if not resolved_ips:
            raise socket.gaierror(f"Hostname {target_str} could not be resolved.")
        return resolved_ips
    except socket.gaierror as e:
        print(f"Error resolving hostname {target_str}: {e}")
        return []

def parse_targets(target_args, input_file):
    """Parses all target specifications into a flat list of unique IP addresses."""
    all_ips = set()
    raw_targets = list(target_args)

    if input_file:
        try:
            with open(input_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        raw_targets.append(line)
        except FileNotFoundError:
            print(f"Error: Input file '{input_file}' not found.")
            return []
        except Exception as e:
            print(f"Error reading input file '{input_file}': {e}")
            return []

    for target_str in raw_targets:
        resolved = resolve_target(target_str)
        for ip in resolved:
            all_ips.add(ip)

    return sorted(all_ips)

def parse_ports(port_str=None, top_n_ports_count=None):
    """Parses port string (e.g., '22,80-100,443') or top N into a list of unique integers."""
    ports = set()

    if top_n_ports_count:
        ports = set(TOP_PORTS.get(top_n_ports_count, []))
        if not ports:
            print(f"Warning: No predefined list for top {top_n_ports_count} ports. Using top 1000.")
            ports = set(TOP_PORTS.get(1000, []))
        return sorted(ports)

    if not port_str:
        return sorted(TOP_PORTS.get(1000, []))

    try:
        components = port_str.split(',')
        for comp in components:
            comp = comp.strip()
            if not comp:
                continue
            if '-' in comp:
                start, end = map(int, comp.split('-'))
                if not (1 <= start <= 65535 and 1 <= end <= 65535 and start <= end):
                    raise ValueError(f"Invalid port range: {comp}.")
                ports.update(range(start, end + 1))
            else:
                port = int(comp)
                if not (1 <= port <= 65535):
                    raise ValueError(f"Invalid port: {port}.")
                ports.add(port)
    except ValueError as e:
        print(f"Error parsing ports: {e}")
        return []

    if not ports:
        raise ValueError("No valid ports specified.")

    return sorted(ports)

# Uncomment for CLI testing:
# if __name__ == "__main__":
#     targets = parse_targets(['127.0.0.1', 'scanme.nmap.org', '192.168.1.1-3'], None)
#     ports = parse_ports('22,80-100,443')
#     print(f"Resolved Targets: {targets}")
#     print(f"Parsed Ports: {ports}")
