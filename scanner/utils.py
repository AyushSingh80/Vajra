import ipaddress
import socket

def parse_targets(target_input):
    targets = []
    try:
        # CIDR/Range Handling
        if "/" in target_input:
            net = ipaddress.IPv4Network(target_input, strict=False)
            targets = [str(ip) for ip in net.hosts()]
        elif "-" in target_input:
            start, end = target_input.split("-")
            start_ip = ipaddress.IPv4Address(start)
            end_ip = ipaddress.IPv4Address(end)
            targets = [str(ip) for ip in range(int(start_ip), int(end_ip) + 1)]
        else:
            # Single IP or hostname
            targets = [socket.gethostbyname(target_input)]
    except Exception as e:
        print(f"Error parsing target {target_input}: {e}")
    return targets
