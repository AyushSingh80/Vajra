from .tcp_connect import tcp_connect_scan
from .tcp_syn import syn_scan
from .udp import udp_scan
from .stealth import fin_scan, null_scan, xmas_scan, ack_scan

async def scan_dispatcher(scan_type, target_ip, port, rate_limiter=None):
    scan_type = scan_type.lower()
    if scan_type == "tcp":
        return await tcp_connect_scan(target_ip, port, rate_limiter=rate_limiter)
    elif scan_type == "syn":
        return await syn_scan(target_ip, port, rate_limiter=rate_limiter)
    elif scan_type == "udp":
        return udp_scan(target_ip, port)  # udp_scan is sync, keep it like this for now
    elif scan_type == "fin":
        return await fin_scan(target_ip, port, rate_limiter=rate_limiter)
    elif scan_type == "null":
        return await null_scan(target_ip, port, rate_limiter=rate_limiter)
    elif scan_type == "xmas":
        return await xmas_scan(target_ip, port, rate_limiter=rate_limiter)
    elif scan_type == "ack":
        return await ack_scan(target_ip, port, rate_limiter=rate_limiter)
    else:
        return "Invalid scan type"
