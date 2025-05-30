#scanner/tcp_syn.py
import asyncio
from scapy.all import IP, TCP, sr1

async def syn_scan(target_ip, port, timeout=2, rate_limiter=None):
    if rate_limiter:
        await rate_limiter.acquire()

    pkt = IP(dst=target_ip) / TCP(dport=port, flags="S")
    # sr1 is blocking, run it in executor to avoid blocking event loop
    loop = asyncio.get_running_loop()
    resp = await loop.run_in_executor(None, lambda: sr1(pkt, timeout=timeout, verbose=0))

    if resp is None:
        return "filtered"
    if resp.haslayer(TCP):
        flags = resp.getlayer(TCP).flags
        if flags == 0x12:  # SYN-ACK
            # Send RST to close connection
            rst_pkt = IP(dst=target_ip) / TCP(dport=port, flags="R")
            await loop.run_in_executor(None, lambda: sr1(rst_pkt, timeout=timeout, verbose=0))
            return "open"
        elif flags == 0x14:  # RST-ACK
            return "closed"
    return "filtered"
