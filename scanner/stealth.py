# scanner/stealth.py
import asyncio
from scapy.all import IP, TCP, sr1

async def fin_scan(target_ip, port, timeout=2, rate_limiter=None):
    if rate_limiter:
        await rate_limiter.acquire()

    pkt = IP(dst=target_ip) / TCP(dport=port, flags="F")
    loop = asyncio.get_running_loop()
    resp = await loop.run_in_executor(None, lambda: sr1(pkt, timeout=timeout, verbose=0))

    if resp is None:
        # No response means port is open or filtered according to FIN scan
        return "open|filtered"
    if resp.haslayer(TCP):
        flags = resp.getlayer(TCP).flags
        if flags == 0x14:  # RST
            return "closed"
    return "filtered"

async def null_scan(target_ip, port, timeout=2, rate_limiter=None):
    if rate_limiter:
        await rate_limiter.acquire()

    pkt = IP(dst=target_ip) / TCP(dport=port, flags=0)
    loop = asyncio.get_running_loop()
    resp = await loop.run_in_executor(None, lambda: sr1(pkt, timeout=timeout, verbose=0))

    if resp is None:
        return "open|filtered"
    if resp.haslayer(TCP):
        flags = resp.getlayer(TCP).flags
        if flags == 0x14:
            return "closed"
    return "filtered"

async def xmas_scan(target_ip, port, timeout=2, rate_limiter=None):
    if rate_limiter:
        await rate_limiter.acquire()

    pkt = IP(dst=target_ip) / TCP(dport=port, flags="FPU")
    loop = asyncio.get_running_loop()
    resp = await loop.run_in_executor(None, lambda: sr1(pkt, timeout=timeout, verbose=0))

    if resp is None:
        return "open|filtered"
    if resp.haslayer(TCP):
        flags = resp.getlayer(TCP).flags
        if flags == 0x14:
            return "closed"
    return "filtered"

async def ack_scan(target_ip, port, timeout=2, rate_limiter=None):
    if rate_limiter:
        await rate_limiter.acquire()

    pkt = IP(dst=target_ip) / TCP(dport=port, flags="A")
    loop = asyncio.get_running_loop()
    resp = await loop.run_in_executor(None, lambda: sr1(pkt, timeout=timeout, verbose=0))

    if resp is None:
        return "filtered"
    if resp.haslayer(TCP):
        flags = resp.getlayer(TCP).flags
        # ACK scan responses: RST means unfiltered, no RST means filtered
        if flags == 0x14:
            return "unfiltered"
    return "filtered"
