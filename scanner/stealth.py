# scanner/stealth.py
import asyncio
from scapy.all import IP, TCP, sr1
from typing import Optional
import logging

logger = logging.getLogger(__name__)

async def fin_scan(target_ip: str, port: int, timeout: float = 2.0, rate_limiter: Optional['RateLimiter'] = None) -> str:
    """
    Performs a TCP FIN scan on a target port.
    Returns "open|filtered", "closed", or "filtered".
    """
    if rate_limiter:
        await rate_limiter.acquire()

    pkt = IP(dst=target_ip) / TCP(dport=port, flags="F")
    loop = asyncio.get_running_loop()
    try:
        # sr1 is blocking, run it in executor to avoid blocking event loop
        resp = await loop.run_in_executor(None, lambda: sr1(pkt, timeout=timeout, verbose=0))

        if resp is None:
            # No response means port is open or filtered according to FIN scan
            return "open|filtered"
        if resp.haslayer(TCP):
            flags = resp.getlayer(TCP).flags
            if flags == 0x14:  # RST (RST-ACK for some OS)
                return "closed"
        return "filtered" # Any other response or no TCP layer means filtered
    except Exception as e:
        logger.debug(f"FIN scan error on {target_ip}:{port}: {e}")
        return "error"

async def null_scan(target_ip: str, port: int, timeout: float = 2.0, rate_limiter: Optional['RateLimiter'] = None) -> str:
    """
    Performs a TCP NULL scan on a target port.
    Returns "open|filtered", "closed", or "filtered".
    """
    if rate_limiter:
        await rate_limiter.acquire()

    pkt = IP(dst=target_ip) / TCP(dport=port, flags=0) # No flags set
    loop = asyncio.get_running_loop()
    try:
        resp = await loop.run_in_executor(None, lambda: sr1(pkt, timeout=timeout, verbose=0))

        if resp is None:
            return "open|filtered"
        if resp.haslayer(TCP):
            flags = resp.getlayer(TCP).flags
            if flags == 0x14: # RST (RST-ACK for some OS)
                return "closed"
        return "filtered" # Any other response or no TCP layer means filtered
    except Exception as e:
        logger.debug(f"NULL scan error on {target_ip}:{port}: {e}")
        return "error"

async def xmas_scan(target_ip: str, port: int, timeout: float = 2.0, rate_limiter: Optional['RateLimiter'] = None) -> str:
    """
    Performs a TCP XMAS scan on a target port.
    Returns "open|filtered", "closed", or "filtered".
    """
    if rate_limiter:
        await rate_limiter.acquire()

    pkt = IP(dst=target_ip) / TCP(dport=port, flags="FPU") # FIN, PSH, URG flags set
    loop = asyncio.get_running_loop()
    try:
        resp = await loop.run_in_executor(None, lambda: sr1(pkt, timeout=timeout, verbose=0))

        if resp is None:
            return "open|filtered"
        if resp.haslayer(TCP):
            flags = resp.getlayer(TCP).flags
            if flags == 0x14: # RST (RST-ACK for some OS)
                return "closed"
        return "filtered" # Any other response or no TCP layer means filtered
    except Exception as e:
        logger.debug(f"XMAS scan error on {target_ip}:{port}: {e}")
        return "error"

async def ack_scan(target_ip: str, port: int, timeout: float = 2.0, rate_limiter: Optional['RateLimiter'] = None) -> str:
    """
    Performs a TCP ACK scan on a target port.
    Returns "unfiltered" or "filtered".
    """
    if rate_limiter:
        await rate_limiter.acquire()

    pkt = IP(dst=target_ip) / TCP(dport=port, flags="A") # ACK flag set
    loop = asyncio.get_running_loop()
    try:
        resp = await loop.run_in_executor(None, lambda: sr1(pkt, timeout=timeout, verbose=0))

        if resp is None:
            return "filtered" # No response typically means filtered (firewall dropping ACK)
        if resp.haslayer(TCP):
            flags = resp.getlayer(TCP).flags
            # ACK scan responses: RST means unfiltered (no firewall blocking state)
            if flags == 0x14: # RST
                return "unfiltered"
        return "filtered" # Any other response means filtered
    except Exception as e:
        logger.debug(f"ACK scan error on {target_ip}:{port}: {e}")
        return "error"

# Type hint for RateLimiter to avoid circular dependency at top level
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from .rate_limiter import RateLimiter