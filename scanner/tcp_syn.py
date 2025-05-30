# scanner/tcp_syn.py
import asyncio
from scapy.all import IP, TCP, sr1
from typing import Optional
import logging

logger = logging.getLogger(__name__)

async def syn_scan(target_ip: str, port: int, timeout: float = 2.0, rate_limiter: Optional['RateLimiter'] = None) -> str:
    """
    Performs a TCP SYN scan on a target port.
    Returns "open", "closed", "filtered", or "error".
    """
    if rate_limiter:
        await rate_limiter.acquire()

    pkt = IP(dst=target_ip) / TCP(dport=port, flags="S")
    # sr1 is blocking, run it in executor to avoid blocking event loop
    loop = asyncio.get_running_loop()
    try:
        resp = await loop.run_in_executor(None, lambda: sr1(pkt, timeout=timeout, verbose=0))

        if resp is None:
            logger.debug(f"SYN scan on {target_ip}:{port}: No response (filtered).")
            return "filtered" # No response usually means filtered
        if resp.haslayer(TCP):
            flags = resp.getlayer(TCP).flags
            if flags == 0x12:  # SYN-ACK
                # Send RST to close connection and avoid completing the handshake
                rst_pkt = IP(dst=target_ip) / TCP(dport=port, flags="R")
                await loop.run_in_executor(None, lambda: sr1(rst_pkt, timeout=0.1, verbose=0)) # Small timeout for RST
                logger.debug(f"SYN scan on {target_ip}:{port}: SYN-ACK received (open).")
                return "open"
            elif flags == 0x14:  # RST-ACK
                logger.debug(f"SYN scan on {target_ip}:{port}: RST-ACK received (closed).")
                return "closed"
        logger.debug(f"SYN scan on {target_ip}:{port}: Unexpected TCP flags or no TCP layer (filtered). Flags: {flags if resp.haslayer(TCP) else 'N/A'}")
        return "filtered" # Any other response with TCP layer
    except Exception as e:
        logger.debug(f"SYN scan error on {target_ip}:{port}: {e}")
        return "error"

# Type hint for RateLimiter to avoid circular dependency at top level
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from .rate_limiter import RateLimiter