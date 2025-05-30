# scanner/tcp_syn.py
import asyncio
from scapy.all import IP, TCP, sr1, conf
import logging
from typing import Optional
from .rate_limiter import RateLimiter

logger = logging.getLogger(__name__)

async def syn_scan(target: str, port: int, timeout: float = 2.0, rate_limiter: Optional[RateLimiter] = None) -> str:
    """
    Perform a TCP SYN scan on the specified target and port.
    
    Args:
        target: Target IP address
        port: Target port
        timeout: Timeout in seconds
        rate_limiter: Optional rate limiter
        
    Returns:
        str: Scan result status ("open", "closed", "filtered", "error")
    """
    try:
        # Configure Scapy for Windows
        conf.use_pcap = False  # Disable pcap on Windows
        conf.use_dnet = False  # Disable dnet on Windows
        
        # Create the SYN packet
        ip = IP(dst=target)
        syn = TCP(dport=port, flags="S")
        
        # Send the packet and wait for response
        response = sr1(ip/syn, timeout=timeout, verbose=0)
        
        if response is None:
            return "filtered"
            
        # Check TCP flags in response
        if response.haslayer(TCP):
            tcp = response.getlayer(TCP)
            if tcp.flags == 0x12:  # SYN-ACK
                # Send RST to close the connection
                rst = TCP(dport=port, flags="R")
                sr1(ip/rst, timeout=timeout, verbose=0)
                return "open"
            elif tcp.flags == 0x14:  # RST-ACK
                return "closed"
        elif response.haslayer(ICMP):
            # Check for ICMP error messages
            icmp = response.getlayer(ICMP)
            if int(icmp.type) == 3 and int(icmp.code) in [1, 2, 3, 9, 10, 13]:
                return "filtered"
                
        return "filtered"
        
    except Exception as e:
        logger.error(f"Error in SYN scan for {target}:{port}: {str(e)}")
        return "error"

# Type hint for RateLimiter to avoid circular dependency at top level
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from .rate_limiter import RateLimiter