# scanner/tcp_connect.py
import asyncio
import socket
import logging
from typing import Optional
from .rate_limiter import RateLimiter

logger = logging.getLogger(__name__)

async def tcp_connect_scan(target: str, port: int, timeout: float = 2.0, rate_limiter: Optional[RateLimiter] = None) -> str:
    """
    Perform a TCP connect scan on the specified target and port.
    
    Args:
        target: Target IP address
        port: Target port
        timeout: Timeout in seconds
        rate_limiter: Optional rate limiter
        
    Returns:
        str: Scan result status ("open", "closed", "filtered", "error")
    """
    if rate_limiter:
        await rate_limiter.acquire()

    try:
        # Create socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        
        # Attempt connection
        result = sock.connect_ex((target, port))
        
        # Close socket
        sock.close()
        
        if result == 0:
            return "open"
        elif result in [10061, 111]:  # Connection refused
            return "closed"
        else:
            return "filtered"
            
    except socket.timeout:
        return "filtered"
    except ConnectionRefusedError:
        return "closed"
    except Exception as e:
        logger.error(f"Error in TCP connect scan for {target}:{port}: {str(e)}")
        return "error"

# Type hint for RateLimiter to avoid circular dependency at top level
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from .rate_limiter import RateLimiter