# scanner/tcp_connect.py
import asyncio
import socket
from typing import Optional
import logging

logger = logging.getLogger(__name__)

async def tcp_connect_scan(target_ip: str, port: int, timeout: float = 1.0, rate_limiter: Optional['RateLimiter'] = None) -> str:
    """
    Performs a TCP Connect scan on a target port.
    Returns "open", "closed", "filtered", or "error".
    """
    if rate_limiter:
        await rate_limiter.acquire()

    try:
        # asyncio.open_connection tries to connect
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(target_ip, port),
            timeout=timeout
        )
        writer.close()
        await writer.wait_closed()
        return "open"
    except asyncio.TimeoutError:
        logger.debug(f"TCP Connect scan on {target_ip}:{port} timed out.")
        return "filtered" # Timeout typically indicates a firewall or host is down
    except ConnectionRefusedError:
        logger.debug(f"TCP Connect scan on {target_ip}:{port} received connection refused (closed).")
        return "closed"
    except OSError as e: # Catch other socket related errors (e.g., host unreachable)
        logger.debug(f"TCP Connect scan on {target_ip}:{port} encountered OS error: {e}")
        # Depending on the specific OSError, it could be filtered or closed
        # For simplicity, classifying as filtered for general OS errors
        return "filtered"
    except Exception as e:
        logger.debug(f"TCP Connect scan on {target_ip}:{port} unexpected error: {e}")
        return "error"

# Type hint for RateLimiter to avoid circular dependency at top level
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from .rate_limiter import RateLimiter