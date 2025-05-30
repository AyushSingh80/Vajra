# scanner/udp.py
import socket
import asyncio
from typing import Optional
import logging

logger = logging.getLogger(__name__)

async def udp_scan(target_ip: str, port: int, timeout: float = 1.0, rate_limiter: Optional['RateLimiter'] = None) -> str:
    """
    Performs a UDP scan on a target port.
    Returns "open", "open|filtered", "closed", or "error".
    """
    if rate_limiter:
        await rate_limiter.acquire()

    def _perform_udp_scan_blocking():
        """Synchronous part of UDP scan to be run in executor."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            sock.sendto(b'', (target_ip, port)) # Send an empty UDP packet

            # Try to receive data; if no response, it's open|filtered
            # If an ICMP port unreachable is received, it's closed
            sock.recvfrom(1024)
            logger.debug(f"UDP scan on {target_ip}:{port}: Received response (open).")
            return "open" # Received a response
        except socket.timeout:
            # Most common case for open/filtered UDP ports: no response
            logger.debug(f"UDP scan on {target_ip}:{port}: Timeout (open|filtered).")
            return "open|filtered"
        except ConnectionRefusedError: # This might occur if a local firewall actively rejects
            logger.debug(f"UDP scan on {target_ip}:{port}: Connection refused (closed).")
            return "closed"
        except socket.error as e:
            # For ICMP port unreachable, a socket.error might be raised
            # Depending on OS and Scapy integration, this can vary.
            # Example: [Errno 10054] for Windows for ICMP Port Unreachable
            # ICMP error messages from socket can be tricky to distinguish from other errors
            if "connection refused" in str(e).lower() or "port unreachable" in str(e).lower():
                logger.debug(f"UDP scan on {target_ip}:{port}: {e} (closed).")
                return "closed"
            logger.debug(f"UDP scan on {target_ip}:{port}: Generic socket error: {e} (filtered).")
            return "filtered" # Other socket errors often mean filtered
        except Exception as e:
            logger.debug(f"UDP scan on {target_ip}:{port}: Unexpected error: {e}.")
            return "error"
        finally:
            if 'sock' in locals() and sock: # Ensure sock is defined before closing
                sock.close()

    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, _perform_udp_scan_blocking)

# Type hint for RateLimiter to avoid circular dependency at top level
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from .rate_limiter import RateLimiter