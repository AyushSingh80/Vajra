import socket
import asyncio
import logging
from dataclasses import dataclass
from typing import Optional, Tuple

logger = logging.getLogger(__name__)

@dataclass
class ServiceInfo:
    """Class to store service detection results"""
    name: str
    version: Optional[str] = None
    banner: Optional[str] = None
    os: Optional[str] = None

# Common service ports and their default services
COMMON_SERVICES = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    143: "imap",
    443: "https",
    445: "microsoft-ds",
    3306: "mysql",
    3389: "rdp",
    5432: "postgresql",
    8080: "http-proxy"
}

async def detect_service(target: str, port: int, timeout: float = 2.0) -> Optional[ServiceInfo]:
    """
    Attempt to detect the service running on the specified port.
    
    Args:
        target: Target IP address
        port: Target port
        timeout: Connection timeout in seconds
        
    Returns:
        Optional[ServiceInfo]: Service information if detected, None otherwise
    """
    try:
        # First check if it's a common service
        if port in COMMON_SERVICES:
            service_name = COMMON_SERVICES[port]
            
            # Try to get banner for some services
            if service_name in ["http", "https", "ftp", "smtp", "pop3", "imap"]:
                banner = await get_banner(target, port, timeout)
                return ServiceInfo(
                    name=service_name,
                    banner=banner
                )
            return ServiceInfo(name=service_name)
            
        # For unknown ports, try to get a banner
        banner = await get_banner(target, port, timeout)
        if banner:
            # Try to identify service from banner
            service_name = identify_service_from_banner(banner)
            return ServiceInfo(
                name=service_name or "unknown",
                banner=banner
            )
            
        return None
        
    except Exception as e:
        logger.debug(f"Error detecting service on {target}:{port}: {str(e)}")
        return None

async def get_banner(target: str, port: int, timeout: float) -> Optional[str]:
    """Get service banner from the target port."""
    try:
        # Create socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        
        # Connect and receive banner
        await asyncio.get_event_loop().sock_connect(sock, (target, port))
        banner = await asyncio.get_event_loop().sock_recv(sock, 1024)
        
        # Close socket
        sock.close()
        
        # Decode banner
        return banner.decode('utf-8', errors='ignore').strip()
        
    except Exception as e:
        logger.debug(f"Error getting banner from {target}:{port}: {str(e)}")
        return None

def identify_service_from_banner(banner: str) -> Optional[str]:
    """Try to identify service from banner text."""
    banner = banner.lower()
    
    # Common service signatures
    if "http" in banner or "apache" in banner or "nginx" in banner:
        return "http"
    elif "ssh" in banner:
        return "ssh"
    elif "ftp" in banner:
        return "ftp"
    elif "smtp" in banner:
        return "smtp"
    elif "pop3" in banner:
        return "pop3"
    elif "imap" in banner:
        return "imap"
    elif "mysql" in banner:
        return "mysql"
    elif "postgresql" in banner:
        return "postgresql"
    elif "microsoft" in banner or "windows" in banner:
        return "microsoft-ds"
        
    return None 