# scanner/service_detector.py
import socket
import asyncio
from typing import Optional, Dict, Tuple
import logging
from dataclasses import dataclass

logger = logging.getLogger(__name__)

@dataclass
class ServiceInfo:
    name: str
    version: Optional[str] = None
    banner: Optional[str] = None
    protocol: str = "tcp"

class ServiceDetector:
    def __init__(self, timeout: float = 2.0):
        self.timeout = timeout
        self._common_ports = {
            21: "ftp",
            22: "ssh",
            23: "telnet",
            25: "smtp",
            53: "dns",
            80: "http",
            110: "pop3",
            143: "imap",
            443: "https",
            3306: "mysql",
            3389: "rdp",
            5432: "postgresql",
            27017: "mongodb"
        }

    async def detect_service(self, host: str, port: int) -> Optional[ServiceInfo]:
        """
        Detect service running on a specific port
        
        Args:
            host: Target host
            port: Target port
            
        Returns:
            ServiceInfo if service detected, None otherwise
        """
        try:
            # First check if it's a common port
            if port in self._common_ports:
                service_name = self._common_ports[port]
                banner = await self._get_banner(host, port)
                return ServiceInfo(
                    name=service_name,
                    banner=banner,
                    protocol="tcp"
                )

            # If not a common port, try to get banner
            banner = await self._get_banner(host, port)
            if banner:
                service_name = self._identify_service_from_banner(banner)
                return ServiceInfo(
                    name=service_name,
                    banner=banner,
                    protocol="tcp"
                )

            return None

        except Exception as e:
            logger.error(f"Error detecting service on {host}:{port}: {str(e)}")
            return None

    async def _get_banner(self, host: str, port: int) -> Optional[str]:
        """Get service banner"""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=self.timeout
            )

            # Try to read banner
            try:
                banner = await asyncio.wait_for(
                    reader.read(1024),
                    timeout=self.timeout
                )
                return banner.decode('utf-8', errors='ignore').strip()
            except:
                return None
            finally:
                writer.close()
                await writer.wait_closed()

        except Exception as e:
            logger.debug(f"Could not get banner from {host}:{port}: {str(e)}")
            return None

    def _identify_service_from_banner(self, banner: str) -> str:
        """Identify service from banner text"""
        banner = banner.lower()
        
        # Common service signatures
        signatures = {
            "ssh": ["ssh", "openssh"],
            "http": ["http", "apache", "nginx", "iis"],
            "ftp": ["ftp", "vsftpd", "proftpd"],
            "smtp": ["smtp", "postfix", "sendmail", "exim"],
            "pop3": ["pop3", "dovecot"],
            "imap": ["imap", "dovecot"],
            "mysql": ["mysql"],
            "postgresql": ["postgresql", "postgres"],
            "mongodb": ["mongodb"],
            "redis": ["redis"],
            "memcached": ["memcached"],
            "elasticsearch": ["elasticsearch"],
            "cassandra": ["cassandra"],
            "rabbitmq": ["rabbitmq"],
            "zookeeper": ["zookeeper"],
            "kafka": ["kafka"],
            "tomcat": ["tomcat", "apache tomcat"],
            "jetty": ["jetty"],
            "glassfish": ["glassfish"],
            "wildfly": ["wildfly", "jboss"],
            "weblogic": ["weblogic"],
            "websphere": ["websphere"],
            "iis": ["iis", "microsoft-iis"],
            "nginx": ["nginx"],
            "apache": ["apache", "httpd"]
        }

        for service, patterns in signatures.items():
            if any(pattern in banner for pattern in patterns):
                return service

        return "unknown"

def detect_service(host: str, port: int) -> Optional[str]:
    """
    Synchronous wrapper for service detection
    
    Args:
        host: Target host
        port: Target port
        
    Returns:
        Service name if detected, None otherwise
    """
    detector = ServiceDetector()
    try:
        service_info = asyncio.run(detector.detect_service(host, port))
        return service_info.name if service_info else None
    except Exception as e:
        logger.error(f"Error in service detection: {str(e)}")
        return None
