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
    """
    Detects services and tries to grab banners from open ports.
    """
    def __init__(self, timeout: float = 2.0):
        self.timeout = timeout
        self._common_ports = {
            21: "ftp",
            22: "ssh",
            23: "telnet",
            25: "smtp",
            53: "dns", # DNS often UDP, but sometimes TCP for zone transfers/large queries
            80: "http",
            110: "pop3",
            143: "imap",
            443: "https",
            3306: "mysql",
            3389: "rdp",
            5432: "postgresql",
            27017: "mongodb",
            6379: "redis", # Added common redis port
            8080: "http-alt", # Common web server alternative
            8443: "https-alt" # Common web server alternative
        }

    async def detect_service(self, host: str, port: int) -> Optional[ServiceInfo]:
        """
        Detect service running on a specific port.

        Args:
            host: Target host
            port: Target port

        Returns:
            ServiceInfo if service detected, None otherwise.
        """
        service_name = None
        banner = None

        try:
            # If it's a common port, assign a preliminary service name
            if port in self._common_ports:
                service_name = self._common_ports[port]

            # Try to get the banner regardless, as it provides more info
            banner = await self._get_banner(host, port)

            if banner:
                # Refine service name based on banner, or assign if not common port
                identified_service_from_banner = self._identify_service_from_banner(banner)
                if identified_service_from_banner != "unknown":
                    service_name = identified_service_from_banner
                # else: keep the common port name if it exists, or it stays None if not common and banner is generic

            # If no service name could be identified at all, but a banner was grabbed,
            # consider it 'unknown' if banner implies a service but we can't name it.
            if not service_name and banner:
                service_name = "unknown"
            
            if service_name: # Only return ServiceInfo if we have a name
                return ServiceInfo(
                    name=service_name,
                    banner=banner,
                    protocol="tcp" # Assuming TCP for banner grabbing
                )
            
            return None # No service identified

        except asyncio.TimeoutError:
            logger.debug(f"Service detection on {host}:{port} timed out.")
            return None
        except ConnectionRefusedError:
            logger.debug(f"Connection refused when detecting service on {host}:{port}.")
            return None
        except Exception as e:
            logger.debug(f"Error detecting service on {host}:{port}: {str(e)}")
            return None

    async def _get_banner(self, host: str, port: int) -> Optional[str]:
        """
        Attempts to get the service banner from a TCP port.
        """
        reader: Optional[asyncio.StreamReader] = None
        writer: Optional[asyncio.StreamWriter] = None
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=self.timeout
            )

            # Try to read banner
            try:
                # Read up to 1024 bytes for banner
                banner_bytes = await asyncio.wait_for(
                    reader.read(1024),
                    timeout=self.timeout
                )
                return banner_bytes.decode('utf-8', errors='ignore').strip()
            except UnicodeDecodeError:
                logger.debug(f"Banner from {host}:{port} could not be UTF-8 decoded.")
                return None
            except asyncio.TimeoutError:
                logger.debug(f"Banner read from {host}:{port} timed out.")
                return None
            except Exception as e: # Catch other potential issues during banner read
                logger.debug(f"Error reading banner from {host}:{port}: {e}")
                return None
        except asyncio.TimeoutError:
            logger.debug(f"Connection to {host}:{port} for banner timed out.")
            return None
        except (ConnectionRefusedError, OSError) as e:
            logger.debug(f"Connection error to {host}:{port} for banner: {e}")
            return None
        except Exception as e:
            logger.debug(f"Could not get banner from {host}:{port} (General Error): {e}")
            return None
        finally:
            if writer:
                writer.close()
                await writer.wait_closed()

    def _identify_service_from_banner(self, banner: str) -> str:
        """
        Identifies service from banner text using a set of common signatures.
        """
        banner_lower = banner.lower() # Work with lowercase banner for case-insensitive matching

        # Common service signatures
        signatures = {
            "ssh": ["ssh", "openssh"],
            "http": ["http", "apache", "nginx", "iis", "microsoft-httpapi"],
            "ftp": ["ftp", "vsftpd", "proftpd", "filezilla"],
            "smtp": ["smtp", "postfix", "sendmail", "exim", "microsoft esmtp"],
            "pop3": ["pop3", "dovecot", "qpopper"],
            "imap": ["imap", "dovecot", "courier-imap"],
            "mysql": ["mysql", "mariadb"],
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
            "apache": ["apache", "httpd"],
            "rdp": ["remote desktop", "rdp", "microsoft-rdp"],
            "telnet": ["telnet", "linux telnet", "microsoft telnet"],
            "dns": ["dns", "bind", "named"], # Less common for TCP banner
            "smb": ["samba", "microsoft windows netbios", "rpc over http"] # Often on 445
        }

        for service, patterns in signatures.items():
            if any(pattern in banner_lower for pattern in patterns):
                return service

        # Additional checks for generic or hard-to-classify banners
        if "server" in banner_lower and "200 ok" in banner_lower:
            return "http" # Generic HTTP response

        if banner_lower.startswith("220 "): # Standard FTP greeting
            return "ftp"
        if banner_lower.startswith("220-") and "microsoft" in banner_lower:
            return "microsoft ftp"
        if banner_lower.startswith("220-") and "proftpd" in banner_lower:
            return "proftpd"

        if "connect to" in banner_lower and "port" in banner_lower:
            return "network device" # Generic network device response

        # If nothing specific, return "unknown"
        return "unknown"

# Removed the synchronous detect_service wrapper as it's inefficient
# and the Scanner class will call ServiceDetector.detect_service directly via await.