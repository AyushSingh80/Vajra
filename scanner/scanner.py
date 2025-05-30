# scanner/scanner.py
from typing import List, Dict, Optional, Union, Tuple
import asyncio
from dataclasses import dataclass, asdict
import logging
import platform

# Import all specific scan types
from .tcp_connect import tcp_connect_scan
from .tcp_syn import syn_scan
from .udp import udp_scan
from .stealth import fin_scan, null_scan, xmas_scan, ack_scan
from .rate_limiter import RateLimiter
from .utils import parse_ports, validate_ip, validate_target, validate_port
from .service_detection import detect_service, ServiceInfo

logger = logging.getLogger(__name__)

@dataclass
class ScanResult:
    """Class to store scan results"""
    target: str
    port: int
    status: str
    service: Optional[str] = None
    version: Optional[str] = None
    banner: Optional[str] = None
    os: Optional[str] = None
    protocol: str = "tcp"
    latency: Optional[float] = None
    error_message: Optional[str] = None

class Scanner:
    def __init__(
        self,
        target: str,
        ports: Union[str, List[int]] = "1-1024",
        scan_type: str = "tcp",
        timeout: float = 2.0,
        retries: int = 2,
        rate_limit: int = 0,  # Default to unlimited rate
        concurrency: int = 10,
        service_detection: bool = True,
        os_detection: bool = False,
        verbose: bool = False
    ):
        self.target = target
        self.ports = parse_ports(ports) if isinstance(ports, str) else ports
        self.scan_type = scan_type.lower()
        self.timeout = timeout
        self.retries = retries
        self.rate_limit = rate_limit
        self.concurrency = concurrency
        self.service_detection = service_detection
        self.os_detection = os_detection
        self.verbose = verbose

        # Use TCP connect scan as default on Windows
        if platform.system() == "Windows" and scan_type in ["tcp", "syn"]:
            self.scan_type = "tcp_connect"
        
        # Only create rate limiter if rate limit is positive
        self.rate_limiter = RateLimiter(self.rate_limit) if self.rate_limit > 0 else None
        
        self._validate_inputs()
        
        if self.verbose:
            logger.setLevel(logging.INFO)

    def _validate_inputs(self):
        """Validate scanner inputs"""
        if not validate_target(self.target):
            raise ValueError(f"Invalid target: {self.target}")
            
        if not self.ports:
            raise ValueError("No valid ports specified for scanning.")
            
        valid_scan_types = ["tcp", "syn", "tcp_connect", "udp", "stealth"]
        if self.scan_type not in valid_scan_types:
            raise ValueError(f"Invalid scan type: {self.scan_type}. Must be one of: {', '.join(valid_scan_types)}")
            
        if self.timeout <= 0:
            raise ValueError("Timeout must be positive")
            
        if self.retries < 0:
            raise ValueError("Retries cannot be negative")
            
        if self.rate_limit < 0:  # Allow zero for unlimited rate
            raise ValueError("Rate limit cannot be negative")
            
        if self.concurrency <= 0:
            raise ValueError("Concurrency must be positive")

    async def _scan_port(self, port: int) -> ScanResult:
        """Scan a single port with retries"""
        start_time = asyncio.get_event_loop().time()
        status = "unknown"
        error_msg = None
        service_info = None

        for attempt in range(self.retries + 1):
            try:
                # Get scan function based on scan type
                if self.scan_type in ["tcp", "syn"]:
                    status = await syn_scan(self.target, port, self.timeout, self.rate_limiter)
                elif self.scan_type == "tcp_connect":
                    status = await tcp_connect_scan(self.target, port, self.timeout, self.rate_limiter)
                elif self.scan_type == "udp":
                    status = await udp_scan(self.target, port, self.timeout, self.rate_limiter)
                else:  # stealth
                    status = await stealth_scan(self.target, port, self.timeout, self.rate_limiter)
                    
                if status != "error":
                    break
                    
            except Exception as e:
                logger.error(f"Error scanning {self.target}:{port}: {str(e)}")
                if attempt == self.retries:
                    status = "error"
                    error_msg = str(e)
                    
        # Service detection for open ports
        if status == "open" and self.service_detection:
            try:
                service_info = await detect_service(self.target, port, self.timeout)
            except Exception as e:
                logger.error(f"Error detecting service on {self.target}:{port}: {str(e)}")
                
        latency = asyncio.get_event_loop().time() - start_time
        
        return ScanResult(
            target=self.target,
            port=port,
            status=status,
            service=service_info.name if service_info else None,
            version=service_info.version if service_info else None,
            banner=service_info.banner if service_info else None,
            os=service_info.os if service_info else None,
            protocol="tcp" if self.scan_type != "udp" else "udp",
            latency=latency,
            error_message=error_msg
        )

    async def scan(self) -> List[ScanResult]:
        """Run the scan with concurrency control"""
        try:
            tasks = []
            semaphore = asyncio.Semaphore(self.concurrency)
            
            async def scan_with_semaphore(port: int) -> ScanResult:
                async with semaphore:
                    return await self._scan_port(port)
                    
            for port in self.ports:
                tasks.append(asyncio.create_task(scan_with_semaphore(port)))
                
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Filter out any exceptions and ensure we have valid results
            valid_results = []
            for result in results:
                if isinstance(result, Exception):
                    logger.error(f"Error during scan: {str(result)}")
                    continue
                if result is not None:
                    valid_results.append(result)
            
            return valid_results
            
        except Exception as e:
            logger.error(f"Error during scan: {str(e)}")
            return []