from typing import List, Dict, Optional, Union, Tuple
import asyncio
from dataclasses import dataclass
from .tcp_connect import tcp_connect_scan
from .tcp_syn import syn_scan
from .udp import udp_scan
from .stealth import fin_scan, null_scan, xmas_scan, ack_scan
from .rate_limiter import RateLimiter
from .utils import validate_target, parse_ports
import logging

logger = logging.getLogger(__name__)

@dataclass
class ScanResult:
    host: str
    port: int
    status: str
    service: Optional[str] = None
    protocol: str = "tcp"
    latency: Optional[float] = None
    banner: Optional[str] = None
    os_info: Optional[Dict] = None

class Scanner:
    def __init__(
        self,
        target: str,
        ports: Union[str, List[int]] = "1-1024",
        scan_type: str = "tcp_syn",
        timeout: float = 2.0,
        retries: int = 1,
        rate_limit: float = 0,
        concurrency: int = 100,
        service_detection: bool = False,
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
        self.rate_limiter = RateLimiter(rate_limit) if rate_limit > 0 else None
        self._validate_inputs()

    def _validate_inputs(self):
        """Validate scanner inputs"""
        if not validate_target(self.target):
            raise ValueError(f"Invalid target format: {self.target}")
        
        if not self.ports:
            raise ValueError("No valid ports specified")
        
        valid_scan_types = ["tcp", "syn", "udp", "fin", "null", "xmas", "ack"]
        if self.scan_type not in valid_scan_types:
            raise ValueError(f"Invalid scan type. Must be one of: {', '.join(valid_scan_types)}")

    async def _scan_port(self, port: int) -> ScanResult:
        """Scan a single port with retries"""
        for attempt in range(self.retries):
            try:
                if self.rate_limiter:
                    await self.rate_limiter.acquire()

                result = await scan_dispatcher(
                    self.scan_type,
                    self.target,
                    port,
                    self.rate_limiter
                )

                if result is True:
                    service = None
                    if self.service_detection:
                        from .service_detector import detect_service
                        service = detect_service(self.target, port)

                    return ScanResult(
                        host=self.target,
                        port=port,
                        status="open",
                        service=service
                    )
                elif result is False:
                    return ScanResult(
                        host=self.target,
                        port=port,
                        status="closed"
                    )
                else:
                    return ScanResult(
                        host=self.target,
                        port=port,
                        status=str(result)
                    )

            except Exception as e:
                logger.error(f"Error scanning port {port}: {str(e)}")
                if attempt == self.retries - 1:
                    return ScanResult(
                        host=self.target,
                        port=port,
                        status="error",
                        service=str(e)
                    )
                await asyncio.sleep(0.1)  # Brief delay between retries

    async def run(self) -> List[ScanResult]:
        """Run the scan with concurrency control"""
        if self.rate_limiter:
            await self.rate_limiter.start()

        try:
            # Create semaphore for concurrency control
            sem = asyncio.Semaphore(self.concurrency)

            async def scan_with_semaphore(port):
                async with sem:
                    return await self._scan_port(port)

            # Create tasks for all ports
            tasks = [scan_with_semaphore(port) for port in self.ports]
            
            # Run all tasks concurrently
            results = await asyncio.gather(*tasks)
            
            # Filter out None results and sort by port
            valid_results = [r for r in results if r is not None]
            valid_results.sort(key=lambda x: x.port)
            
            return valid_results

        finally:
            if self.rate_limiter:
                await self.rate_limiter.stop()

async def scan_dispatcher(scan_type: str, target_ip: str, port: int, rate_limiter: Optional[RateLimiter] = None) -> Union[bool, str]:
    """Dispatch to appropriate scan function based on scan type"""
    scan_type = scan_type.lower()
    try:
        if scan_type == "tcp":
            return await tcp_connect_scan(target_ip, port, rate_limiter=rate_limiter)
        elif scan_type == "syn":
            return await syn_scan(target_ip, port, rate_limiter=rate_limiter)
        elif scan_type == "udp":
            return await udp_scan(target_ip, port)
        elif scan_type == "fin":
            return await fin_scan(target_ip, port, rate_limiter=rate_limiter)
        elif scan_type == "null":
            return await null_scan(target_ip, port, rate_limiter=rate_limiter)
        elif scan_type == "xmas":
            return await xmas_scan(target_ip, port, rate_limiter=rate_limiter)
        elif scan_type == "ack":
            return await ack_scan(target_ip, port, rate_limiter=rate_limiter)
        else:
            return "Invalid scan type"
    except Exception as e:
        logger.error(f"Error in scan_dispatcher: {str(e)}")
        return f"Error: {str(e)}"
