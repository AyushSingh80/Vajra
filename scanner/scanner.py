# scanner/scanner.py
from typing import List, Dict, Optional, Union, Tuple
import asyncio
from dataclasses import dataclass, asdict
import logging

# Import all specific scan types
from .tcp_connect import tcp_connect_scan
from .tcp_syn import syn_scan
from .udp import udp_scan
from .stealth import fin_scan, null_scan, xmas_scan, ack_scan
from .rate_limiter import RateLimiter
from .utils import parse_ports, validate_ip # Added validate_ip
from .service_detector import ServiceDetector # Import ServiceDetector

logger = logging.getLogger(__name__)

@dataclass
class ScanResult:
    host: str
    port: int
    status: str # "open", "closed", "filtered", "unfiltered", "timeout", "error"
    service: Optional[str] = None
    protocol: str = "tcp" # Default to tcp, can be 'udp'
    latency: Optional[float] = None
    banner: Optional[str] = None
    os_info: Optional[Dict] = None
    error_message: Optional[str] = None # Added for specific error messages

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
        os_detection: bool = False, # Not yet implemented, but passed through
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
        self.os_detection = os_detection # Store the flag
        self.verbose = verbose

        self.rate_limiter: Optional[RateLimiter] = None
        if self.rate_limit > 0:
            self.rate_limiter = RateLimiter(self.rate_limit)

        self.service_detector = ServiceDetector(timeout=self.timeout) # Instantiate once
        
        self._validate_inputs()
        
        if self.verbose:
            logger.setLevel(logging.INFO)
        # Assuming logger is already configured by cli.py for general levels

    def _validate_inputs(self):
        """Validate scanner inputs (only validates target format initially, specific target IP passed later)"""
        # Note: self.target at init might be a placeholder.
        # Actual IP validation for resolved IPs happens in utils.parse_targets.
        # This check is more about the general format if a single target was passed here.
        
        if not self.ports:
            raise ValueError("No valid ports specified for scanning.")

        valid_scan_types = ["tcp", "syn", "udp", "fin", "null", "xmas", "ack"]
        if self.scan_type not in valid_scan_types:
            raise ValueError(f"Invalid scan type '{self.scan_type}'. Must be one of: {', '.join(valid_scan_types)}")

        if self.timeout <= 0:
            raise ValueError("Timeout must be a positive value.")
        if self.retries < 0:
            raise ValueError("Retries cannot be negative.")
        if self.concurrency <= 0:
            raise ValueError("Concurrency must be a positive value.")

    async def _scan_port(self, port: int) -> ScanResult:
        """Scan a single port with retries and service detection."""
        for attempt in range(self.retries):
            start_time = asyncio.get_event_loop().time()
            status: str = "unknown"
            error_msg: Optional[str] = None
            service_name: Optional[str] = None
            banner_text: Optional[str] = None

            try:
                # Acquire token if rate limiting is enabled
                if self.rate_limiter:
                    await self.rate_limiter.acquire()

                # Dispatch to the appropriate scan function
                # All scan functions are expected to return a status string: "open", "closed", "filtered", "unfiltered"
                # Some might return "open|filtered"
                scan_func = self._get_scan_function(self.scan_type)
                
                # Pass timeout to all scan functions (if they accept it)
                if self.scan_type in ["tcp", "syn", "fin", "null", "xmas", "ack", "udp"]:
                    # Pass timeout to all, rate_limiter to TCP/Stealth
                    if self.scan_type == "udp":
                        status = await scan_func(self.target, port, timeout=self.timeout)
                    else:
                        status = await scan_func(self.target, port, timeout=self.timeout, rate_limiter=self.rate_limiter)
                else:
                    status = "error"
                    error_msg = f"Unknown scan type: {self.scan_type}"

                # Handle "open|filtered" status from stealth scans
                if status == "open|filtered":
                    # For a more definitive answer, a SYN/Connect scan might be needed here
                    # For now, we'll just report it as is.
                    pass # Keep the status as "open|filtered"
                
                # Service detection for 'open' ports
                if self.service_detection and status == "open":
                    service_info = await self.service_detector.detect_service(self.target, port)
                    if service_info:
                        service_name = service_info.name
                        banner_text = service_info.banner
                        # Note: ServiceInfo also has 'version' and 'protocol',
                        # you might want to extend ScanResult to include these.

                latency = asyncio.get_event_loop().time() - start_time
                return ScanResult(
                    host=self.target,
                    port=port,
                    status=status,
                    service=service_name,
                    banner=banner_text,
                    protocol="tcp" if self.scan_type != "udp" else "udp",
                    latency=latency,
                    error_message=error_msg
                )

            except asyncio.TimeoutError:
                status = "timeout"
                error_msg = "Operation timed out."
            except ConnectionRefusedError:
                status = "closed" # Specific for TCP connect when immediate refusal
            except Exception as e:
                status = "error"
                error_msg = f"Scan error: {type(e).__name__} - {str(e)}"
                logger.debug(f"Error scanning {self.target}:{port} (Attempt {attempt + 1}/{self.retries}): {error_msg}")

            latency = asyncio.get_event_loop().time() - start_time
            if attempt < self.retries - 1:
                await asyncio.sleep(0.1) # Brief delay before retry

        # If all retries fail
        return ScanResult(
            host=self.target,
            port=port,
            status=status,
            protocol="tcp" if self.scan_type != "udp" else "udp",
            latency=latency,
            error_message=error_msg
        )

    def _get_scan_function(self, scan_type: str):
        """Helper to return the correct async scan function."""
        if scan_type == "tcp":
            return tcp_connect_scan
        elif scan_type == "syn":
            return syn_scan
        elif scan_type == "udp":
            return udp_scan
        elif scan_type == "fin":
            return fin_scan
        elif scan_type == "null":
            return null_scan
        elif scan_type == "xmas":
            return xmas_scan
        elif scan_type == "ack":
            return ack_scan
        else:
            raise ValueError(f"Unsupported scan type: {scan_type}")

    async def run(self) -> List[ScanResult]:
        """
        Runs the port scan for the initialized target and ports.
        Returns a list of ScanResult objects.
        """
        if not validate_ip(self.target):
            logger.error(f"Invalid target IP: {self.target}. Skipping scan.")
            return []

        # Start rate limiter if enabled
        if self.rate_limiter:
            await self.rate_limiter.start()

        try:
            # Create a semaphore for concurrency control
            sem = asyncio.Semaphore(self.concurrency)

            async def scan_with_semaphore(port):
                async with sem:
                    return await self._scan_port(port)

            logger.info(f"Scanning {self.target} with {self.scan_type.upper()} scan on {len(self.ports)} ports using {self.concurrency} concurrent tasks.")
            
            # Create tasks for all ports
            tasks = [scan_with_semaphore(port) for port in self.ports]

            # Run all tasks concurrently
            results = await asyncio.gather(*tasks)

            # Filter out None results (though _scan_port should always return a ScanResult now)
            valid_results = [r for r in results if r is not None]
            valid_results.sort(key=lambda x: x.port)
            
            if self.verbose:
                if self.rate_limiter:
                    stats = self.rate_limiter.get_stats()
                    logger.info(f"Rate Limiter Stats: Total={stats['total_requests']}, Throttled={stats['throttled_requests']},"
                                f" Avg Rate={stats['average_rate']:.2f} req/s, Duration={stats['duration']:.2f}s")

            return valid_results

        except Exception as e:
            logger.critical(f"An error occurred during the overall scan for {self.target}: {e}")
            return []
        finally:
            # Stop rate limiter if it was started
            if self.rate_limiter:
                await self.rate_limiter.stop()

# No global scan_dispatcher function needed here as Scanner._get_scan_function handles dispatching