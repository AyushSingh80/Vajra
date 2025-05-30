#!/usr/bin/env python3
import typer
import sys
import logging
from typing import List, Optional
from dataclasses import asdict

# Configure basic logging for the main script
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

# Initialize the Typer application
app = typer.Typer()

@app.command()
def cli(
    targets: List[str] = typer.Argument(..., help="Target IP(s), hostname(s), CIDR, or IP range"),
    ports: str = typer.Option(None, "-p", "--ports", help="Ports to scan (e.g., '22,80,443' or '1-1024')"),
    top_ports: Optional[int] = typer.Option(None, "--top-ports", help="Scan top N common ports (10, 100, or 1000)"),
    scan_type: str = typer.Option("tcp_connect", "-s", "--scan-type", help="Scan type (tcp_connect, syn, udp, stealth)"),
    timeout: float = typer.Option(2.0, "-t", "--timeout", help="Timeout for each port scan in seconds"),
    retries: int = typer.Option(1, "-r", "--retries", help="Number of retries for each port scan"),
    rate: float = typer.Option(0, "--rate", help="Maximum packets per second (0 for unlimited)"),
    max_concurrency: int = typer.Option(100, "-c", "--max-concurrency", help="Maximum concurrent connections"),
    service_version: bool = typer.Option(False, "-sV", "--service-version", help="Detect service and version"),
    os_detection: bool = typer.Option(False, "-O", "--os-detection", help="Attempt OS detection"),
    output_json: Optional[str] = typer.Option(None, "-oJ", "--output-json", help="Output results to JSON file"),
    output_csv: Optional[str] = typer.Option(None, "-oC", "--output-csv", help="Output results to CSV file"),
    verbose: bool = typer.Option(False, "-v", "--verbose", help="Enable verbose output"),
    debug: bool = typer.Option(False, "--debug", help="Enable debug logging"),
    input_file: Optional[str] = typer.Option(None, "-iL", "--input-file", help="Input file with targets")
):
    """Run the network scanner in CLI mode"""
    logger.info("Starting CLI mode...")
    
    try:
        from scanner.scanner import Scanner
        import asyncio
        
        # Create scanner instance
        scanner = Scanner(
            target=targets[0] if targets else None,  # For now, use first target
            ports=ports,
            scan_type=scan_type,
            timeout=timeout,
            retries=retries,
            rate_limit=rate,
            concurrency=max_concurrency,
            service_detection=service_version,
            os_detection=os_detection,
            verbose=verbose
        )
        
        # Run the scan
        results = asyncio.run(scanner.scan())
        
        # Process results
        for result in results:
            line = f"[+] {result.target}:{result.port} -> {result.status}"
            if result.service:
                line += f" | Service: {result.service}"
            if result.version:
                line += f" v{result.version}"
            print(line)
            
        # Save results if requested
        if output_json:
            from scanner.output_formatter import save_json
            save_json([asdict(r) for r in results], output_json)
            logger.info(f"Results saved to {output_json}")
            
        if output_csv:
            from scanner.output_formatter import save_csv
            save_csv([asdict(r) for r in results], output_csv)
            logger.info(f"Results saved to {output_csv}")
            
    except ImportError as e:
        logger.error(f"Failed to load scanner module: {e}")
        sys.exit(1)
    except Exception as e:
        logger.critical(f"An unexpected error occurred: {e}")
        sys.exit(1)

@app.command()
def api(
    host: str = "127.0.0.1",
    port: int = 8000,
    debug: bool = False
):
    """Run the network scanner in API mode"""
    logger.info(f"Starting API server on {host}:{port} (Debug: {debug})...")
    try:
        from api.server import start_api_server
        start_api_server(host, port, debug)
    except ImportError as e:
        logger.error(f"Failed to load API server module: {e}")
        sys.exit(1)
    except Exception as e:
        logger.critical(f"An unexpected error occurred during API server startup: {e}")
        sys.exit(1)

if __name__ == "__main__":
    app()