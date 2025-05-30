# scanner/cli.py
import argparse
import asyncio
import logging
import sys
from typing import List, Optional
from .scanner import Scanner
from .utils import parse_targets, parse_ports

logger = logging.getLogger(__name__)

def parse_args():
    parser = argparse.ArgumentParser(description="Vajra Network Scanner")
    
    # Target specification
    parser.add_argument("targets", nargs="+", help="Target IP addresses, hostnames, or CIDR ranges")
    
    # Port specification
    parser.add_argument("-p", "--ports", default="1-1024",
                      help="Ports to scan (e.g., '80,443,8080' or '1-1024')")
    
    # Scan type
    parser.add_argument("-s", "--scan-type", default="tcp",
                      choices=["tcp", "syn", "tcp_connect", "udp", "stealth"],
                      help="Type of scan to perform")
    
    # Performance settings
    parser.add_argument("-t", "--timeout", type=float, default=2.0,
                      help="Timeout for each scan in seconds")
    parser.add_argument("-r", "--retries", type=int, default=2,
                      help="Number of retries for failed scans")
    parser.add_argument("--rate-limit", type=int, default=0,
                      help="Maximum scans per second (0 for unlimited)")
    parser.add_argument("-c", "--concurrency", type=int, default=10,
                      help="Maximum concurrent scans")
    
    # Additional options
    parser.add_argument("--service-detection", action="store_true",
                      help="Enable service detection")
    parser.add_argument("--os-detection", action="store_true",
                      help="Enable OS detection (not implemented yet)")
    parser.add_argument("-v", "--verbose", action="store_true",
                      help="Enable verbose output")
    
    # Output format
    parser.add_argument("-o", "--output", choices=["text", "json", "xml"],
                      default="text", help="Output format")
    parser.add_argument("-f", "--output-file",
                      help="File to save results (default: stdout)")
    
    return parser.parse_args()

async def run_scan(args):
    """Run the scan with the given arguments"""
    try:
        # Parse targets and ports
        targets = parse_targets(args.targets)
        ports = parse_ports(args.ports)
        
        if not targets:
            logger.error("No valid targets specified")
            return 1
            
        if not ports:
            logger.error("No valid ports specified")
            return 1
            
        # Initialize scanner
        scanner = Scanner(
            target=targets[0],  # For now, scan first target only
            ports=ports,
            scan_type=args.scan_type,
            timeout=args.timeout,
            retries=args.retries,
            rate_limit=args.rate_limit,
            concurrency=args.concurrency,
            service_detection=args.service_detection,
            os_detection=args.os_detection
        )
        
        # Run scan
        results = await scanner.scan()
        
        # Output results
        if args.output_file:
            with open(args.output_file, 'w') as f:
                output_results(results, args.output, f)
        else:
            output_results(results, args.output, sys.stdout)
            
        return 0
        
    except Exception as e:
        logger.error(f"Error during scan: {str(e)}")
        return 1

def output_results(results, format: str, file):
    """Output scan results in the specified format"""
    if format == "text":
        for result in results:
            status = result.status.upper()
            service = f" ({result.service})" if result.service else ""
            version = f" {result.version}" if result.version else ""
            print(f"{result.target}:{result.port} - {status}{service}{version}", file=file)
            
    elif format == "json":
        import json
        json.dump([vars(r) for r in results], file, indent=2)
        
    elif format == "xml":
        import xml.etree.ElementTree as ET
        root = ET.Element("scan_results")
        for result in results:
            port = ET.SubElement(root, "port")
            port.set("target", result.target)
            port.set("number", str(result.port))
            port.set("status", result.status)
            if result.service:
                port.set("service", result.service)
            if result.version:
                port.set("version", result.version)
        ET.ElementTree(root).write(file, encoding="unicode")

def main():
    args = parse_args()
    return asyncio.run(run_scan(args))

if __name__ == "__main__":
    sys.exit(main())