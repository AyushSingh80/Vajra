# scanner/cli.py
import argparse
import asyncio
import logging

# Corrected imports for internal modules
from .scanner import Scanner # Import the main Scanner class
from .output_formatter import save_json, save_csv
from .utils import parse_ports, parse_targets, validate_ip, validate_port # Added validate_ip, validate_port for CLI validation

# Configure logging for CLI feedback
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

async def run_scan(args):
    """
    Main async scanning workflow.
    """
    targets = parse_targets(args.targets, args.input_file)
    if not targets:
        logger.error("No valid targets specified. Exiting.")
        return

    ports = parse_ports(args.ports, args.top_ports)
    if not ports:
        logger.error("No valid ports specified for scanning. Exiting.")
        return

    # Initialize the Scanner class with all relevant arguments
    # Note: Service detection and OS detection are now handled by the Scanner class itself
    # and passed via its constructor.
    scanner = Scanner(
        target="dummy", # This will be set per target in the loop below
        ports=ports,
        scan_type=args.scan_type,
        timeout=args.timeout,
        retries=args.retries,
        rate_limit=args.rate,
        concurrency=args.max_concurrency,
        service_detection=args.service_version,
        os_detection=args.os_detection, # Pass this even if not fully implemented yet
        verbose=args.verbose
    )

    all_results = []
    
    # Start rate limiter if enabled (it's managed internally by Scanner, but starting it explicitly here if not part of Scanner)
    # The Scanner class's run() method now handles rate_limiter start/stop.

    print(f"\n[*] Starting scan on {len(targets)} target(s) for {len(ports)} port(s) with {args.scan_type.upper()} scan...\n")

    for target_ip in targets:
        # Update the scanner's target for the current IP
        scanner.target = target_ip
        
        # Run the scan for the current target
        # The scanner.run() method returns a list of ScanResult objects
        try:
            results_for_target = await scanner.run()
            all_results.extend(results_for_target)

            # Console Output: Print each scanned port result
            for entry in results_for_target:
                line = f"[+] {entry.host}:{entry.port} -> {entry.status}"
                if entry.service:
                    line += f" | Service: {entry.service}"
                if entry.banner: # If banner is collected, print it
                    line += f" | Banner: {entry.banner[:50]}..." if len(entry.banner) > 50 else f" | Banner: {entry.banner}"
                if entry.os_info: # If OS info is collected, print it
                    line += f" | OS: {entry.os_info.get('name', 'Unknown')}"
                print(line)
        except Exception as e:
            logger.error(f"Failed to scan target {target_ip}: {e}")

    # Save results to files if specified
    if args.output_json:
        # Convert ScanResult objects to dictionaries for JSON serialization
        json_output = [res.__dict__ for res in all_results]
        save_json(json_output, args.output_json)
        logger.info(f"Results saved to {args.output_json}")
    if args.output_csv:
        # CSV formatter expects a list of dictionaries as before
        csv_output = [res.__dict__ for res in all_results]
        save_csv(csv_output, args.output_csv)
        logger.info(f"Results saved to {args.output_csv}")

    print("\n[*] Scan completed.")

def main():
    parser = argparse.ArgumentParser(
        description="A fast and flexible asynchronous port scanner.",
        formatter_class=argparse.RawTextHelpFormatter
    )

    # Target Specification
    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument(
        'targets', nargs='*', help='Target IP(s), hostname(s), CIDR (e.g., 192.168.1.0/24), or IP range (e.g., 192.168.1.1-10).'
    )
    target_group.add_argument(
        '-iL', '--input-file', metavar='FILE', help='Input file with targets, one per line.'
    )

    # Port Specification
    port_group = parser.add_mutually_exclusive_group()
    port_group.add_argument(
        '-p', '--ports', metavar='PORTS',
        help='Ports to scan (e.g., "22,80,443" or "1-1024").\nDefaults to top 1000 ports if not specified.'
    )
    port_group.add_argument(
        '--top-ports', type=int, choices=[10, 100, 1000],
        help='Scan top N common ports (10, 100, or 1000).\nOverrides -p if specified.'
    )

    # Scan Type
    parser.add_argument(
        '-sT', dest='scan_type', action='store_const', const='tcp', default='syn',
        help='TCP Connect scan (default if no other scan type specified is SYN).'
    )
    parser.add_argument(
        '-sS', dest='scan_type', action='store_const', const='syn',
        help='TCP SYN scan (default).'
    )
    parser.add_argument(
        '-sU', dest='scan_type', action='store_const', const='udp',
        help='UDP scan.'
    )
    parser.add_argument(
        '-sF', dest='scan_type', action='store_const', const='fin',
        help='FIN scan.'
    )
    parser.add_argument(
        '-sN', dest='scan_type', action='store_const', const='null',
        help='NULL scan.'
    )
    parser.add_argument(
        '-sX', dest='scan_type', action='store_const', const='xmas',
        help='XMAS scan.'
    )
    parser.add_argument(
        '-sA', dest='scan_type', action='store_const', const='ack',
        help='ACK scan.'
    )

    # Performance and Reliability
    parser.add_argument(
        '-t', '--timeout', type=float, default=2.0,
        help='Timeout for each port scan in seconds (default: 2.0).'
    )
    parser.add_argument(
        '-r', '--retries', type=int, default=1,
        help='Number of retries for each port scan (default: 1).'
    )
    parser.add_argument(
        '--rate', type=float, default=0,
        help='Maximum packets per second (0 for unlimited, default: 0).'
    )
    parser.add_argument(
        '-c', '--max-concurrency', type=int, default=100,
        help='Maximum concurrent connections/tasks (default: 100).'
    )

    # Service Detection
    parser.add_argument(
        '-sV', '--service-version', action='store_true',
        help='Attempt to detect service and version on open ports.'
    )
    
    # OS Detection (Placeholder for future functionality)
    parser.add_argument(
        '-O', '--os-detection', action='store_true',
        help='Attempt to detect OS (Not yet implemented).'
    )

    # Output Options
    parser.add_argument(
        '-oJ', '--output-json', metavar='FILE',
        help='Output scan results to a JSON file.'
    )
    parser.add_argument(
        '-oC', '--output-csv', metavar='FILE',
        help='Output scan results to a CSV file.'
    )
    parser.add_argument(
        '-v', '--verbose', action='store_true',
        help='Enable verbose output for more details during scanning.'
    )
    parser.add_argument(
        '--debug', action='store_true',
        help='Enable debug logging (much more verbose).'
    )


    args = parser.parse_args()

    # Set logging level based on arguments
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
    elif args.verbose:
        logging.getLogger().setLevel(logging.INFO)
    else:
        logging.getLogger().setLevel(logging.WARNING) # Default to WARNING for less output

    # Run the async scanning routine
    try:
        asyncio.run(run_scan(args))
    except KeyboardInterrupt:
        logger.warning("\nScan interrupted by user.")
    except Exception as e:
        logger.critical(f"An unhandled error occurred: {e}")

if __name__ == "__main__":
    main()