# scanner/cli.py

import argparse
import asyncio
from scanner import scan_ports
from service_detector import detect_service
from output_formatter import save_json, save_csv
from utils import parse_ports, parse_targets
from scanner.rate_limiter import RateLimiter


def main():
    parser = argparse.ArgumentParser(
        description='⚡ Advanced Network Port Scanner - Modular, Efficient, Ethical'
    )

    # --- Target Specification ---
    parser.add_argument(
        "targets", nargs="*", help="Target IPs, hostnames, ranges (e.g., 192.168.1.1-100), or CIDR (e.g., 192.168.1.0/24)."
    )
    parser.add_argument(
        "-iL", "--input-file", help="Scan targets from file (one target per line)."
    )

    # --- Port Specification ---
    port_group = parser.add_mutually_exclusive_group()
    port_group.add_argument(
        "-p", "--ports", help="Ports to scan, e.g., '22', '80,443', '1-1024'."
    )
    port_group.add_argument(
        "--top-ports", type=int, metavar="N",
        help="Scan top N most common ports."
    )

    # --- Scan Techniques ---
    scan_type_group = parser.add_mutually_exclusive_group()
    scan_type_group.add_argument("-sT", "--tcp-connect", action="store_true",
                                 help="TCP Connect scan (default).")
    scan_type_group.add_argument("-sS", "--tcp-syn", action="store_true",
                                 help="TCP SYN (Stealth) scan (root required).")
    scan_type_group.add_argument("-sU", "--udp-scan", action="store_true",
                                 help="UDP scan (root required for ICMP).")
    scan_type_group.add_argument("-sA", "--ack-scan", action="store_true",
                                 help="TCP ACK scan (NYI - Future).")
    scan_type_group.add_argument("-sF", "--fin-scan", action="store_true",
                                 help="TCP FIN scan (NYI - Future).")
    scan_type_group.add_argument("-sX", "--xmas-scan", action="store_true",
                                 help="TCP Xmas scan (NYI - Future).")
    scan_type_group.add_argument("-sN", "--null-scan", action="store_true",
                                 help="TCP Null scan (NYI - Future).")

    # --- Service & OS Detection ---
    parser.add_argument("-sV", "--service-version", action="store_true",
                        help="Service/version detection.")
    parser.add_argument("-O", "--os-detection", action="store_true",
                        help="OS detection (NYI - Future).")

    # --- Performance & Timing ---
    parser.add_argument("--timeout", type=float, default=1.0,
                        help="Timeout in seconds per probe (default: 1.0).")
    parser.add_argument("--retries", type=int, default=1,
                        help="Retries for failed probes (default: 1).")
    parser.add_argument("--max-concurrency", type=int, default=100,
                        help="Max concurrent scan tasks (default: 100).")
    parser.add_argument("--rate", type=float, default=0,
                        help="Max packets per second (0 = unlimited) [Future Feature].")

    # --- Output Options ---
    output_group = parser.add_argument_group("Output Options")
    output_group.add_argument("-oJ", "--output-json", metavar="FILE",
                              help="Save results to JSON file.")
    output_group.add_argument("-oC", "--output-csv", metavar="FILE",
                              help="Save results to CSV file.")
    output_group.add_argument("-oX", "--output-xml", metavar="FILE",
                              help="Output XML (Nmap-like) [NYI - Future].")
    output_group.add_argument("-oG", "--output-grepable", metavar="FILE",
                              help="Output Grepable format [NYI - Future].")

    # --- Logging and Debugging ---
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Verbose output during scanning.")
    parser.add_argument("--debug", action="store_true",
                        help="Enable debug logging.")

    # Parse CLI Arguments
    args = parser.parse_args()

    # Process Targets from CLI or Input File
    targets = parse_targets(args.targets, args.input_file)
    if not targets:
        print("[!] No valid targets specified. Exiting.")
        return

    # Process Ports from CLI or Top N
    ports = parse_ports(args.ports, args.top_ports)
    if not ports:
        print("[!] No valid ports specified. Exiting.")
        return

    # Determine Scan Type
    if args.tcp_syn:
        scan_type = 'SYN'
    elif args.udp_scan:
        scan_type = 'UDP'
    elif args.ack_scan:
        scan_type = 'ACK'   # NYI
    elif args.fin_scan:
        scan_type = 'FIN'   # NYI
    elif args.xmas_scan:
        scan_type = 'XMAS'  # NYI
    elif args.null_scan:
        scan_type = 'NULL'  # NYI
    else:
        scan_type = 'TCP'  # Default TCP Connect scan

    # Run the async scanning routine
    asyncio.run(run_scan(targets, ports, scan_type, args))


async def run_scan(targets, ports, scan_type, args):
    """
    Main async scanning workflow.
    """

    # Initialize rate limiter if user specified rate limit > 0, else None (unlimited)
    rate_limiter = RateLimiter(args.rate) if args.rate > 0 else None

    if rate_limiter:
        await rate_limiter.start()

    all_results = []

    # Scan each target sequentially (could be parallelized if desired)
    for target in targets:
        results = await scan_ports(
            target=target,
            ports=ports,
            rate_limiter=rate_limiter,
            scan_type=scan_type,
            timeout=args.timeout,
            retries=args.retries,
            concurrency=args.max_concurrency,
            verbose=args.verbose,
            debug=args.debug
        )

        final_results = []
        for port, status in results:
            service = None
            if args.service_version and status is True:
                service = detect_service(target, port)
            final_results.append({
                'host': target,
                'port': port,
                'status': 'open' if status is True else status,
                'service': service or ''
            })

        all_results.extend(final_results)

        # Console Output: Print each scanned port result
        for entry in final_results:
            line = f"[+] {entry['host']}:{entry['port']} -> {entry['status']}"
            if entry['service']:
                line += f" | {entry['service']}"
            print(line)

    if rate_limiter:
        await rate_limiter.stop()

    # Save results to files if specified
    if args.output_json:
        save_json(all_results, args.output_json)
    if args.output_csv:
        save_csv(all_results, args.output_csv)

    # NYI: XML and Grepable output - To be implemented in future releases


if __name__ == "__main__":
    main()
