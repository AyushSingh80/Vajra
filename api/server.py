# api/server.py
from flask import Flask, request, jsonify
import asyncio # Required to run asynchronous scanner methods
import logging
import socket # To catch socket.gaierror during target resolution
from typing import Dict, List, Optional, Any

# Corrected imports: Use resolve_target to process various target inputs,
# and parse_ports for port string handling.
from scanner.scanner import Scanner
from scanner.utils import resolve_target, parse_ports

app = Flask(__name__)
# Configure logging for the Flask app.
# Ensure consistent logging format across your project.
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Helper function to run asynchronous code within a synchronous Flask route.
# This is a common pattern for integrating async libraries into sync Flask.
# Be aware: In a highly concurrent production environment with a synchronous WSGI server,
# this can block the event loop. For heavy loads, consider an ASGI framework (like Quart/FastAPI)
# or a task queue (like Celery).
def run_async_in_sync(coro):
    """Runs an asynchronous coroutine in a synchronous context."""
    return asyncio.run(coro)

@app.route("/api/scan", methods=["POST"])
def scan():
    """
    Handles POST requests to /api/scan.
    Expects a JSON body with 'target' and optional scan parameters.
    """
    try:
        data: Dict[str, Any] = request.get_json()
        if not data:
            return jsonify({"error": "Request must be JSON and not empty."}), 400

        target_input = data.get("target")
        if not target_input:
            return jsonify({"error": "The 'target' parameter is required in the request body."}), 400

        # --- Target Resolution ---
        # Use resolve_target from scanner.utils to handle various target inputs
        # (single IP, hostname, CIDR, IP range) and get a list of actual IPs to scan.
        try:
            targets_to_scan: List[str] = resolve_target(str(target_input))
        except (ValueError, socket.gaierror) as e:
            logger.warning(f"Invalid or unresolvable target received: '{target_input}' - {e}")
            return jsonify({"error": f"Invalid or unresolvable target format: {e}"}), 400
        except Exception as e:
            logger.error(f"Unexpected error during target resolution for '{target_input}': {e}", exc_info=True)
            return jsonify({"error": "An unexpected error occurred while processing the target."}), 500

        if not targets_to_scan:
            return jsonify({"error": "No valid IP addresses could be resolved from the provided target."}), 400

        # --- Port Parsing ---
        # Use parse_ports from scanner.utils to handle port ranges/lists or top N ports.
        ports_input = data.get("ports")
        top_ports_input = data.get("top_ports")
        try:
            # parse_ports expects int for top_ports, so ensure conversion if present
            parsed_top_ports = int(top_ports_input) if top_ports_input is not None else None
            ports = parse_ports(ports_input, parsed_top_ports)
        except ValueError as e:
            logger.warning(f"Invalid port specification received: '{ports_input}' or '{top_ports_input}' - {e}")
            return jsonify({"error": f"Invalid port specification: {e}"}), 400
        except Exception as e:
            logger.error(f"Unexpected error during port parsing: {e}", exc_info=True)
            return jsonify({"error": "An unexpected error occurred while parsing ports."}), 500

        if not ports:
            return jsonify({"error": "No valid ports specified or parsed for scanning."}), 400

        # --- Other Scan Parameters ---
        # Get optional parameters from the request body with sensible defaults.
        # These parameter names should align with those expected by your Scanner class constructor.
        scan_type = data.get("scan_type", "syn") # Default to SYN scan
        timeout = data.get("timeout", 2.0)
        retries = data.get("retries", 1)
        rate_limit = data.get("rate", 0.0) # 0 for unlimited, note the parameter name 'rate'
        concurrency = data.get("max_concurrency", 100) # Note the parameter name 'max_concurrency'
        service_detection = data.get("service_version", False) # Note the parameter name 'service_version'
        os_detection = data.get("os_detection", False)
        verbose = data.get("verbose", False)

        all_scan_results: List[Dict[str, Any]] = []

        logger.info(f"API Scan Request: Target '{target_input}' resolved to {len(targets_to_scan)} IP(s).")
        logger.debug(f"Scan parameters: Type={scan_type}, Ports={len(ports)}, Timeout={timeout}, Concurrency={concurrency}")

        # --- Perform Scan for Each Resolved IP ---
        for current_target_ip in targets_to_scan:
            logger.info(f"Scanning target: {current_target_ip} on {len(ports)} port(s) using {scan_type.upper()} scan.")
            
            # Create a new Scanner instance for each individual IP address.
            scanner = Scanner(
                target=current_target_ip,
                ports=ports,
                scan_type=scan_type,
                timeout=timeout,
                retries=retries,
                rate_limit=rate_limit,
                concurrency=concurrency,
                service_detection=service_detection,
                os_detection=os_detection,
                verbose=verbose
            )
            
            # Execute the asynchronous scanner.run() within the synchronous Flask context.
            raw_results = run_async_in_sync(scanner.run())
            
            # Convert ScanResult objects to dictionaries for JSON serialization.
            # `__dict__` is a convenient way to get a dict representation of a dataclass instance.
            results_for_ip = [res.__dict__ for res in raw_results]
            all_scan_results.extend(results_for_ip)
            logger.info(f"Completed scan for {current_target_ip}. Found {len([r for r in raw_results if r.status == 'open'])} open ports.")

        return jsonify({
            "status": "success",
            "requested_target_input": target_input,
            "scanned_ips": targets_to_scan, # Show all IPs that were actually scanned
            "total_results": len(all_scan_results),
            "results": all_scan_results
        }), 200

    except Exception as e:
        # Catch any unexpected errors during the entire process.
        logger.critical(f"Unhandled API Scan endpoint error: {e}", exc_info=True)
        return jsonify({"error": f"An unhandled internal server error occurred: {str(e)}"}), 500

def start_api_server(host: str = "127.0.0.1", port: int = 8000, debug: bool = False):
    """Starts the Flask API server."""
    logger.info(f"Starting Flask API server on http://{host}:{port} (Debug mode: {debug})...")
    # In a production deployment, use a production-ready WSGI server like Gunicorn or uWSGI.
    app.run(host=host, port=port, debug=debug)