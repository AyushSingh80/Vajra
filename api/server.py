from flask import Flask, request, jsonify
from scanner.scanner import Scanner
from scanner.utils import validate_target
from typing import Dict, List, Optional
import logging

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@app.route("/api/scan", methods=["POST"])
def scan():
    try:
        data = request.get_json()
        if not data or "target" not in data:
            return jsonify({"error": "Target is required"}), 400

        target = data["target"]
        if not validate_target(target):
            return jsonify({"error": "Invalid target format"}), 400

        ports = data.get("ports", "1-1024")
        scan_type = data.get("scan_type", "tcp_syn")
        timeout = data.get("timeout", 2)

        scanner = Scanner(target, ports, scan_type, timeout)
        results = scanner.run()
        
        return jsonify({
            "status": "success",
            "target": target,
            "results": results
        })

    except Exception as e:
        logger.error(f"Scan error: {str(e)}")
        return jsonify({"error": str(e)}), 500

def start_api_server(host: str = "127.0.0.1", port: int = 8000, debug: bool = False):
    """Start the API server"""
    app.run(host=host, port=port, debug=debug)
