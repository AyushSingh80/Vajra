#!/usr/bin/env python3
import typer
import sys
import logging

# Configure basic logging for the main script
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

# Corrected import: Import the 'main' function from scanner.cli
# We alias it to 'scanner_cli_main' to avoid name collision with the main.py's own 'main' function
try:
    from scanner.cli import main as scanner_cli_main
except ImportError as e:
    logger.error(f"Failed to load scanner.cli module: {e}")
    # Exit if the core CLI module cannot be loaded
    sys.exit(1)

# Initialize the Typer application
app = typer.Typer()

@app.command()
def cli():
    """Run the network scanner in CLI mode"""
    logger.info("Starting CLI mode...")
    # Call the main function from scanner.cli
    # argparse in scanner.cli.main() will automatically parse sys.argv
    scanner_cli_main()

@app.command()
def api(
    host: str = "127.0.0.1",
    port: int = 8000,
    debug: bool = False
):
    """Run the network scanner in API mode"""
    logger.info(f"Starting API server on {host}:{port} (Debug: {debug})...")
    # Assuming api.server.start_api_server exists and works
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
    # This will run the Typer application, which then dispatches to cli() or api()
    app()