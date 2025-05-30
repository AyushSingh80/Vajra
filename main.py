#!/usr/bin/env python3
import typer
from scanner.cli import app as cli_app
from api.server import start_api_server

app = typer.Typer()

@app.command()
def cli():
    """Run the network scanner in CLI mode"""
    cli_app()

@app.command()
def api(
    host: str = "127.0.0.1",
    port: int = 8000,
    debug: bool = False
):
    """Run the network scanner in API mode"""
    start_api_server(host, port, debug)

if __name__ == "__main__":
    app()
