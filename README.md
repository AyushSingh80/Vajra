# Vajra Network Scanner

A powerful and flexible network scanning tool that supports both CLI and API interfaces.

## Features

- Multiple scanning techniques (TCP SYN, TCP Connect, UDP)
- Service detection
- Rate limiting
- Stealth scanning capabilities
- REST API interface
- Rich CLI interface

## Installation

### Using pip

```bash
pip install -r requirements.txt
```

### Using Docker

```bash
docker build -t vajra .
docker run -p 8000:8000 vajra
```

## Usage

### CLI Mode

```bash
# Basic scan
python main.py cli --target 192.168.1.1

# Scan specific ports
python main.py cli --target 192.168.1.1 --ports 80,443,8080

# Use different scan type
python main.py cli --target 192.168.1.1 --scan-type tcp_connect
```

### API Mode

```bash
# Start the API server
python main.py api

# Default configuration:
# - Host: 127.0.0.1
# - Port: 8000
```

#### API Endpoints

POST `/api/scan`
```json
{
    "target": "192.168.1.1",
    "ports": "80,443,8080",
    "scan_type": "tcp_syn",
    "timeout": 2
}
```

## Development

1. Clone the repository
2. Install dependencies: `pip install -r requirements.txt`
3. Run tests: `python -m pytest tests/`

## License

MIT License 