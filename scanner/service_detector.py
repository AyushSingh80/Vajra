# scanner/service_detector.py
import socket

def detect_service(host, port):
    try:
        with socket.create_connection((host, port), timeout=2) as s:
            s.sendall(b'HEAD / HTTP/1.0\r\n\r\n')
            banner = s.recv(1024).decode(errors='ignore')
            return banner.strip()
    except:
        return None
