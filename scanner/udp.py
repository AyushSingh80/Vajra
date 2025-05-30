# scanner/udp.py
import socket
import asyncio

async def udp_scan(target_ip, port, timeout=1.0):
    def scan():
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            sock.sendto(b'', (target_ip, port))
            sock.recvfrom(1024)
            return "open"
        except socket.timeout:
            return "open|filtered"
        except ConnectionRefusedError:
            return "closed"
        except Exception:
            return "closed"
        finally:
            sock.close()
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, scan)
