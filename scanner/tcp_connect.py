# scanner/tcp_connect.py
import asyncio
import socket

async def tcp_connect_scan(target_ip, port, timeout=1.0, rate_limiter=None):
    if rate_limiter:
        await rate_limiter.acquire()

    try:
        conn = asyncio.open_connection(target_ip, port)
        reader, writer = await asyncio.wait_for(conn, timeout=timeout)
        writer.close()
        await writer.wait_closed()
        return "open"
    except asyncio.TimeoutError:
        return "filtered"
    except Exception:
        return "closed"
