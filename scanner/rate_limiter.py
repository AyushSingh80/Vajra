#scanner/rate_limiter.py
import asyncio
import time

class AsyncRateLimiter:
    def __init__(self, rate_per_sec: float):
        """
        rate_per_sec: max allowed operations per second. 0 means unlimited.
        """
        self.rate = rate_per_sec
        self.tokens = rate_per_sec
        self.lock = asyncio.Lock()
        self.refill_task = None
        self.last_time = time.monotonic()
        self.running = False

    async def _refill(self):
        while self.running:
            async with self.lock:
                now = time.monotonic()
                elapsed = now - self.last_time
                self.last_time = now
                self.tokens = min(self.rate, self.tokens + elapsed * self.rate)
            await asyncio.sleep(0.01)

    async def start(self):
        if self.rate <= 0:
            return
        self.running = True
        self.refill_task = asyncio.create_task(self._refill())

    async def stop(self):
        if self.rate <= 0:
            return
        self.running = False
        if self.refill_task:
            await self.refill_task

    async def acquire(self):
        if self.rate <= 0:
            return
        while True:
            async with self.lock:
                if self.tokens >= 1:
                    self.tokens -= 1
                    return
            await asyncio.sleep(0.01)
