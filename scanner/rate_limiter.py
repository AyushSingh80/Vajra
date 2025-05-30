#scanner/rate_limiter.py
import asyncio
import time
from typing import Optional
import logging

logger = logging.getLogger(__name__)

class RateLimiter:
    def __init__(self, rate: float):
        """
        Initialize rate limiter
        
        Args:
            rate: Maximum number of operations per second
        """
        self.rate = rate
        self.interval = 1.0 / rate if rate > 0 else 0
        self.last_check = 0.0
        self.tokens = 0
        self.max_tokens = rate
        self._lock = asyncio.Lock()
        self._running = False
        self._task: Optional[asyncio.Task] = None
        self._stats = {
            'total_requests': 0,
            'throttled_requests': 0,
            'start_time': 0,
            'end_time': 0
        }

    async def start(self):
        """Start the rate limiter"""
        if self._running:
            return
        
        self._running = True
        self._stats['start_time'] = time.time()
        self._task = asyncio.create_task(self._token_generator())
        logger.debug(f"Rate limiter started with rate {self.rate} ops/sec")

    async def stop(self):
        """Stop the rate limiter"""
        if not self._running:
            return
        
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        self._stats['end_time'] = time.time()
        logger.debug("Rate limiter stopped")

    async def _token_generator(self):
        """Generate tokens at the specified rate"""
        while self._running:
            async with self._lock:
                if self.tokens < self.max_tokens:
                    self.tokens += 1
            await asyncio.sleep(self.interval)

    async def acquire(self):
        """
        Acquire a token for an operation
        
        Returns:
            float: Time waited for the token
        """
        if self.rate <= 0:
            return 0

        start_time = time.time()
        self._stats['total_requests'] += 1

        while True:
            async with self._lock:
                if self.tokens > 0:
                    self.tokens -= 1
                    return time.time() - start_time

            self._stats['throttled_requests'] += 1
            await asyncio.sleep(0.01)  # Small delay to prevent CPU spinning

    def get_stats(self) -> dict:
        """Get current statistics about the rate limiter"""
        duration = self._stats['end_time'] - self._stats['start_time'] if self._stats['end_time'] > 0 else 0
        return {
            'rate': self.rate,
            'total_requests': self._stats['total_requests'],
            'throttled_requests': self._stats['throttled_requests'],
            'throttle_percentage': (self._stats['throttled_requests'] / self._stats['total_requests'] * 100) 
                if self._stats['total_requests'] > 0 else 0,
            'duration': duration,
            'average_rate': self._stats['total_requests'] / duration if duration > 0 else 0
        }

    def __enter__(self):
        """Context manager entry"""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        asyncio.create_task(self.stop())
