# scanner/rate_limiter.py
import asyncio
import time
from typing import Optional
import logging

logger = logging.getLogger(__name__)

class RateLimiter:
    """
    A token bucket based rate limiter for asynchronous operations.
    """
    def __init__(self, rate: float):
        """
        Initializes the RateLimiter.

        Args:
            rate: The maximum number of operations per second.
                  If 0 or less, rate limiting is effectively disabled.
        """
        self.rate = rate # operations per second
        self._tokens = 0.0
        self._last_fill_time = time.monotonic()
        self._running = False
        self._task: Optional[asyncio.Task] = None
        self._lock = asyncio.Lock() # For token generation and acquisition
        self._wakeup_event = asyncio.Event() # To wake up sleeping acquirers

        self._stats = {
            'total_requests': 0,
            'throttled_requests': 0,
            'start_time': 0.0,
            'end_time': 0.0
        }

        if self.rate > 0:
            self._tokens = self.rate # Start with full bucket
            self._fill_rate = 1.0 / self.rate # time per operation
        else:
            self._fill_rate = 0.0 # No actual filling needed if unlimited

    async def start(self):
        """Starts the token generation task."""
        if self.rate <= 0:
            logger.debug("Rate limiting is disabled (rate <= 0).")
            return

        if self._running:
            logger.debug("Rate limiter already running.")
            return

        logger.debug(f"Starting rate limiter with rate: {self.rate} req/s")
        self._running = True
        self._stats['start_time'] = time.time()
        self._stats['end_time'] = 0.0 # Reset end time on start
        self._stats['total_requests'] = 0
        self._stats['throttled_requests'] = 0
        self._task = asyncio.create_task(self._token_generator())

    async def stop(self):
        """Stops the token generation task and records end time."""
        if not self._running:
            return

        logger.debug("Stopping rate limiter.")
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        
        # Only set end_time if it hasn't been set by a previous stop call for this run
        if self._stats['end_time'] == 0.0:
            self._stats['end_time'] = time.time()
        logger.debug("Rate limiter stopped.")


    async def _token_generator(self):
        """Generates tokens periodically."""
        try:
            while self._running:
                now = time.monotonic()
                time_elapsed = now - self._last_fill_time
                if time_elapsed > 0:
                    async with self._lock:
                        self._tokens = min(self.rate, self._tokens + time_elapsed * self.rate)
                    self._last_fill_time = now
                
                # If there are tokens, wake up any waiting acquirers
                if self._tokens > 0:
                    self._wakeup_event.set() # Signal that tokens might be available

                # Sleep until the next token generation or if a token is needed
                # Small sleep to yield control, but rely more on event.wait() for efficiency
                await asyncio.sleep(0.01) # Yield control
                await self._wakeup_event.wait() # Wait for acquire to signal need or for next fill
                self._wakeup_event.clear() # Clear event after waking up
        except asyncio.CancelledError:
            logger.debug("Token generator task cancelled.")
        except Exception as e:
            logger.error(f"Error in token generator: {e}")

    async def acquire(self):
        """
        Acquires a token, blocking if no tokens are available.
        Increments total_requests and throttled_requests if blocked.
        """
        if self.rate <= 0: # If rate limiting is disabled, just return
            async with self._lock:
                self._stats['total_requests'] += 1
            return

        async with self._lock:
            self._stats['total_requests'] += 1
            if self._tokens >= 1:
                self._tokens -= 1
                return

            # No tokens, need to wait
            self._stats['throttled_requests'] += 1

        # Wait until tokens are available
        while True:
            self._wakeup_event.set() # Signal token generator that we need a token
            await self._wakeup_event.wait() # Wait for token generator to signal
            self._wakeup_event.clear() # Clear event after waking up

            async with self._lock:
                if self._tokens >= 1:
                    self._tokens -= 1
                    return
            await asyncio.sleep(0.001) # Small sleep to prevent busy-waiting

    def get_stats(self) -> dict:
        """Get current statistics about the rate limiter"""
        if self._stats['start_time'] == 0:
            return {
                'rate': self.rate,
                'total_requests': 0,
                'throttled_requests': 0,
                'throttle_percentage': 0,
                'duration': 0,
                'average_rate': 0
            }

        current_end_time = self._stats['end_time'] if self._stats['end_time'] > 0 else time.time()
        duration = current_end_time - self._stats['start_time']
        
        # Ensure duration is not zero to avoid division by zero
        duration = max(duration, 1e-9) # Smallest non-zero duration

        return {
            'rate': self.rate,
            'total_requests': self._stats['total_requests'],
            'throttled_requests': self._stats['throttled_requests'],
            'throttle_percentage': (self._stats['throttled_requests'] / self._stats['total_requests'] * 100)
                if self._stats['total_requests'] > 0 else 0,
            'duration': duration,
            'average_rate': self._stats['total_requests'] / duration
        }

    async def __aenter__(self):
        """Asynchronous context manager entry."""
        await self.start()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Asynchronous context manager exit."""
        await self.stop()