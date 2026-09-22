"""Token-bucket rate limiter to prevent IP bans."""
import time
import threading


class RateLimiter:
    """Thread-safe rate limiter using a sliding window."""

    def __init__(self, max_requests: int = 10, time_window: float = 60.0):
        self.max_requests = max_requests
        self.time_window = time_window
        self._timestamps: list = []
        self._lock = threading.Lock()

    def wait_if_needed(self) -> None:
        """Block until a request slot is available."""
        while True:
            with self._lock:
                now = time.time()
                # Drop timestamps outside the window
                self._timestamps = [t for t in self._timestamps if now - t < self.time_window]
                if len(self._timestamps) < self.max_requests:
                    self._timestamps.append(now)
                    return
                # Calculate how long to sleep
                wait = self.time_window - (now - self._timestamps[0])
            time.sleep(max(wait, 0.5))
