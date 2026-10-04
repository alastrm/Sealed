"""
In-memory sliding window rate limiter for FastAPI.
Provides per-IP request throttling to prevent brute-force attacks and abuse.
"""

import time
from collections import defaultdict, deque
from fastapi import HTTPException, Request, status


class SlidingWindowRateLimiter:
    """
    Sliding window rate limiter tracking request timestamps per client IP.
    """

    def __init__(self, times: int, seconds: int):
        self.times = times
        self.seconds = seconds
        self._requests: dict[str, deque[float]] = defaultdict(deque)

    def _get_client_ip(self, request: Request) -> str:
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            return forwarded.split(",")[0].strip()
        real_ip = request.headers.get("X-Real-IP")
        if real_ip:
            return real_ip.strip()
        if request.client:
            return request.client.host
        return "127.0.0.1"

    async def __call__(self, request: Request) -> None:
        client_ip = self._get_client_ip(request)
        now = time.time()
        window_start = now - self.seconds

        queue = self._requests[client_ip]

        # Purge timestamps outside the active sliding window
        while queue and queue[0] < window_start:
            queue.popleft()

        if len(queue) >= self.times:
            oldest = queue[0]
            retry_after = max(1, int(oldest + self.seconds - now))
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Rate limit exceeded: maximum {self.times} requests per {self.seconds}s.",
                headers={"Retry-After": str(retry_after)},
            )

        queue.append(now)


# Standard rate limiters for critical application routes
report_submission_limiter = SlidingWindowRateLimiter(times=15, seconds=60)
case_lookup_limiter = SlidingWindowRateLimiter(times=45, seconds=60)
auth_limiter = SlidingWindowRateLimiter(times=30, seconds=60)
