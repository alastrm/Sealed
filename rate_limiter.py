"""
Rate limiting module using slowapi.
Enforces per-client IP request limits to mitigate brute-force and spam attacks.
Note: Client IP is strictly used as an in-memory key; it is never persisted or logged.
"""

from fastapi import Request
from slowapi import Limiter


def get_real_client_ip(request: Request) -> str:
    """
    Extracts client IP for in-memory rate limiting keys.
    Use the ASGI peer. Caller-supplied proxy headers are not a trusted identity.
    """
    if request.client:
        return request.client.host
    return "127.0.0.1"


# Global slowapi Limiter instance
limiter = Limiter(key_func=get_real_client_ip)

# Defined rate limits per user requirements:
# - Case creation: maximum 5 requests per minute
# - Case lookup by hash: maximum 15 requests per minute
LIMIT_CREATE_CASE = "5/minute"
LIMIT_LOOKUP_CASE = "15/minute"
LIMIT_AUTH = "15/minute"
