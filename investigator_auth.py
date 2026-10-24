"""Single-workspace investigator authentication, independent of encryption keys.

The locally provisioned 256-bit access key authenticates HMAC challenges. Only an
opaque, HttpOnly cookie is issued to the browser. Sessions are intentionally
process-local: restart/reload (including access-key rotation) revokes them all.
"""

import hashlib
import hmac
import json
import logging
import os
import secrets
import threading
import time
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Callable
from urllib.parse import urlsplit

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from database import get_db
from models import Investigator

COOKIE_NAME = "sealed_investigator_session"
COOKIE_PATH = "/api/v1"
CHALLENGE_TTL = 60
SESSION_TTL = 3600
MAX_CHALLENGES = 256
MAX_SESSIONS = 128
REQUEST_HEADER = "X-Sealed-Request"


def auth_file_path() -> Path:
    return Path(os.environ.get(
        "SEALED_AUTH_FILE",
        str(Path(__file__).resolve().parent / "storage" / "investigator-auth.json"),
    ))


def allowed_origins() -> list[str]:
    origins = os.environ.get(
        "SEALED_ALLOWED_ORIGINS", "http://localhost:3000,http://127.0.0.1:3000"
    ).split(",")
    normalized = []
    for value in origins:
        origin = value.strip()
        parsed = urlsplit(origin)
        if (parsed.scheme not in ("http", "https") or not parsed.hostname
                or parsed.username or parsed.password or parsed.path
                or parsed.query or parsed.fragment or "*" in origin):
            raise ValueError("SEALED_ALLOWED_ORIGINS must contain explicit HTTP(S) origins")
        normalized.append(origin)
    return normalized


def secure_cookie() -> bool:
    return os.environ.get("SEALED_COOKIE_SECURE", "false").lower() == "true"


def proof_message(challenge_id: str, nonce: str, username: str, origin: str) -> bytes:
    # IDs/nonces are server-generated hex. Username validation excludes newlines.
    return f"sealed:investigator-auth:v1\n{challenge_id}\n{nonce}\n{username}\n{origin}".encode()


@dataclass(frozen=True)
class AuthConfig:
    username: str
    access_key: bytes


class InvestigatorAuth:
    def __init__(self, config: AuthConfig | None, clock: Callable[[], float] = time.monotonic):
        self.config = config
        self.clock = clock
        self._challenges: dict[str, tuple[str, str, str, float]] = {}
        self._sessions: dict[str, float] = {}
        self._lock = threading.Lock()

    def _prune(self) -> None:
        now = self.clock()
        self._challenges = {key: item for key, item in self._challenges.items() if item[3] > now}
        self._sessions = {key: expiry for key, expiry in self._sessions.items() if expiry > now}

    def challenge(self, username: str, origin: str) -> tuple[str, str]:
        if self.config is None:
            raise HTTPException(503, "Investigator access is not configured. Run the local access setup.")
        with self._lock:
            self._prune()
            if len(self._challenges) >= MAX_CHALLENGES:
                raise HTTPException(429, "Too many pending login challenges. Try again shortly.")
            challenge_id, nonce = secrets.token_hex(32), secrets.token_hex(32)
            self._challenges[challenge_id] = (username, nonce, origin, self.clock() + CHALLENGE_TTL)
        return challenge_id, nonce

    def authenticate(self, challenge_id: str, username: str, proof: str, origin: str) -> None:
        with self._lock:
            self._prune()
            challenge = self._challenges.pop(challenge_id, None)
        # Every challenge is consumed, including on an incorrect proof or origin.
        if self.config is None or challenge is None:
            raise HTTPException(401, "Invalid or expired investigator credentials.")
        expected = hmac.new(
            self.config.access_key,
            proof_message(challenge_id, challenge[1], challenge[0], challenge[2]),
            hashlib.sha256,
        ).hexdigest()
        valid_proof = secrets.compare_digest(proof, expected)
        if not (valid_proof and username == challenge[0] == self.config.username and origin == challenge[2]):
            raise HTTPException(401, "Invalid or expired investigator credentials.")

    def create_session(self, old_token: str | None = None) -> str:
        token = secrets.token_urlsafe(32)
        with self._lock:
            self._prune()
            if old_token:
                self._sessions.pop(self._digest(old_token), None)
            if len(self._sessions) >= MAX_SESSIONS:
                raise HTTPException(429, "Too many active investigator sessions.")
            self._sessions[self._digest(token)] = self.clock() + SESSION_TTL
        return token

    @staticmethod
    def _digest(token: str) -> str:
        return hashlib.sha256(token.encode()).hexdigest()

    def is_authenticated(self, token: str | None) -> bool:
        if not token or len(token) > 128 or self.config is None:
            return False
        with self._lock:
            self._prune()
            return self._digest(token) in self._sessions

    def revoke(self, token: str | None) -> None:
        if token:
            with self._lock:
                self._sessions.pop(self._digest(token), None)


@lru_cache(maxsize=1)
def get_auth_service() -> InvestigatorAuth:
    path = auth_file_path()
    if not path.exists():
        return InvestigatorAuth(None)
    # Invalid configuration fails closed; never fall back to a default secret.
    try:
        config = json.loads(path.read_text(encoding="utf-8"))
        key = bytes.fromhex(config["accessKey"])
        username = config["username"]
        if (len(key) != 32 or not isinstance(username, str) or not 1 <= len(username) <= 255
                or any(c in username for c in "\r\n")):
            raise ValueError("Invalid investigator authentication configuration")
    except (OSError, ValueError, TypeError, KeyError):
        logging.getLogger(__name__).error("Investigator authentication configuration is invalid or unreadable; access is disabled.")
        return InvestigatorAuth(None)
    return InvestigatorAuth(AuthConfig(username=username, access_key=key))


def require_browser_write(request: Request) -> str:
    origin = request.headers.get("origin", "")
    if origin not in allowed_origins() or request.headers.get(REQUEST_HEADER) != "1":
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Untrusted request origin or missing CSRF request header.")
    if request.headers.get("sec-fetch-site") == "cross-site":
        raise HTTPException(403, "Cross-site investigator requests are not allowed.")
    return origin


def require_investigator(
    request: Request,
    db: Session = Depends(get_db),
    auth: InvestigatorAuth = Depends(get_auth_service),
) -> Investigator:
    if not auth.is_authenticated(request.cookies.get(COOKIE_NAME)):
        raise HTTPException(401, "Investigator authentication required.")
    investigator = db.execute(select(Investigator).where(
        Investigator.username == auth.config.username
    )).scalars().first()
    if investigator is None:
        raise HTTPException(401, "Investigator authentication required.")
    if request.method not in ("GET", "HEAD", "OPTIONS"):
        require_browser_write(request)
    return investigator
