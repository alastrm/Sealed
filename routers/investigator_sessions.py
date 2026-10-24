from fastapi import APIRouter, Depends, HTTPException, Request, Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from database import get_db

from investigator_auth import (
    COOKIE_NAME, COOKIE_PATH, SESSION_TTL, InvestigatorAuth,
    get_auth_service, require_browser_write, require_investigator, secure_cookie,
)
from models import Investigator
from rate_limiter import LIMIT_AUTH, limiter
from schemas import InvestigatorChallengeRequest, InvestigatorLoginRequest

router = APIRouter(prefix="/api/v1/investigators/auth", tags=["Investigator authentication"])


def peer_address(request: Request) -> str:
    # Do not trust caller-controlled forwarding headers for authentication limits.
    return request.client.host if request.client else "local"


@router.post("/challenge")
@limiter.limit(LIMIT_AUTH, key_func=peer_address)
def challenge(
    request: Request,
    payload: InvestigatorChallengeRequest,
    auth: InvestigatorAuth = Depends(get_auth_service),
) -> dict:
    origin = require_browser_write(request)
    challenge_id, nonce = auth.challenge(payload.username, origin)
    return {"challengeId": challenge_id, "nonce": nonce, "expiresIn": 60}


@router.post("/session")
@limiter.limit(LIMIT_AUTH, key_func=peer_address)
def login(
    request: Request,
    response: Response,
    payload: InvestigatorLoginRequest,
    auth: InvestigatorAuth = Depends(get_auth_service),
    db: Session = Depends(get_db),
) -> dict:
    origin = require_browser_write(request)
    auth.authenticate(payload.challenge_id, payload.username, payload.proof, origin)
    if db.execute(select(Investigator).where(Investigator.username == payload.username)).scalars().first() is None:
        raise HTTPException(401, "Invalid or expired investigator credentials.")
    token = auth.create_session(request.cookies.get(COOKIE_NAME))
    response.set_cookie(
        COOKIE_NAME, token, max_age=SESSION_TTL, httponly=True,
        secure=secure_cookie(), samesite="strict", path=COOKIE_PATH,
    )
    return {"username": payload.username, "expiresIn": SESSION_TTL}


@router.get("/session")
def session(investigator: Investigator = Depends(require_investigator)) -> dict:
    return {"username": investigator.username}


@router.delete("/session", status_code=204)
def logout(
    request: Request,
    response: Response,
    auth: InvestigatorAuth = Depends(get_auth_service),
) -> None:
    # Also permit clearing an expired cookie, but never accept a cross-origin logout.
    require_browser_write(request)
    auth.revoke(request.cookies.get(COOKIE_NAME))
    response.delete_cookie(COOKIE_NAME, path=COOKIE_PATH, secure=secure_cookie(), httponly=True, samesite="strict")
