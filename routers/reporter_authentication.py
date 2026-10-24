import re
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import Field
from sqlalchemy import select
from sqlalchemy.orm import Session
from database import get_db
from models import Case
from message_protocol import b64, validate_manifest
from reporter_auth import ReporterAuth, get_reporter_auth
from schemas import CamelModel
from rate_limiter import limiter, LIMIT_LOOKUP_CASE

router = APIRouter(prefix='/api/v1/reporter-auth', tags=['Reporter proof of possession'])


class ChallengeRequest(CamelModel):
    auth_version: int = 1
    locator: str = Field(min_length=44, max_length=44)
    signing_public_key: str = Field(min_length=44, max_length=44)
    operation: str = Field(max_length=160)
    request_digest: str = Field(pattern=r'^[0-9a-f]{64}$')
    enroll: bool = False


@router.post('/challenge')
@limiter.limit('120/minute')
def challenge(request: Request, payload: ChallengeRequest, db: Session = Depends(get_db),
              auth: ReporterAuth = Depends(get_reporter_auth)):
    b64(payload.locator, 32)
    b64(payload.signing_public_key, 32)
    if payload.auth_version != 1:
        raise HTTPException(400, 'Unsupported reporter authentication version.')
    uuid = r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
    allowed = (r'POST /api/v1/cases/(?:lookup|messages|attachments|' + uuid + r'/(?:access|messages))|'
               r'GET /api/v1/cases/(?:' + uuid + r'/audit-verify|attachments/' + uuid + r')')
    if not re.fullmatch(allowed, payload.operation):
        raise HTTPException(400, 'Unsupported reporter operation.')
    case = db.scalar(select(Case).where(Case.case_access_token_hash == payload.locator))
    if case is None:
        if not payload.enroll or payload.operation != 'POST /api/v1/cases/attachments':
            raise HTTPException(404, 'No case found for these recovery credentials.')
        case_id, key = '', payload.signing_public_key
    else:
        if case.protocol_version != 2:
            raise HTTPException(410, 'Legacy reporter access is unavailable: no enrolled signing identity. Investigator archive is UNVERIFIED and READ-ONLY.')
        validate_manifest(case.manifest)
        case_id, key = case.id, case.manifest['reporterSigningPublicKey']
        if key != payload.signing_public_key:
            raise HTTPException(403, 'Recovery signing identity does not match the case.')
    return auth.issue(case_id=case_id, locator=payload.locator, key=key,
                      operation=payload.operation, request_digest=payload.request_digest)
