"""Reporter request authentication v1; separate from ciphertext protocol v2.

Ed25519 proofs of possession, never a stored bearer. Bounded one-use challenges
are process-local, like M1 sessions. Restart invalidates them; use one worker.
"""
import hashlib
import secrets
import threading
import time
from functools import lru_cache

from fastapi import HTTPException
from sqlalchemy import select

from message_protocol import b64, validate_manifest, verify, wire
from models import Case


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def upload_digest(attachment_id, case_id, content_digest, staging_token, credential):
    return digest(wire(['sealed:upload', 1, attachment_id, case_id or '', content_digest,
                        staging_token or '', credential or '']))


def proof_bytes(c):
    return wire(['sealed:reporter-auth', 1, 2, c['challengeId'], c['nonce'],
                 c['caseId'], c['locator'], c['signingPublicKey'], c['operation'],
                 c['requestDigest'], c['expiresAt']])


class ReporterAuth:
    def __init__(self, clock=time.time):
        self.clock = clock
        self.pending = {}
        self.lock = threading.Lock()

    def issue(self, *, case_id, locator, key, operation, request_digest):
        with self.lock:
            now = int(self.clock())
            self.pending = {k: v for k, v in self.pending.items() if v['expiresAt'] > now}
            if len(self.pending) >= 512:
                raise HTTPException(429, 'Too many pending reporter challenges.')
            challenge = dict(authVersion=1, protocolVersion=2, challengeId=secrets.token_hex(32),
                nonce=secrets.token_hex(32), caseId=case_id, locator=locator,
                signingPublicKey=key, operation=operation, requestDigest=request_digest, expiresAt=now + 60)
            self.pending[challenge['challengeId']] = challenge
            return challenge.copy()

    def consume(self, request, *, operation, request_digest, case=None, locator=None, key=None):
        # Pop under one lock BEFORE verification: neither concurrent request nor
        # an invalid proof can reuse the nonce, even if the business write fails.
        with self.lock:
            c = self.pending.pop(request.headers.get('x-sealed-challenge', ''), None)
        if not c or c['expiresAt'] <= self.clock():
            raise HTTPException(401, 'Reporter proof is missing, expired or already used.')
        if c['operation'] != operation or c['requestDigest'] != request_digest:
            raise HTTPException(403, 'Reporter proof does not authorize this request.')
        if case is not None:
            if case.protocol_version != 2:
                raise HTTPException(410, 'Legacy reporter access is unavailable: no enrolled signing identity. Investigator archive is UNVERIFIED and READ-ONLY.')
            validate_manifest(case.manifest)
            expected_key = case.manifest['reporterSigningPublicKey']
            if c['caseId'] != case.id or c['locator'] != case.case_access_token_hash or c['signingPublicKey'] != expected_key:
                raise HTTPException(403, 'Reporter proof belongs to another case.')
        elif c['caseId'] or c['locator'] != locator or c['signingPublicKey'] != key:
            raise HTTPException(403, 'Reporter staging proof does not match its owner.')
        verify(request.headers.get('x-sealed-proof'), proof_bytes(c), c['signingPublicKey'])
        return c


@lru_cache(maxsize=1)
def get_reporter_auth():
    return ReporterAuth()


def find_case(db, locator):
    b64(locator, 32)
    case = db.scalar(select(Case).where(Case.case_access_token_hash == locator))
    if case is None:
        raise HTTPException(404, 'No case found for these recovery credentials.')
    if case.protocol_version != 2:
        raise HTTPException(410, 'Legacy reporter access is unavailable: no enrolled signing identity. Investigator archive is UNVERIFIED and READ-ONLY.')
    return case


async def authorize_json(request, case, auth):
    return auth.consume(request, operation=request.method + ' ' + request.url.path,
                        request_digest=digest(await request.body()), case=case)


def authorize_read(request, case, auth):
    return auth.consume(request, operation=request.method + ' ' + request.url.path,
                        request_digest=digest(b''), case=case)
