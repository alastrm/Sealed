"""Disposable API fixtures; never reset or write to the developer's database."""
import hashlib
import hmac
import base64
import json
import uuid
import secrets
import tempfile
from contextlib import ExitStack, contextmanager
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from database import Base, get_db
from investigator_auth import AuthConfig, InvestigatorAuth, get_auth_service, proof_message
from main import app
from models import Investigator, InvestigatorIdentity
from message_protocol import identity_bytes, report_bytes, message_bytes
from reporter_auth import ReporterAuth, get_reporter_auth, proof_bytes, upload_digest
from rate_limiter import limiter
from seed import TEST_INVESTIGATOR

ORIGIN = "http://localhost:3000"
WRITE_HEADERS = {"Origin": ORIGIN, "X-Sealed-Request": "1"}


def encoded(value):
    return base64.b64encode(value).decode()


def public(key):
    return encoded(key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))


def signed_case(fixture, **changes):
    case_id = changes.pop('caseId', str(uuid.uuid4()))
    token = changes.pop('caseAccessTokenHash', encoded(secrets.token_bytes(32)))
    ciphertext = changes.pop('encryptedReport', encoded(bytes(48)))
    reporter_key = changes.pop('reporterPublicKey', fixture.reporter_public)
    manifest = dict(protocolVersion=2, caseId=case_id, reporterPublicKey=reporter_key,
        reporterSigningPublicKey=public(fixture.reporter_sign), investigatorPublicKey=fixture.identity['publicKey'],
        investigatorSigningPublicKey=fixture.identity['signingPublicKey'], identitySignature=fixture.identity['identitySignature'],
        credentialCommitment=encoded(hashlib.sha256(token.encode()).digest()), encryptedReport=ciphertext)
    manifest['reportSignature'] = encoded(fixture.reporter_sign.sign(report_bytes(manifest)))
    return dict(protocolVersion=2, manifest=manifest, caseId=case_id,
                reporterPublicKey=reporter_key, caseAccessTokenHash=token, encryptedReport=ciphertext, **changes)


def signed_reply(fixture, case_id, role='INVESTIGATOR', **changes):
    with fixture.sessions() as db:
        from models import Case
        manifest = db.get(Case, case_id).manifest
    message_id = changes.pop('messageId', str(uuid.uuid4()))
    nonce = changes.pop('nonce', encoded(secrets.token_bytes(24)))
    ciphertext = changes.pop('encryptedResponse', changes.pop('encryptedMessage', encoded(bytes(16))))
    signer = fixture.investigator_sign if role == 'INVESTIGATOR' else fixture.reporter_sign
    result = dict(protocolVersion=2, messageId=message_id, nonce=nonce,
        investigatorPublicKey=fixture.identity['publicKey'],
        signature=encoded(signer.sign(message_bytes(manifest, message_id, role, nonce, ciphertext))))
    if role == 'INVESTIGATOR':
        result.update(caseId=case_id, encryptedResponse=ciphertext)
    else:
        result.update(caseAccessTokenHash=fixture.case_token, encryptedMessage=ciphertext)
    result.update(changes)
    return result


@contextmanager
def isolated_api(clock=None):
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    sessions = sessionmaker(bind=engine)
    Base.metadata.create_all(engine)
    with sessions() as db:
        db.add(Investigator(**TEST_INVESTIGATOR))
        db.commit()
    investigator_sign = Ed25519PrivateKey.generate()
    identity = dict(protocolVersion=2, publicKey=public(X25519PrivateKey.generate()),
                    signingPublicKey=public(investigator_sign))
    identity['identitySignature'] = encoded(investigator_sign.sign(identity_bytes(identity['publicKey'], identity['signingPublicKey'])))
    with sessions() as db:
        db.add(InvestigatorIdentity(signing_public_key=identity['signingPublicKey'], public_key=identity['publicKey'],
            investigator_id=TEST_INVESTIGATOR['id'], identity_signature=identity['identitySignature'], encrypted_bundle='{}', active=1))
        db.commit()
    key = secrets.token_bytes(32)
    config = AuthConfig(TEST_INVESTIGATOR["username"], key)
    auth = InvestigatorAuth(config, **({"clock": clock} if clock else {}))

    def test_db():
        with sessions() as db:
            yield db

    previous = app.dependency_overrides.copy()
    app.dependency_overrides[get_db] = test_db
    app.dependency_overrides[get_auth_service] = lambda: auth
    reporter_auth = ReporterAuth()
    app.dependency_overrides[get_reporter_auth] = lambda: reporter_auth
    limiter.reset()
    try:
        with tempfile.TemporaryDirectory(prefix="sealed-tests-") as directory, ExitStack() as stack:
            stack.enter_context(patch("main.engine", engine))
            stack.enter_context(patch("database.SessionLocal", sessions))
            stack.enter_context(patch("seed.SessionLocal", sessions))
            stack.enter_context(patch("seed.engine", engine))
            stack.enter_context(patch("routers.cases.STORAGE_DIR", directory))
            client = stack.enter_context(TestClient(app))
            fixture = SimpleNamespace(client=client, sessions=sessions, auth=auth, reporter_auth=reporter_auth,
                                  key=key, username=config.username, storage=Path(directory), identity=identity,
                                  investigator_sign=investigator_sign, reporter_sign=Ed25519PrivateKey.generate(),
                                  reporter_public=public(X25519PrivateKey.generate()))
            fixture.reporter = ReporterClient(fixture)
            yield fixture
    finally:
        app.dependency_overrides.clear()
        app.dependency_overrides.update(previous)
        limiter.reset()
        engine.dispose()


def login(fixture, client=None, key=None, username=None):
    client = client or fixture.client
    username = username or fixture.username
    challenge = client.post("/api/v1/investigators/auth/challenge", headers=WRITE_HEADERS,
                            json={"username": username})
    assert challenge.status_code == 200, challenge.text
    data = challenge.json()
    proof = hmac.new(key or fixture.key, proof_message(
        data["challengeId"], data["nonce"], username, ORIGIN), hashlib.sha256).hexdigest()
    return client.post("/api/v1/investigators/auth/session", headers=WRITE_HEADERS, json={
        "username": username, "challengeId": data["challengeId"], "proof": proof,
    })


def reporter_proof(fixture, operation, digest, locator, *, enroll=False, signer=None):
    signer = signer or fixture.reporter_sign
    signing_public = public(signer)
    frontend_fixture = getattr(fixture, 'frontend_fixture', None)
    if frontend_fixture:
        signing_public = frontend_fixture['case']['manifest']['reporterSigningPublicKey']
    challenge = fixture.client.post('/api/v1/reporter-auth/challenge', json=dict(
        authVersion=1, locator=locator, signingPublicKey=signing_public,
        operation=operation, requestDigest=digest, enroll=enroll))
    if challenge.status_code != 200:
        return challenge
    c = challenge.json()
    if frontend_fixture:
        from test_message_protocol import frontend
        proof = frontend('auth-proof', fixture=frontend_fixture, challenge=c)['proof']
    else:
        proof = encoded(signer.sign(proof_bytes(c)))
    return {'X-Sealed-Challenge': c['challengeId'], 'X-Sealed-Proof': proof}


class ReporterClient:
    """Explicit positive-test caller; raw fixture.client remains unauthenticated.

    Uses the real challenge endpoint and signatures, no authorization overrides.
    """
    def __init__(self, fixture):
        self.f = fixture

    def __getattr__(self, name):
        return getattr(self.f.client, name)

    def post(self, path, **kwargs):
        if not path.startswith('/api/v1/cases/'):
            return self.f.client.post(path, **kwargs)
        payload = kwargs.get('json') or {}
        data = dict(kwargs.get('data') or {})
        locator = payload.get('caseAccessTokenHash') or data.get('case_access_token_hash') or data.get('staging_token')
        if not locator:
            return self.f.client.post(path, **kwargs)
        if path == '/api/v1/cases/attachments':
            file = kwargs['files']['file'][1]
            if not isinstance(file, bytes):
                file = file.read()
                kwargs['files']['file'] = ('evidence.enc', file, 'application/octet-stream')
            data['attachment_id'] = data.get('attachment_id') or str(uuid.uuid4())
            data['signing_public_key'] = (self.f.frontend_fixture['case']['manifest']['reporterSigningPublicKey']
                if getattr(self.f, 'frontend_fixture', None) else public(self.f.reporter_sign))
            data['content_digest'] = hashlib.sha256(file).hexdigest()
            kwargs['data'] = data
            digest = upload_digest(data['attachment_id'], data.get('case_id'), data['content_digest'], data.get('staging_token'), data.get('case_access_token_hash'))
            headers = reporter_proof(self.f, 'POST '+path, digest, locator, enroll=bool(data.get('staging_token')))
            if not isinstance(headers, dict): return headers
            kwargs['headers'] = {**kwargs.get('headers', {}), **headers}
            return self.f.client.post(path, **kwargs)
        request = self.f.client.build_request('POST', path, **kwargs)
        headers = reporter_proof(self.f, 'POST '+path, hashlib.sha256(request.content).hexdigest(), locator)
        if not isinstance(headers, dict): return headers
        request.headers.update(headers)
        return self.f.client.send(request)
