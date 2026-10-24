"""Disposable loopback server only; never use this fixture against developer data."""
import json
import os
import uuid
from pathlib import Path

fixture = json.loads(Path(os.environ['SEALED_TEST_FIXTURE']).read_text())
assert 'sealed-demo-' in os.environ['DATABASE_URL'] or 'sealed-m3-' in os.environ['DATABASE_URL']
from database import Base, engine, SessionLocal
from models import Investigator, InvestigatorIdentity, Case, CaseMessage
from main import app
from fastapi.responses import Response

Base.metadata.create_all(engine)
with SessionLocal() as db:
    account = fixture['account']; packet = fixture['packet']; legacy = fixture['legacy']
    if db.get(Investigator, account['id']) is None:
        db.add(Investigator(id=account['id'], username=account['username'], public_key=account['publicKey'],
            encrypted_private_key=account['encryptedPrivateKey'], private_key_nonce=account['privateKeyNonce'],
            kdf_salt=account['kdfSalt'], kdf_ops_limit=2, kdf_mem_limit=67108864, kdf_algorithm=2))
        db.add(InvestigatorIdentity(signing_public_key=packet['signingPublicKey'], investigator_id=account['id'],
            public_key=packet['publicKey'], identity_signature=packet['identitySignature'], encrypted_bundle=json.dumps(packet), active=1))
        db.add(Case(id=legacy['id'], protocol_version=1, case_access_token_hash=legacy['caseAccessTokenHash'],
            reporter_public_key=legacy['reporterPublicKey'], encrypted_report=legacy['encryptedReport']))
        db.flush()
        db.add(CaseMessage(id=str(uuid.uuid4()), case_id=legacy['id'], protocol_version=1,
            encrypted_response=legacy['reply']['encryptedResponse'], nonce=legacy['reply']['nonce'],
            investigator_public_key=account['publicKey'], sender_type='INVESTIGATOR'))
        db.commit()

lose_once = True
@app.middleware('http')
async def lose_committed_acknowledgement(request, call_next):
    global lose_once
    response = await call_next(request)
    if lose_once and request.method == 'POST' and request.url.path == '/api/v1/cases' and response.status_code == 201:
        lose_once = False
        return Response(b'incomplete-json', status_code=201, media_type='application/json')
    return response
