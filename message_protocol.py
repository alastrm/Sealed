"""V2 wire validation and Ed25519 verification. Never handles plaintext keys/content."""
import base64
import hashlib
import json
import uuid

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from fastapi import HTTPException
from sqlalchemy import select

from models import CaseMessage, InvestigatorIdentity

MANIFEST_FIELDS = {
    'protocolVersion', 'caseId', 'reporterPublicKey', 'reporterSigningPublicKey',
    'investigatorPublicKey', 'investigatorSigningPublicKey', 'identitySignature',
    'credentialCommitment', 'encryptedReport', 'reportSignature',
}


def wire(values: list) -> bytes:
    # All variable fields are canonical UUID or base64 ASCII. Fixed-order JSON
    # arrays have identical bytes in JSON.stringify and this encoder.
    return json.dumps(values, ensure_ascii=True, separators=(',', ':')).encode('ascii')


def b64(value, size=None, minimum=None, maximum=100000) -> bytes:
    try:
        if not isinstance(value, str) or len(value) > maximum:
            raise ValueError()
        decoded = base64.b64decode(value, validate=True)
        if base64.b64encode(decoded).decode() != value:
            raise ValueError()
        if (size is not None and len(decoded) != size) or (minimum is not None and len(decoded) < minimum):
            raise ValueError()
        return decoded
    except (ValueError, TypeError):
        raise HTTPException(400, 'Invalid protocol encoding or length.') from None


def canonical_uuid(value):
    try:
        if not isinstance(value, str) or str(uuid.UUID(value)) != value:
            raise ValueError()
    except (ValueError, TypeError, AttributeError):
        raise HTTPException(400, 'A canonical UUID is required.') from None


def verify(signature, data, public_key):
    sig, key = b64(signature, 64), b64(public_key, 32)
    try:
        Ed25519PublicKey.from_public_bytes(key).verify(sig, data)
    except (InvalidSignature, ValueError):
        raise HTTPException(403, 'Message signature verification failed.') from None


def identity_bytes(public_key, signing_public_key):
    return wire(['sealed:identity', 2, public_key, signing_public_key])


def report_bytes(m):
    return wire(['sealed:report', 2, m['caseId'], 'REPORTER',
                 m['reporterPublicKey'], m['reporterSigningPublicKey'],
                 m['investigatorPublicKey'], m['investigatorSigningPublicKey'],
                 m['identitySignature'], m['credentialCommitment'], m['encryptedReport']])


def message_bytes(m, message_id, role, nonce, ciphertext):
    return wire(['sealed:message', 2, m['caseId'], message_id, role,
                 m['reporterPublicKey'], m['reporterSigningPublicKey'],
                 m['investigatorPublicKey'], m['investigatorSigningPublicKey'],
                 m['reportSignature'], nonce, ciphertext])


def validate_identity(packet):
    required = {'protocolVersion', 'publicKey', 'signingPublicKey', 'identitySignature',
                'encryptedPrivateKey', 'privateKeyNonce', 'kdfSalt', 'kdfOpsLimit', 'kdfMemLimit', 'kdfAlgorithm'}
    if not isinstance(packet, dict) or set(packet) != required or packet['protocolVersion'] != 2:
        raise HTTPException(400, 'Invalid v2 identity bundle.')
    b64(packet['publicKey'], 32)
    b64(packet['signingPublicKey'], 32)
    b64(packet['encryptedPrivateKey'], size=144, maximum=192)
    b64(packet['privateKeyNonce'], 24)
    b64(packet['kdfSalt'], 16)
    if (packet['kdfOpsLimit'], packet['kdfMemLimit'], packet['kdfAlgorithm']) != (2, 67108864, 2):
        raise HTTPException(400, 'Unsupported identity KDF parameters.')
    verify(packet['identitySignature'], identity_bytes(packet['publicKey'], packet['signingPublicKey']), packet['signingPublicKey'])


def active_identity(db, investigator_id=None):
    query = select(InvestigatorIdentity).where(InvestigatorIdentity.active == 1)
    if investigator_id is not None:
        query = query.where(InvestigatorIdentity.investigator_id == investigator_id)
    identity = db.execute(query).scalars().first()
    if identity is None:
        raise HTTPException(503, 'Initialize a fresh v2 investigator identity using local setup.')
    return identity


def validate_manifest(m):
    if not isinstance(m, dict) or set(m) != MANIFEST_FIELDS or m.get('protocolVersion') != 2:
        raise HTTPException(400, 'A complete v2 signed report manifest is required.')
    canonical_uuid(m['caseId'])
    for name in ('reporterPublicKey', 'reporterSigningPublicKey', 'investigatorPublicKey',
                 'investigatorSigningPublicKey', 'credentialCommitment'):
        b64(m[name], 32)
    b64(m['encryptedReport'], minimum=48)
    verify(m['identitySignature'], identity_bytes(m['investigatorPublicKey'], m['investigatorSigningPublicKey']), m['investigatorSigningPublicKey'])
    verify(m['reportSignature'], report_bytes(m), m['reporterSigningPublicKey'])


def validate_creation(db, payload):
    if payload.protocol_version != 2:
        raise HTTPException(409, 'Legacy submission is disabled. Use protocol v2.')
    m = payload.manifest
    validate_manifest(m)
    identity = active_identity(db)
    if (m['investigatorPublicKey'], m['investigatorSigningPublicKey'], m['identitySignature']) != (
            identity.public_key, identity.signing_public_key, identity.identity_signature):
        raise HTTPException(403, 'Report recipient is not the configured active identity.')
    if (payload.case_id, payload.reporter_public_key, payload.encrypted_report) != (
            m['caseId'], m['reporterPublicKey'], m['encryptedReport']):
        raise HTTPException(403, 'Report context does not match its signed manifest.')
    b64(payload.case_access_token_hash, 32)
    commitment = base64.b64encode(hashlib.sha256(payload.case_access_token_hash.encode('ascii')).digest()).decode()
    if commitment != m['credentialCommitment']:
        raise HTTPException(403, 'Recovery credential does not match the signed report.')


def read_only(db, case):
    if case.protocol_version != 2 or not case.manifest:
        return True
    identity = db.get(InvestigatorIdentity, case.manifest['investigatorSigningPublicKey'])
    return identity is None or identity.active != 1


def validate_reply(db, case, payload, role, ciphertext, investigator=None):
    if read_only(db, case):
        raise HTTPException(409, 'Archived/legacy conversations are UNVERIFIED or archived and READ-ONLY.')
    if payload.protocol_version != 2:
        raise HTTPException(409, 'Protocol downgrade rejected; a signed v2 message is required.')
    m = case.manifest
    validate_manifest(m)
    canonical_uuid(payload.message_id)
    b64(payload.nonce, 24)
    b64(ciphertext, minimum=16)
    if payload.investigator_public_key not in (None, m['investigatorPublicKey']):
        raise HTTPException(403, 'Message cannot replace the case investigator key.')
    identity = db.get(InvestigatorIdentity, m['investigatorSigningPublicKey'])
    if investigator is not None and identity.investigator_id != investigator.id:
        raise HTTPException(403, 'Identity does not belong to this investigator session.')
    key = m['investigatorSigningPublicKey'] if role == 'INVESTIGATOR' else m['reporterSigningPublicKey']
    verify(payload.signature, message_bytes(m, payload.message_id, role, payload.nonce, ciphertext), key)
    if db.get(CaseMessage, payload.message_id) is not None:
        raise HTTPException(409, 'Message replay rejected: ID already exists.')
