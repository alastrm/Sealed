"""Versioned server consistency history. No non-repudiation/completeness claim.

One transaction locks the case, validates current state, mutates content/status,
and appends a snapshot-bound event plus head. Old hash-chain rows are preserved.
"""
import hashlib
import json
import uuid
from datetime import datetime, timezone

from fastapi import HTTPException
from sqlalchemy import select, update
from models import Case, CaseMessage, CaseAttachment, CaseHistoryHead, CaseHistoryEvent, AttachmentUpload
from message_protocol import validate_manifest, verify, message_bytes, read_only

ZERO = '0' * 64


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(',', ':'))


def hash_value(value):
    return hashlib.blake2b(canonical(value).encode(), digest_size=32).hexdigest()


def stamp(value):
    return value.replace(tzinfo=timezone.utc).isoformat() if value.tzinfo is None else value.astimezone(timezone.utc).isoformat()


def snapshot(db, case, storage):
    from attachment_service import checked_path
    m = case.manifest
    validate_manifest(m)
    if (case.id, case.reporter_public_key, case.encrypted_report) != (m['caseId'], m['reporterPublicKey'], m['encryptedReport']):
        raise ValueError('Report differs from its signed manifest.')
    import base64
    commitment = base64.b64encode(hashlib.sha256(case.case_access_token_hash.encode()).digest()).decode()
    if commitment != m['credentialCommitment']:
        raise ValueError('Recovery locator differs from its signed commitment.')
    messages = []
    for msg in db.scalars(select(CaseMessage).where(CaseMessage.case_id == case.id).order_by(CaseMessage.id)):
        if msg.protocol_version != 2 or msg.sender_type not in ('REPORTER', 'INVESTIGATOR') or msg.investigator_public_key != m['investigatorPublicKey']:
            raise ValueError('Invalid message context.')
        key = m['reporterSigningPublicKey'] if msg.sender_type == 'REPORTER' else m['investigatorSigningPublicKey']
        verify(msg.signature, message_bytes(m, msg.id, msg.sender_type, msg.nonce, msg.encrypted_response), key)
        messages.append({'id': msg.id, 'digest': hash_value([msg.protocol_version, msg.case_id, msg.encrypted_response,
            msg.nonce, msg.investigator_public_key, msg.sender_type, msg.signature, stamp(msg.created_at)])})
    attachments = []
    for item in db.scalars(select(CaseAttachment).where(CaseAttachment.case_id == case.id).order_by(CaseAttachment.id)):
        path = checked_path(storage, item.ciphertext_path)
        if not path.is_file() or path.stat().st_size != item.size_bytes:
            raise ValueError('Attachment is missing or truncated.')
        with path.open('rb') as source:
            hasher = hashlib.sha256()
            while chunk := source.read(256 * 1024):
                hasher.update(chunk)
            digest = hasher.hexdigest()
        lease = db.get(AttachmentUpload, item.id)
        if lease and (lease.state != 'claimed' or lease.content_digest != digest):
            raise ValueError('Attachment differs from its finalized upload.')
        attachments.append({'id': item.id, 'size': item.size_bytes, 'digest': digest, 'createdAt': stamp(item.created_at)})
    return {'caseId': case.id, 'protocolVersion': case.protocol_version, 'manifestDigest': hash_value(m),
            'createdAt': stamp(case.created_at), 'status': case.status.value,
            'messages': messages, 'attachments': attachments}


def event_hash(event):
    return hash_value(['sealed:history', 1, event.case_id, event.sequence, event.id,
        event.event_type, event.actor, event.created_at, event.payload_hash, event.previous_hash,
        event.request_id, event.request_digest])


def history_version(db, case_id):
    head = db.get(CaseHistoryHead, case_id)
    return head.sequence if head else 0


def verify_history(db, case, storage):
    events = db.scalars(select(CaseHistoryEvent).where(CaseHistoryEvent.case_id == case.id).order_by(CaseHistoryEvent.sequence)).all()
    result = dict(is_valid=False, events_count=len(events), broken_at=None, latest_hash=None,
                  status='unavailable', reason='No M4 consistency history; earlier activity is not verified.',
                  completeness_verified=False, historical_baseline=False)
    if case.protocol_version != 2:
        result.update(status='legacy', reason='Legacy archive is UNVERIFIED and READ-ONLY.')
        return result
    head = db.get(CaseHistoryHead, case.id)
    if not events and head is None:
        return result
    try:
        previous, prior_snapshot = ZERO, None
        for seq, event in enumerate(events, 1):
            result['broken_at'] = event.id
            payload = json.loads(event.payload_json)
            if event.sequence != seq or event.previous_hash != previous or event.payload_hash != hash_value(payload) or event.current_hash != event_hash(event):
                raise ValueError('History sequence or digest mismatch.')
            current = payload['snapshot']
            if current['caseId'] != case.id:
                raise ValueError('History case mismatch.')
            if seq == 1 and event.event_type not in ('CASE_CREATED', 'BASELINE'):
                raise ValueError('Missing initial history event.')
            if prior_snapshot:
                for name in ('messages', 'attachments'):
                    old = {x['id']: x for x in prior_snapshot[name]}
                    new = {x['id']: x for x in current[name]}
                    if any(new.get(k) != v for k, v in old.items()):
                        raise ValueError('History removes or rewrites an existing object.')
                if current['manifestDigest'] != prior_snapshot['manifestDigest'] or current['createdAt'] != prior_snapshot['createdAt']:
                    raise ValueError('History rewrites the original report.')
                if current['status'] != prior_snapshot['status']:
                    if not event.actor.startswith('INVESTIGATOR:') or payload.get('fromStatus') != prior_snapshot['status']:
                        raise ValueError('Status event has no authorized actor or origin state.')
            previous, prior_snapshot = event.current_hash, current
        if not events or head is None or head.sequence != len(events) or head.current_hash != previous:
            raise ValueError('History head disagrees with the event list (possible truncation).')
        if prior_snapshot != snapshot(db, case, storage):
            raise ValueError('Current case, messages, status or attachments differ from recorded history.')
        result.update(is_valid=True, status='consistent', reason=None, broken_at=None, latest_hash=previous,
                      historical_baseline=events[0].event_type == 'BASELINE')
    except (ValueError, KeyError, TypeError, OSError, HTTPException):
        result.update(status='inconsistent', reason='Stored history or signed case data is inconsistent.')
    return result


def append_history(db, case, storage, event_type, actor, *, from_status=None, request_id=None, request_digest=None):
    db.flush()
    head = db.get(CaseHistoryHead, case.id)
    if head is None:
        head = CaseHistoryHead(case_id=case.id, sequence=0, current_hash=ZERO)
        db.add(head)
    payload = {'snapshot': snapshot(db, case, storage), 'fromStatus': from_status}
    event = CaseHistoryEvent(id=str(uuid.uuid4()), case_id=case.id, sequence=head.sequence + 1,
        event_type=event_type, actor=actor, payload_json=canonical(payload), payload_hash=hash_value(payload),
        previous_hash=head.current_hash, created_at=datetime.now(timezone.utc).isoformat(),
        request_id=request_id, request_digest=request_digest)
    event.current_hash = event_hash(event)
    db.add(event)
    head.sequence, head.current_hash = event.sequence, event.current_hash
    db.flush()
    return event


def lock_case(db, case_id):
    # A write lock held to commit serializes reply, upload and transition checks.
    db.execute(update(Case).where(Case.id == case_id).values(status=Case.status).execution_options(synchronize_session=False))
    case = db.get(Case, case_id)
    if case is None:
        raise HTTPException(404, 'Case not found.')
    db.refresh(case)
    return case


def prepare_mutation(db, case_id, storage, *, allow_closed=False):
    case = lock_case(db, case_id)
    if read_only(db, case):
        raise HTTPException(409, 'Archived/legacy cases are READ-ONLY.')
    if case.status.value == 'CLOSED' and not allow_closed:
        raise HTTPException(409, 'Case is closed. An Investigator must reopen it before replies or uploads.')
    result = verify_history(db, case, storage)
    if result['status'] == 'inconsistent':
        raise HTTPException(409, 'Case consistency check failed; no changes were made.')
    if result['status'] == 'unavailable':
        try:
            append_history(db, case, storage, 'BASELINE', 'SYSTEM')
        except (ValueError, HTTPException, OSError):
            raise HTTPException(409, 'Existing signed case data cannot establish a consistency baseline.') from None
    return case
