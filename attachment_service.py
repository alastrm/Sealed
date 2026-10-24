"""Owned, retryable ciphertext staging. No encryption keys or file metadata here."""
import hashlib
import os
import re
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi import HTTPException
from sqlalchemy import select, update

from message_protocol import canonical_uuid
from models import AttachmentUpload, CaseAttachment, AuditEventType

MAX_CIPHERTEXT_BYTES = 10 * 1024 * 1024 + 16
MAX_ATTACHMENTS = 10
MAX_BATCH_BYTES = 32 * 1024 * 1024
LEASE = timedelta(hours=24)
# The supported local API uses one worker. DB conditional updates also serialize
# finalization against cleanup; this lock covers filesystem publication in-process.
upload_lock = threading.RLock()


def now():
    return datetime.now(timezone.utc)


def owner_hash(role, credential):
    return hashlib.sha256((role + ':' + credential).encode()).hexdigest()


def attachment_ids(values):
    values = values or []
    if len(values) > MAX_ATTACHMENTS or len(set(values)) != len(values):
        raise HTTPException(400, 'At most 10 distinct attachment IDs are allowed.')
    for value in values:
        canonical_uuid(value)
    return values


def checked_path(storage, value):
    root = Path(storage).resolve()
    path = Path(value).resolve()
    if path.parent != root or path.is_symlink():
        raise HTTPException(403, 'Invalid attachment storage path.')
    return path


def claim_attachments(db, ids, case_id, owner, storage, *, initial=False):
    """All claims occur in the same transaction as the signed report/message."""
    total = 0
    for attachment_id in attachment_ids(ids):
        attachment = db.get(CaseAttachment, attachment_id)
        lease = db.get(AttachmentUpload, attachment_id)
        if (attachment is None or lease is None or lease.owner_hash != owner
                or lease.intended_case_id != (None if initial else case_id)):
            raise HTTPException(403, 'Attachment is missing or does not belong to this operation.')
        if attachment.case_id is not None or lease.state == 'claimed':
            raise HTTPException(409, 'Attachment has already been finalized.')
        path = checked_path(storage, attachment.ciphertext_path)
        if not path.is_file() or path.stat().st_size != attachment.size_bytes:
            raise HTTPException(409, 'Attachment upload is missing or incomplete. Retry the upload.')
        with path.open('rb') as source:
            digest = hashlib.sha256()
            while chunk := source.read(256 * 1024):
                digest.update(chunk)
        if digest.hexdigest() != lease.content_digest:
            raise HTTPException(409, 'Attachment upload is damaged. Prepare a new upload.')
        total += attachment.size_bytes
        if total > MAX_BATCH_BYTES:
            raise HTTPException(413, 'Encrypted attachments exceed the 32 MiB batch limit.')
        changed = db.execute(update(AttachmentUpload).where(
            AttachmentUpload.id == attachment_id, AttachmentUpload.state == 'staged',
            AttachmentUpload.expires_at > now(),
        ).values(state='claimed').execution_options(synchronize_session=False)).rowcount
        if changed != 1:
            raise HTTPException(410, 'Staged attachment expired. Prepare a new upload.')
        attachment.case_id = case_id



def cleanup_staged(db, storage, *, apply=False, cutoff=None):
    """Only expired, managed, unclaimed blobs. Never infer ownership from age alone.

    Tombstones prevent a late request from reviving an expired upload ID. Old
    legacy files/rows are left alone. Our abandoned .part files and untracked
    new-format ciphertext are quarantined. Dry run is the default, including the CLI.
    """
    cutoff = cutoff or now()
    result = {'expired': 0, 'removed': 0, 'quarantined': 0}
    with upload_lock:
        candidates = db.execute(select(AttachmentUpload, CaseAttachment).join(
            CaseAttachment, AttachmentUpload.id == CaseAttachment.id).where(
                CaseAttachment.case_id.is_(None), AttachmentUpload.expires_at <= cutoff,
                AttachmentUpload.state.in_(['staged', 'expired']),
            )).all()
        for lease, attachment in candidates:
            result['expired'] += 1
            if not apply:
                continue
            changed = db.execute(update(AttachmentUpload).where(
                AttachmentUpload.id == lease.id, AttachmentUpload.state.in_(['staged', 'expired']),
                AttachmentUpload.expires_at <= cutoff,
                AttachmentUpload.id.in_(select(CaseAttachment.id).where(CaseAttachment.case_id.is_(None))),
            ).values(state='expired').execution_options(synchronize_session=False)).rowcount
            db.commit()
            if changed:
                path = checked_path(storage, attachment.ciphertext_path)
                # A second row must never make another case's legitimate file a
                # cleanup target, even in an inconsistent manually edited DB.
                shared = db.scalar(select(CaseAttachment.id).where(
                    CaseAttachment.ciphertext_path == str(path), CaseAttachment.id != attachment.id))
                if not shared and path.name == f'v3-{attachment.id}.enc' and path.is_file():
                    path.unlink()
                    result['removed'] += 1
        root = Path(storage).resolve()
        for path in root.glob('v3-*'):
            identifier = r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
            if not re.fullmatch(r'v3-' + identifier + r'(?:\.enc|-[0-9a-f]{16}\.part)', path.name) or not path.is_file():
                continue
            if db.scalar(select(CaseAttachment.id).where(CaseAttachment.ciphertext_path == str(path))) is not None:
                continue
            if path.is_symlink() or path.stat().st_mtime > cutoff.timestamp() - LEASE.total_seconds():
                continue
            result['quarantined'] += 1
            if apply:
                quarantine = root / 'quarantine'
                quarantine.mkdir(exist_ok=True)
                target = quarantine / path.name
                if not target.exists():
                    os.rename(path, target)
    return result
