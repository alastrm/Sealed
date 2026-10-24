import os
import hashlib
from pathlib import Path
import json
import secrets
import uuid
from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile, status
from fastapi.responses import FileResponse
from starlette.concurrency import run_in_threadpool
from sqlalchemy import select, update
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError

from history_service import append_history, verify_history, history_version, prepare_mutation, lock_case
from reporter_auth import ReporterAuth, get_reporter_auth, find_case, authorize_json, authorize_read, upload_digest
from database import get_db
from message_protocol import read_only, validate_creation, validate_reply
from investigator_auth import InvestigatorAuth, get_auth_service, require_investigator
from models import AuditEventType, Case, CaseAttachment, CaseMessage, CaseStatus, Investigator, AttachmentUpload, SubmissionReceipt
from attachment_service import (MAX_CIPHERTEXT_BYTES, LEASE, now, owner_hash, attachment_ids, claim_attachments, upload_lock, checked_path)
from message_protocol import b64, canonical_uuid
from rate_limiter import LIMIT_CREATE_CASE, LIMIT_LOOKUP_CASE, limiter
from schemas import (
    AuditVerificationResponse,
    CaseAccessRequestDto,
    CaseAccessResponseDto,
    CaseAttachmentUploadResponse,
    CaseCreatedResponse,
    CaseMessageDto,
    CreateCaseDto,
    ReporterReplyDto,
)

router = APIRouter(prefix="/api/v1/cases", tags=["Cases"])

STORAGE_DIR = os.path.join(os.getcwd(), "storage", "attachments")
os.makedirs(STORAGE_DIR, exist_ok=True)
MAX_ATTACHMENT_SIZE = MAX_CIPHERTEXT_BYTES  # Largest padded bucket plus secretbox MAC


@router.post(
    "",
    response_model=CaseCreatedResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Submit New Whistleblower Case",
    description="Accepts an anonymous encrypted report, stores it with OPEN status, links it to reporter's token hash, and initiates audit chain.",
)
@limiter.limit(LIMIT_CREATE_CASE)
def create_case(
    request: Request,
    payload: CreateCaseDto,
    db: Session = Depends(get_db),
) -> CaseCreatedResponse:
    ids = attachment_ids(payload.attachment_ids)
    digest = hashlib.sha256(json.dumps({**payload.model_dump(), 'attachment_ids': sorted(ids)},
        sort_keys=True, separators=(',', ':')).encode()).hexdigest()

    def repeated():
        existing = db.get(Case, payload.case_id)
        if existing is None:
            return None
        receipt = db.get(SubmissionReceipt, payload.case_id)
        if receipt is None or not secrets.compare_digest(receipt.request_digest, digest):
            raise HTTPException(409, 'Case ID is already used by a different submission.')
        return CaseCreatedResponse(case_id=existing.id, status=existing.status, created_at=existing.created_at)

    replay = repeated()
    if replay is not None:
        return replay
    validate_creation(db, payload)
    if db.scalar(select(Case.id).where(Case.case_access_token_hash == payload.case_access_token_hash)) is not None:
        raise HTTPException(409, 'These recovery credentials already identify a report. Use Track.')
    try:
        case = Case(
            id=payload.case_id, protocol_version=2, manifest_json=json.dumps(payload.manifest),
            case_access_token_hash=payload.case_access_token_hash,
            reporter_public_key=payload.reporter_public_key,
            encrypted_report=payload.encrypted_report, status=CaseStatus.OPEN,
        )
        db.add(case)
        db.flush()
        claim_attachments(db, ids, case.id, owner_hash('reporter', payload.manifest['reporterSigningPublicKey'] + ':' + payload.case_access_token_hash), STORAGE_DIR, initial=True)
        append_history(db, case, STORAGE_DIR, 'CASE_CREATED', 'REPORTER')
        db.add(SubmissionReceipt(case_id=case.id, request_digest=digest,
            credential_digest=hashlib.sha256(payload.case_access_token_hash.encode()).hexdigest()))
        db.commit()
    except IntegrityError:
        db.rollback()
        replay = repeated()
        if replay is not None:
            return replay
        raise HTTPException(409, 'Concurrent submission conflict; retry the same submission.') from None
    except Exception:
        db.rollback()
        raise
    return CaseCreatedResponse(case_id=case.id, status=case.status, created_at=case.created_at)


@router.post(
    "/attachments",
    response_model=CaseAttachmentUploadResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Upload Blind Encrypted Evidence Attachment",
    description="Stores an encrypted binary blob without metadata. Ciphertext is bounded to the largest padding bucket plus its authentication tag.",
)
@limiter.limit(LIMIT_LOOKUP_CASE)
async def upload_attachment(
    request: Request,
    file: UploadFile = File(...),
    case_id: str | None = Form(None),
    attachment_id: str | None = Form(None),
    staging_token: str | None = Form(None),
    case_access_token_hash: str | None = Form(None),
    signing_public_key: str | None = Form(None),
    content_digest: str | None = Form(None),
    reporter_auth: ReporterAuth = Depends(get_reporter_auth),
    db: Session = Depends(get_db),
    auth: InvestigatorAuth = Depends(get_auth_service),
) -> CaseAttachmentUploadResponse:
    attachment_id = attachment_id or str(uuid.uuid4())
    canonical_uuid(attachment_id)
    resolved_case_id = case_id
    if case_id:
        canonical_uuid(case_id)
    reporter_case = None
    if case_access_token_hash or staging_token:
        locator = case_access_token_hash or staging_token
        b64(locator, 32)
        b64(signing_public_key, 32)
        found_case = db.scalar(select(Case).where(Case.case_access_token_hash == locator))
        if case_access_token_hash and (not found_case or (case_id and found_case.id != case_id)):
            raise HTTPException(403, 'Invalid attachment case credential.')
        if case_access_token_hash:
            resolved_case_id = found_case.id
        elif case_id:
            raise HTTPException(400, 'Initial staging cannot specify an existing case.')
        reporter_case = found_case
        reporter_auth.consume(request, operation='POST /api/v1/cases/attachments',
            request_digest=upload_digest(attachment_id, case_id, content_digest, staging_token, case_access_token_hash),
            case=found_case, locator=locator, key=signing_public_key)
        if found_case and signing_public_key != found_case.manifest['reporterSigningPublicKey']:
            raise HTTPException(403, 'Wrong attachment signing identity.')
        owner = owner_hash('reporter', signing_public_key + ':' + locator)
    elif case_id:
        investigator = require_investigator(request, db, auth)
        if db.get(Case, case_id) is None:
            raise HTTPException(404, 'Case not found.')
        owner = owner_hash('investigator', investigator.id)
    else:
        raise HTTPException(401, 'Initial uploads require a reporter signing proof.')

    root = Path(STORAGE_DIR).resolve()
    root.mkdir(parents=True, exist_ok=True)
    temporary = root / f'v3-{attachment_id}-{secrets.token_hex(8)}.part'
    destination = root / f'v3-{attachment_id}.enc'
    published = False
    size = 0
    digest = hashlib.sha256()
    try:
        with temporary.open('xb') as target:
            while chunk := await file.read(256 * 1024):
                size += len(chunk)
                if size > MAX_ATTACHMENT_SIZE:
                    raise HTTPException(413, 'Encrypted attachment exceeds 10 MiB plus its 16-byte MAC.')
                digest.update(chunk)
                target.write(chunk)
        if size == 0:
            raise HTTPException(400, 'Empty ciphertext upload.')
        if signing_public_key and digest.hexdigest() != content_digest:
            raise HTTPException(403, 'Uploaded bytes do not match the signed request.')
        with upload_lock:
            # Recheck after streaming and hold the DB lock only during publication.
            # A concurrent close wins before publication or waits for this commit.
            if resolved_case_id:
                prepare_mutation(db, resolved_case_id, STORAGE_DIR)
            elif reporter_case:
                prepare_mutation(db, reporter_case.id, STORAGE_DIR)
            lease = db.get(AttachmentUpload, attachment_id)
            attachment = db.get(CaseAttachment, attachment_id)
            if attachment is not None or lease is not None:
                if (not attachment or not lease or lease.owner_hash != owner
                    or lease.intended_case_id != resolved_case_id
                    or lease.content_digest != digest.hexdigest() or attachment.size_bytes != size):
                    raise HTTPException(409, 'Upload ID is already used by a different upload.')
                if lease.state == 'expired':
                    raise HTTPException(410, 'Upload expired; prepare a new upload.')
                if lease.state == 'staged':
                    changed = db.execute(update(AttachmentUpload).where(
                        AttachmentUpload.id == attachment_id, AttachmentUpload.state == 'staged',
                        AttachmentUpload.expires_at > now(),
                    ).values(expires_at=now() + LEASE).execution_options(synchronize_session=False)).rowcount
                    if changed != 1:
                        raise HTTPException(410, 'Upload expired; prepare a new upload.')
                destination = checked_path(STORAGE_DIR, attachment.ciphertext_path)
                if not destination.exists():
                    os.rename(temporary, destination)
                db.commit()
                return CaseAttachmentUploadResponse(attachment_id=attachment.id, size_bytes=size, created_at=attachment.created_at)
            if destination.exists():
                # A process crash may leave ciphertext without a receipt. Do not
                # overwrite or adopt a blob whose owner can no longer be proven.
                raise HTTPException(409, 'Unreconciled upload file; prepare a new upload ID.')
            attachment = CaseAttachment(id=attachment_id, case_id=None,
                ciphertext_path=str(destination), size_bytes=size)
            db.add(attachment)
            db.flush()
            db.add(AttachmentUpload(id=attachment_id, owner_hash=owner,
                intended_case_id=resolved_case_id, content_digest=digest.hexdigest(),
                state='staged', expires_at=now() + LEASE))
            os.rename(temporary, destination)
            published = True
            db.commit()
            return CaseAttachmentUploadResponse(attachment_id=attachment.id, size_bytes=size, created_at=attachment.created_at)
    except BaseException:
        db.rollback()
        if published:
            # Delete only the file this request published, and only if no committed
            # database record owns it (including an ambiguous commit outcome).
            if db.get(CaseAttachment, attachment_id) is None and destination.exists():
                destination.unlink()
        raise
    finally:
        try:
            await file.close()
        finally:
            if temporary.exists():
                temporary.unlink()


@router.get(
    "/attachments/{attachment_id}",
    summary="Download Blind Encrypted Evidence Attachment",
    description="Streams the raw encrypted blob with strict security headers preventing browser execution (Anti-XSS).",
)
def download_attachment(
    attachment_id: str,
    request: Request,
    db: Session = Depends(get_db),
    reporter_auth: ReporterAuth = Depends(get_reporter_auth),
    auth: InvestigatorAuth = Depends(get_auth_service),
) -> FileResponse:
    # 1. Strict UUID validation
    try:
        parsed_uuid = uuid.UUID(attachment_id)
        valid_attachment_id = str(parsed_uuid)
    except (ValueError, TypeError, AttributeError):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid attachment ID format: '{attachment_id}'. Must be a valid UUID.",
        )

    attachment = db.get(CaseAttachment, valid_attachment_id)
    if not attachment:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Attachment with ID '{valid_attachment_id}' was not found.",
        )

    if not attachment.case_id:
        raise HTTPException(403, 'Staged attachments are not downloadable.')
    case = db.get(Case, attachment.case_id)
    if request.headers.get('x-sealed-challenge'):
        authorize_read(request, case, reporter_auth)
    else:
        require_investigator(request, db, auth)
    resolved_file_path = checked_path(STORAGE_DIR, attachment.ciphertext_path)
    if not resolved_file_path.is_file():
        raise HTTPException(404, 'Attachment file not found on disk.')

    return FileResponse(
        path=resolved_file_path,
        media_type="application/octet-stream",
        headers={
            "Content-Disposition": 'attachment; filename="evidence.enc"',
            "X-Content-Type-Options": "nosniff",
            "Cache-Control": "no-store",
        },
    )


@router.get('/{case_id}/audit-verify', response_model=AuditVerificationResponse)
def verify_audit(case_id: str, request: Request, db: Session = Depends(get_db),
                 reporter_auth: ReporterAuth = Depends(get_reporter_auth),
                 auth: InvestigatorAuth = Depends(get_auth_service)):
    case = db.get(Case, case_id)
    if not case:
        raise HTTPException(404, 'Case not found.')
    if request.headers.get('x-sealed-challenge'):
        authorize_read(request, case, reporter_auth)
    else:
        require_investigator(request, db, auth)
    case = lock_case(db, case_id)  # one consistent SQL snapshot during verification
    return AuditVerificationResponse(**verify_history(db, case, STORAGE_DIR))


def case_response(db, case):
    return CaseAccessResponseDto(case_id=case.id, protocol_version=case.protocol_version, manifest=case.manifest,
        read_only=read_only(db, case) or case.status == CaseStatus.CLOSED, status=case.status,
        revision=history_version(db, case.id), created_at=case.created_at,
        reporter_public_key=case.reporter_public_key, messages=[CaseMessageDto.model_validate(m) for m in case.messages])


@router.post('/lookup', response_model=CaseAccessResponseDto)
@limiter.limit(LIMIT_LOOKUP_CASE)
async def lookup_case(request: Request, payload: CaseAccessRequestDto, db: Session = Depends(get_db),
                      reporter_auth: ReporterAuth = Depends(get_reporter_auth)):
    case = find_case(db, payload.case_access_token_hash)
    await authorize_json(request, case, reporter_auth)
    return case_response(db, case)


def persist_reporter_reply(db, case, payload):
    case = prepare_mutation(db, case.id, STORAGE_DIR)
    validate_reply(db, case, payload, 'REPORTER', payload.encrypted_message)
    try:
        message = CaseMessage(id=payload.message_id, protocol_version=2, signature=payload.signature,
            case_id=case.id, encrypted_response=payload.encrypted_message, nonce=payload.nonce,
            investigator_public_key=case.manifest['investigatorPublicKey'], sender_type='REPORTER')
        db.add(message)
        db.flush()
        claim_attachments(db, payload.attachment_ids, case.id,
            owner_hash('reporter', case.manifest['reporterSigningPublicKey'] + ':' + case.case_access_token_hash), STORAGE_DIR)
        # Reporter messages never mutate investigator workflow status.
        append_history(db, case, STORAGE_DIR, 'MESSAGE_RECEIVED', 'REPORTER')
        db.commit()
        db.refresh(message)
        return CaseMessageDto.model_validate(message)
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, 'Duplicate record ID rejected.') from None
    except Exception:
        db.rollback()
        raise


@router.post('/messages', response_model=CaseMessageDto, status_code=201)
@limiter.limit(LIMIT_LOOKUP_CASE)
async def add_reporter_message_by_hash(request: Request, payload: ReporterReplyDto, db: Session = Depends(get_db),
                                       reporter_auth: ReporterAuth = Depends(get_reporter_auth)):
    case = find_case(db, payload.case_access_token_hash)
    await authorize_json(request, case, reporter_auth)
    return await run_in_threadpool(persist_reporter_reply, db, case, payload)


@router.post('/{case_id}/access', response_model=CaseAccessResponseDto)
@limiter.limit(LIMIT_LOOKUP_CASE)
async def access_case(request: Request, case_id: str, payload: CaseAccessRequestDto, db: Session = Depends(get_db),
                      reporter_auth: ReporterAuth = Depends(get_reporter_auth)):
    case = find_case(db, payload.case_access_token_hash)
    if case.id != case_id:
        raise HTTPException(403, 'Recovery credentials belong to another case.')
    await authorize_json(request, case, reporter_auth)
    return case_response(db, case)


@router.post('/{case_id}/messages', response_model=CaseMessageDto, status_code=201)
@limiter.limit(LIMIT_LOOKUP_CASE)
async def add_reporter_message(request: Request, case_id: str, payload: ReporterReplyDto, db: Session = Depends(get_db),
                               reporter_auth: ReporterAuth = Depends(get_reporter_auth)):
    case = find_case(db, payload.case_access_token_hash)
    if case.id != case_id:
        raise HTTPException(403, 'Recovery credentials belong to another case.')
    await authorize_json(request, case, reporter_auth)
    return await run_in_threadpool(persist_reporter_reply, db, case, payload)
