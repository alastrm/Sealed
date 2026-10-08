import os
import secrets
import uuid
from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile, status
from fastapi.responses import FileResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from audit_service import record_audit_event, verify_case_audit_chain
from database import get_db
from models import AuditEventType, Case, CaseAttachment, CaseMessage, CaseStatus, Investigator
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
MAX_ATTACHMENT_SIZE = 10 * 1024 * 1024  # Strictly up to 10 MB


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
    # Check if a case with this ID already exists
    existing = db.get(Case, payload.case_id)
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Case with ID '{payload.case_id}' already exists.",
        )

    try:
        case = Case(
            id=payload.case_id,
            case_access_token_hash=payload.case_access_token_hash,
            reporter_public_key=payload.reporter_public_key,
            encrypted_report=payload.encrypted_report,
            status=CaseStatus.OPEN,
        )
        db.add(case)
        db.flush()

        # Record Genesis event in cryptographic audit chain
        record_audit_event(
            db=db,
            case_id=case.id,
            event_type=AuditEventType.CASE_CREATED,
            payload_data={
                "case_id": case.id,
                "reporter_public_key": case.reporter_public_key,
                "case_access_token_hash": case.case_access_token_hash,
                "encrypted_report_hash": secrets.token_hex(16),
            },
        )

        # Link any attachments submitted with this initial report
        if payload.attachment_ids:
            for att_id in payload.attachment_ids:
                att = db.get(CaseAttachment, att_id)
                if att:
                    att.case_id = case.id
                    record_audit_event(
                        db=db,
                        case_id=case.id,
                        event_type=AuditEventType.ATTACHMENT_ADDED,
                        payload_data={
                            "attachment_id": att.id,
                            "size_bytes": att.size_bytes,
                        },
                    )

        db.commit()
        db.refresh(case)
    except Exception:
        db.rollback()
        raise

    return CaseCreatedResponse(
        case_id=case.id,
        status=case.status,
        created_at=case.created_at,
    )


@router.post(
    "/attachments",
    response_model=CaseAttachmentUploadResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Upload Blind Encrypted Evidence Attachment",
    description="Stores an encrypted binary blob without metadata. File size strictly limited to 10MB.",
)
@limiter.limit(LIMIT_LOOKUP_CASE)
async def upload_attachment(
    request: Request,
    file: UploadFile = File(...),
    case_id: str | None = Form(None),
    case_access_token_hash: str | None = Form(None),
    db: Session = Depends(get_db),
) -> CaseAttachmentUploadResponse:
    content = await file.read()
    if len(content) > MAX_ATTACHMENT_SIZE:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"Attachment size {len(content)} bytes exceeds maximum allowed limit of 10 MB.",
        )

    resolved_case_id = case_id
    if not resolved_case_id and case_access_token_hash:
        stmt = select(Case).where(Case.case_access_token_hash == case_access_token_hash)
        found_case = db.execute(stmt).scalars().first()
        if found_case:
            resolved_case_id = found_case.id

    attachment_id = str(uuid.uuid4())
    file_path = os.path.join(STORAGE_DIR, f"{attachment_id}.enc")

    try:
        with open(file_path, "wb") as f:
            f.write(content)

        attachment = CaseAttachment(
            id=attachment_id,
            case_id=resolved_case_id,
            ciphertext_path=file_path,
            size_bytes=len(content),
        )
        db.add(attachment)

        if resolved_case_id:
            record_audit_event(
                db=db,
                case_id=resolved_case_id,
                event_type=AuditEventType.ATTACHMENT_ADDED,
                payload_data={
                    "attachment_id": attachment_id,
                    "size_bytes": len(content),
                },
            )

        db.commit()
        db.refresh(attachment)
    except Exception:
        db.rollback()
        if os.path.exists(file_path):
            try:
                os.remove(file_path)
            except OSError:
                pass
        raise

    return CaseAttachmentUploadResponse(
        attachment_id=attachment.id,
        size_bytes=attachment.size_bytes,
        created_at=attachment.created_at,
    )


@router.get(
    "/attachments/{attachment_id}",
    summary="Download Blind Encrypted Evidence Attachment",
    description="Streams the raw encrypted blob with strict security headers preventing browser execution (Anti-XSS).",
)
def download_attachment(
    attachment_id: str,
    db: Session = Depends(get_db),
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

    # 2. Strict canonical path containment (Path Traversal prevention)
    resolved_storage_dir = os.path.abspath(STORAGE_DIR)
    resolved_file_path = os.path.abspath(attachment.ciphertext_path)

    try:
        is_contained = os.path.commonpath([resolved_file_path, resolved_storage_dir]) == resolved_storage_dir
    except ValueError:
        is_contained = False

    if not is_contained:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access Denied: Path traversal detected.",
        )

    if not os.path.isfile(resolved_file_path):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Attachment file not found on disk.",
        )

    return FileResponse(
        path=resolved_file_path,
        media_type="application/octet-stream",
        headers={
            "Content-Disposition": 'attachment; filename="evidence.enc"',
            "X-Content-Type-Options": "nosniff",
            "Cache-Control": "no-store",
        },
    )


@router.get(
    "/{case_id}/audit-verify",
    response_model=AuditVerificationResponse,
    summary="Verify Tamper-Evident BLAKE2b Audit Chain",
    description="Verifies the cryptographic integrity of the hash chain from Genesis to latest state.",
)
def verify_audit(
    case_id: str,
    db: Session = Depends(get_db),
) -> AuditVerificationResponse:
    case = db.get(Case, case_id)
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Case with ID '{case_id}' was not found.",
        )

    result = verify_case_audit_chain(db, case_id)
    return AuditVerificationResponse(
        is_valid=result["is_valid"],
        events_count=result["events_count"],
        broken_at=result.get("broken_at"),
        latest_hash=result.get("latest_hash"),
        reason=result.get("reason"),
    )


@router.post(
    "/lookup",
    response_model=CaseAccessResponseDto,
    summary="Lookup Case by Access Token Hash (No UUID Required)",
    description="Reporter queries case purely using their derived 12-word mnemonic token hash.",
)
@limiter.limit(LIMIT_LOOKUP_CASE)
def lookup_case(
    request: Request,
    payload: CaseAccessRequestDto,
    db: Session = Depends(get_db),
) -> CaseAccessResponseDto:
    stmt = select(Case).where(Case.case_access_token_hash == payload.case_access_token_hash)
    case = db.execute(stmt).scalars().first()
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Обращение с такой мнемонической фразой не найдено. Проверьте правильность введённых слов.",
        )

    # Constant-time comparison to ensure exact verification
    if not secrets.compare_digest(payload.case_access_token_hash, case.case_access_token_hash):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access Denied: Invalid case access token hash.",
        )

    messages = [CaseMessageDto.model_validate(m) for m in case.messages]

    return CaseAccessResponseDto(
        case_id=case.id,
        status=case.status,
        created_at=case.created_at,
        reporter_public_key=case.reporter_public_key,
        messages=messages,
    )


@router.post(
    "/messages",
    response_model=CaseMessageDto,
    status_code=status.HTTP_201_CREATED,
    summary="Submit Reporter Follow-Up Reply (By Access Token Hash)",
    description="Enables two-way encrypted dialogue. Reporter sends an authenticated follow-up message verified via caseAccessTokenHash.",
)
@limiter.limit(LIMIT_LOOKUP_CASE)
def add_reporter_message_by_hash(
    request: Request,
    payload: ReporterReplyDto,
    db: Session = Depends(get_db),
) -> CaseMessageDto:
    stmt = select(Case).where(Case.case_access_token_hash == payload.case_access_token_hash)
    case = db.execute(stmt).scalars().first()
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Case not found for the provided access token hash.",
        )

    if not secrets.compare_digest(payload.case_access_token_hash, case.case_access_token_hash):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access Denied: Invalid case access token hash.",
        )

    inv_pub = payload.investigator_public_key
    if not inv_pub:
        inv = db.execute(select(Investigator)).scalars().first()
        inv_pub = inv.public_key if inv else ""

    try:
        message = CaseMessage(
            case_id=case.id,
            encrypted_response=payload.encrypted_message,
            nonce=payload.nonce,
            investigator_public_key=inv_pub,
            sender_type="REPORTER",
        )
        case.status = CaseStatus.IN_REVIEW
        db.add(message)
        db.flush()

        record_audit_event(
            db=db,
            case_id=case.id,
            event_type=AuditEventType.MESSAGE_RECEIVED,
            payload_data={
                "message_id": message.id,
                "sender_type": "REPORTER",
                "nonce": message.nonce,
            },
        )
        record_audit_event(
            db=db,
            case_id=case.id,
            event_type=AuditEventType.STATUS_CHANGED,
            payload_data={
                "new_status": CaseStatus.IN_REVIEW.value,
            },
        )

        db.commit()
        db.refresh(message)
    except Exception:
        db.rollback()
        raise

    return CaseMessageDto.model_validate(message)


@router.post(
    "/{case_id}/access",
    response_model=CaseAccessResponseDto,
    summary="Access Case by ID and Access Token Hash",
    description="Verifies the reporter's caseAccessTokenHash using constant-time comparison and returns messages thread.",
)
@limiter.limit(LIMIT_LOOKUP_CASE)
def access_case(
    request: Request,
    case_id: str,
    payload: CaseAccessRequestDto,
    db: Session = Depends(get_db),
) -> CaseAccessResponseDto:
    case = db.get(Case, case_id)
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Case with ID '{case_id}' was not found.",
        )

    # Constant-time comparison to prevent timing attacks
    is_authorized = secrets.compare_digest(
        payload.case_access_token_hash,
        case.case_access_token_hash,
    )

    if not is_authorized:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access Denied: Invalid case access token hash.",
        )

    messages = [CaseMessageDto.model_validate(m) for m in case.messages]

    return CaseAccessResponseDto(
        case_id=case.id,
        status=case.status,
        created_at=case.created_at,
        reporter_public_key=case.reporter_public_key,
        messages=messages,
    )


@router.post(
    "/{case_id}/messages",
    response_model=CaseMessageDto,
    status_code=status.HTTP_201_CREATED,
    summary="Submit Reporter Follow-Up Reply by Case ID",
    description="Enables two-way encrypted dialogue. Reporter sends an authenticated follow-up message to investigator.",
)
@limiter.limit(LIMIT_LOOKUP_CASE)
def add_reporter_message(
    request: Request,
    case_id: str,
    payload: ReporterReplyDto,
    db: Session = Depends(get_db),
) -> CaseMessageDto:
    case = db.get(Case, case_id)
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Case with ID '{case_id}' was not found.",
        )

    if not secrets.compare_digest(payload.case_access_token_hash, case.case_access_token_hash):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access Denied: Invalid case access token hash.",
        )

    inv_pub = payload.investigator_public_key
    if not inv_pub:
        inv = db.execute(select(Investigator)).scalars().first()
        inv_pub = inv.public_key if inv else ""

    try:
        message = CaseMessage(
            case_id=case.id,
            encrypted_response=payload.encrypted_message,
            nonce=payload.nonce,
            investigator_public_key=inv_pub,
            sender_type="REPORTER",
        )
        case.status = CaseStatus.IN_REVIEW
        db.add(message)
        db.flush()

        record_audit_event(
            db=db,
            case_id=case.id,
            event_type=AuditEventType.MESSAGE_RECEIVED,
            payload_data={
                "message_id": message.id,
                "sender_type": "REPORTER",
                "nonce": message.nonce,
            },
        )
        record_audit_event(
            db=db,
            case_id=case.id,
            event_type=AuditEventType.STATUS_CHANGED,
            payload_data={
                "new_status": CaseStatus.IN_REVIEW.value,
            },
        )

        db.commit()
        db.refresh(message)
    except Exception:
        db.rollback()
        raise

    return CaseMessageDto.model_validate(message)
