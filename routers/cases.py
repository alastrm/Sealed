import secrets
from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from database import get_db
from models import Case, CaseMessage, CaseStatus, Investigator
from rate_limiter import LIMIT_CREATE_CASE, LIMIT_LOOKUP_CASE, limiter
from schemas import (
    CaseAccessRequestDto,
    CaseAccessResponseDto,
    CaseCreatedResponse,
    CaseMessageDto,
    CreateCaseDto,
    ReporterReplyDto,
)

router = APIRouter(prefix="/api/v1/cases", tags=["Cases"])


@router.post(
    "",
    response_model=CaseCreatedResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Submit New Whistleblower Case",
    description="Accepts an anonymous encrypted report, stores it with OPEN status, and links it to reporter's token hash.",
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

    case = Case(
        id=payload.case_id,
        case_access_token_hash=payload.case_access_token_hash,
        reporter_public_key=payload.reporter_public_key,
        encrypted_report=payload.encrypted_report,
        status=CaseStatus.OPEN,
    )
    db.add(case)
    db.commit()
    db.refresh(case)

    return CaseCreatedResponse(
        case_id=case.id,
        status=case.status,
        created_at=case.created_at,
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

    message = CaseMessage(
        case_id=case.id,
        encrypted_response=payload.encrypted_message,
        nonce=payload.nonce,
        investigator_public_key=inv_pub,
        sender_type="REPORTER",
    )
    case.status = CaseStatus.IN_REVIEW
    db.add(message)
    db.commit()
    db.refresh(message)

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

    message = CaseMessage(
        case_id=case.id,
        encrypted_response=payload.encrypted_message,
        nonce=payload.nonce,
        investigator_public_key=inv_pub,
        sender_type="REPORTER",
    )
    case.status = CaseStatus.IN_REVIEW
    db.add(message)
    db.commit()
    db.refresh(message)

    return CaseMessageDto.model_validate(message)
