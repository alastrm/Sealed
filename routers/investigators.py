import uuid
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from audit_service import record_audit_event
from database import get_db
from models import AuditEventType, Case, CaseMessage, CaseStatus, Investigator
from rate_limiter import LIMIT_AUTH, limiter
from schemas import (
    CaseMessageDto,
    InvestigatorAccountDto,
    InvestigatorCaseListItem,
    InvestigatorPublicKeyResponse,
    InvestigatorResponseDto,
)

router = APIRouter(prefix="/api/v1/investigators", tags=["Investigators"])


@router.get(
    "/public-key",
    response_model=InvestigatorPublicKeyResponse,
    summary="Get Investigator Public Key",
    description="Returns the X25519 public key of the investigator so the reporter can encrypt the report via crypto_box_seal.",
)
def get_investigator_public_key(
    username: str | None = Query(None, description="Optional username filter"),
    db: Session = Depends(get_db),
) -> InvestigatorPublicKeyResponse:
    query = select(Investigator)
    if username:
        query = query.where(Investigator.username == username)
    investigator = db.execute(query).scalars().first()

    if not investigator:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No active investigator found in the system.",
        )

    return InvestigatorPublicKeyResponse(
        investigator_id=investigator.id,
        username=investigator.username,
        public_key=investigator.public_key,
    )


@router.get(
    "/account",
    response_model=InvestigatorAccountDto,
    summary="Get Encrypted Investigator Account Blob (Zero-Knowledge Login)",
    description="Returns the encrypted private key blob, KDF salt, and limits for client-side password decryption.",
)
@limiter.limit(LIMIT_AUTH)
def get_investigator_account(
    request: Request,
    username: str | None = Query(None, description="Username of the investigator"),
    db: Session = Depends(get_db),
) -> InvestigatorAccountDto:
    query = select(Investigator)
    if username:
        query = query.where(Investigator.username == username)
    investigator = db.execute(query).scalars().first()

    if not investigator:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Investigator account not found.",
        )

    return InvestigatorAccountDto.model_validate(investigator)


@router.get(
    "/cases",
    response_model=list[InvestigatorCaseListItem],
    summary="List All Cases for Investigators",
    description="Returns all whistleblower cases with ciphertext reports and status.",
)
def list_investigator_cases(
    db: Session = Depends(get_db),
) -> list[InvestigatorCaseListItem]:
    stmt = (
        select(Case)
        .order_by(desc(Case.created_at))
    )
    cases = db.execute(stmt).scalars().all()

    result = []
    for c in cases:
        result.append(
            InvestigatorCaseListItem(
                id=c.id,
                reporter_public_key=c.reporter_public_key,
                encrypted_report=c.encrypted_report,
                status=c.status,
                created_at=c.created_at,
                message_count=len(c.messages),
            )
        )
    return result


@router.get(
    "/cases/{case_id}/messages",
    response_model=list[CaseMessageDto],
    summary="Get All Messages in a Case Thread",
    description="Returns all authenticated messages exchanged between investigator and reporter for this case.",
)
def get_case_messages(
    case_id: str,
    db: Session = Depends(get_db),
) -> list[CaseMessageDto]:
    case = db.get(Case, case_id)
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Case with ID '{case_id}' was not found.",
        )
    return [CaseMessageDto.model_validate(m) for m in case.messages]


@router.post(
    "/cases/{case_id}/messages",
    response_model=CaseMessageDto,
    status_code=status.HTTP_201_CREATED,
    summary="Submit Investigator Response",
    description="Saves authenticated encrypted response from investigator to reporter and marks case as RESPONDED.",
)
def create_investigator_response(
    case_id: str,
    payload: InvestigatorResponseDto,
    db: Session = Depends(get_db),
) -> CaseMessageDto:
    case = db.get(Case, case_id)
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Case with ID '{case_id}' was not found.",
        )

    # Persist the authenticated encrypted message
    message = CaseMessage(
        id=str(uuid.uuid4()),
        case_id=case_id,
        encrypted_response=payload.encrypted_response,
        nonce=payload.nonce,
        investigator_public_key=payload.investigator_public_key,
        sender_type="INVESTIGATOR",
    )
    db.add(message)
    db.flush()

    record_audit_event(
        db=db,
        case_id=case.id,
        event_type=AuditEventType.MESSAGE_RECEIVED,
        payload_data={
            "message_id": message.id,
            "sender_type": "INVESTIGATOR",
            "nonce": message.nonce,
        },
    )
    record_audit_event(
        db=db,
        case_id=case.id,
        event_type=AuditEventType.STATUS_CHANGED,
        payload_data={
            "new_status": CaseStatus.RESPONDED.value,
        },
    )

    # Transition case status to RESPONDED
    case.status = CaseStatus.RESPONDED

    db.commit()
    db.refresh(message)

    return CaseMessageDto.model_validate(message)

