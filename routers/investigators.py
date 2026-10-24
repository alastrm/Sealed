import uuid
import json
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import desc, select
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError

from history_service import append_history, prepare_mutation, history_version, hash_value, lock_case
from message_protocol import canonical_uuid
from models import CaseHistoryEvent
from schemas import CaseTransitionDto
from database import get_db
from models import AuditEventType, Case, CaseMessage, CaseStatus, Investigator, InvestigatorIdentity
from rate_limiter import LIMIT_AUTH, limiter
from investigator_auth import require_investigator
from message_protocol import read_only, validate_reply
from attachment_service import claim_attachments, owner_hash
from routers import cases as case_routes
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

    identity = db.execute(select(InvestigatorIdentity).where(
        InvestigatorIdentity.investigator_id == investigator.id,
        InvestigatorIdentity.active == 1,
    )).scalars().first()
    return InvestigatorPublicKeyResponse(
        investigator_id=investigator.id, username=investigator.username,
        public_key=identity.public_key if identity else investigator.public_key,
        protocol_version=2 if identity else 1,
        signing_public_key=identity.signing_public_key if identity else None,
        identity_signature=identity.identity_signature if identity else None,
    )


@router.get('/identities')
def investigator_identities(
    db: Session = Depends(get_db),
    investigator: Investigator = Depends(require_investigator),
) -> list[dict]:
    identities = db.execute(select(InvestigatorIdentity).where(
        InvestigatorIdentity.investigator_id == investigator.id,
    ).order_by(InvestigatorIdentity.active.desc())).scalars().all()
    return [dict(json.loads(item.encrypted_bundle), active=bool(item.active)) for item in identities]



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
    investigator: Investigator = Depends(require_investigator),
) -> InvestigatorAccountDto:
    if username is not None and username != investigator.username:
        raise HTTPException(403, "This session cannot access another investigator account.")
    return InvestigatorAccountDto.model_validate(investigator)


@router.get(
    "/cases",
    response_model=list[InvestigatorCaseListItem],
    summary="List All Cases for Investigators",
    description="Returns all whistleblower cases with ciphertext reports and status.",
)
def list_investigator_cases(
    db: Session = Depends(get_db),
    investigator: Investigator = Depends(require_investigator),
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
                protocol_version=c.protocol_version, manifest=c.manifest,
                read_only=read_only(db, c) or c.status == CaseStatus.CLOSED,
                revision=history_version(db, c.id),
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
    investigator: Investigator = Depends(require_investigator),
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
    investigator: Investigator = Depends(require_investigator),
) -> CaseMessageDto:
    if payload.case_id != case_id:
        raise HTTPException(400, "The case ID must match the request path.")
    case = db.get(Case, case_id)
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Case with ID '{case_id}' was not found.",
        )

    case = prepare_mutation(db, case_id, case_routes.STORAGE_DIR)
    validate_reply(db, case, payload, 'INVESTIGATOR', payload.encrypted_response, investigator)
    previous_status = case.status.value

    try:
        # Persist the authenticated encrypted message
        message = CaseMessage(
            id=payload.message_id, protocol_version=2, signature=payload.signature,
            case_id=case_id,
            encrypted_response=payload.encrypted_response,
            nonce=payload.nonce,
            investigator_public_key=case.manifest['investigatorPublicKey'],
            sender_type="INVESTIGATOR",
        )
        db.add(message)
        db.flush()
        claim_attachments(db, payload.attachment_ids, case.id, owner_hash('investigator', investigator.id), case_routes.STORAGE_DIR)

        case.status = CaseStatus.RESPONDED
        append_history(db, case, case_routes.STORAGE_DIR, 'MESSAGE_RECEIVED',
            'INVESTIGATOR:' + investigator.id, from_status=previous_status)

        db.commit()
        db.refresh(message)
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, 'Duplicate message ID rejected.') from None
    except Exception:
        db.rollback()
        raise

    return CaseMessageDto.model_validate(message)



# Content is immutable while CLOSED; explicit reopening resumes the same signed identities.
TRANSITIONS = {
    CaseStatus.OPEN: {CaseStatus.IN_REVIEW, CaseStatus.CLOSED},
    CaseStatus.IN_REVIEW: {CaseStatus.CLOSED},
    CaseStatus.RESPONDED: {CaseStatus.IN_REVIEW, CaseStatus.CLOSED},
    CaseStatus.CLOSED: {CaseStatus.IN_REVIEW},
}


@router.post('/cases/{case_id}/status')
def transition_case(case_id: str, payload: CaseTransitionDto, db: Session = Depends(get_db),
                    investigator: Investigator = Depends(require_investigator)):
    canonical_uuid(payload.request_id)
    digest = hash_value([case_id, payload.expected_revision, payload.target_status.value, investigator.id])
    case = lock_case(db, case_id)
    previous = db.scalar(select(CaseHistoryEvent).where(CaseHistoryEvent.request_id == payload.request_id))
    if previous:
        if previous.case_id != case_id or previous.request_digest != digest:
            raise HTTPException(409, 'Transition ID belongs to a different operation.')
        return {'caseId': case.id, 'status': case.status.value, 'revision': history_version(db, case.id)}
    if payload.expected_revision != history_version(db, case.id):
        raise HTTPException(409, 'Case changed. Refresh before changing its status.')
    if read_only(db, case):
        raise HTTPException(409, 'Archived/legacy cases are READ-ONLY.')
    identity = db.get(InvestigatorIdentity, case.manifest['investigatorSigningPublicKey'])
    if identity.investigator_id != investigator.id:
        raise HTTPException(403, 'Case identity does not belong to this Investigator.')
    if payload.target_status not in TRANSITIONS[case.status]:
        raise HTTPException(409, 'Invalid case status transition.')
    case = prepare_mutation(db, case.id, case_routes.STORAGE_DIR, allow_closed=True)
    before = case.status.value
    case.status = payload.target_status
    append_history(db, case, case_routes.STORAGE_DIR, 'STATUS_CHANGED', 'INVESTIGATOR:' + investigator.id,
        from_status=before, request_id=payload.request_id, request_digest=digest)
    db.commit()
    return {'caseId': case.id, 'status': case.status.value, 'revision': history_version(db, case.id)}
