import uuid
from datetime import datetime
from pydantic import BaseModel, ConfigDict, Field
from pydantic.alias_generators import to_camel

from models import CaseStatus


class CamelModel(BaseModel):
    """
    Base model ensuring camelCase serialization and deserialization
    for strict conformity with TypeScript contracts in poc.ts.
    """
    model_config = ConfigDict(
        alias_generator=to_camel,
        populate_by_name=True,
        from_attributes=True,
    )


# ---------------------------------------------------------------------------
# Case DTOs
# ---------------------------------------------------------------------------

class CreateCaseDto(CamelModel):
    """
    DTO sent by the anonymous reporter client to create a new case.
    """
    case_id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="Client-generated or server-assigned UUID v4",
    )
    reporter_public_key: str = Field(
        ...,
        min_length=1,
        description="Base64 encoded X25519 public key of the reporter",
    )
    case_access_token_hash: str = Field(
        ...,
        min_length=1,
        description="Base64 encoded BLAKE2b hash of the case_access_token",
    )
    encrypted_report: str = Field(
        ...,
        min_length=1,
        description="Base64 encoded crypto_box_seal anonymous sealed box ciphertext",
    )


class CaseCreatedResponse(CamelModel):
    """
    Response returned after case submission.
    """
    case_id: str
    status: CaseStatus
    created_at: datetime


class CaseAccessRequestDto(CamelModel):
    """
    Payload sent by reporter to authenticate and read case details and messages.
    """
    case_access_token_hash: str = Field(
        ...,
        min_length=1,
        description="Base64 encoded BLAKE2b hash derived from reporter's 12-word mnemonic",
    )


class CaseMessageDto(CamelModel):
    """
    Encrypted message DTO between investigator and reporter.
    """
    id: str
    case_id: str
    encrypted_response: str
    nonce: str
    investigator_public_key: str
    sender_type: str = "INVESTIGATOR"
    sender: str = "INVESTIGATOR"
    created_at: datetime


class ReporterReplyDto(CamelModel):
    """
    DTO sent by reporter to submit a follow-up message in an existing case.
    """
    case_access_token_hash: str = Field(
        ...,
        min_length=1,
        description="Base64 encoded token hash derived from 12 words",
    )
    encrypted_message: str = Field(
        ...,
        description="Base64 encoded ciphertext encrypted with crypto_box_easy",
    )
    nonce: str = Field(
        ...,
        description="Base64 encoded 24-byte nonce",
    )
    investigator_public_key: str | None = Field(
        default=None,
        description="Optional Base64 encoded investigator public key (inferred from DB if omitted)",
    )



class CaseAccessResponseDto(CamelModel):
    """
    Response for authorized reporter containing case status and decrypted message thread.
    """
    case_id: str
    status: CaseStatus
    created_at: datetime
    reporter_public_key: str
    messages: list[CaseMessageDto] = []


# ---------------------------------------------------------------------------
# Investigator DTOs
# ---------------------------------------------------------------------------

class InvestigatorPublicKeyResponse(CamelModel):
    """
    Public key retrieval response for anonymous submission.
    """
    investigator_id: str
    username: str
    public_key: str


class InvestigatorCaseListItem(CamelModel):
    """
    Case summary representation for the investigator dashboard.
    """
    id: str
    reporter_public_key: str
    encrypted_report: str
    status: CaseStatus
    created_at: datetime
    message_count: int = 0


class InvestigatorResponseDto(CamelModel):
    """
    DTO sent by the investigator to encrypt and send a reply to a case.
    """
    case_id: str = Field(
        ...,
        description="UUID of the case being responded to",
    )
    encrypted_response: str = Field(
        ...,
        min_length=1,
        description="Base64 encoded crypto_box_easy ciphertext with Poly1305 MAC",
    )
    nonce: str = Field(
        ...,
        min_length=1,
        description="Base64 encoded 24-byte crypto_box_NONCEBYTES",
    )
    investigator_public_key: str = Field(
        ...,
        min_length=1,
        description="Base64 encoded X25519 public key of the investigator",
    )


class InvestigatorAccountDto(CamelModel):
    """
    Full Zero-Knowledge investigator record (for client-side login & private key decryption).
    """
    id: str
    username: str
    public_key: str
    encrypted_private_key: str
    private_key_nonce: str
    kdf_salt: str
    kdf_ops_limit: int
    kdf_mem_limit: int
    kdf_algorithm: int
    created_at: datetime
