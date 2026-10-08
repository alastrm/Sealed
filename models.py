import enum
import uuid
from datetime import datetime, timezone
from sqlalchemy import DateTime, Enum as SQLEnum, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from database import Base


class CaseStatus(str, enum.Enum):
    OPEN = "OPEN"
    IN_REVIEW = "IN_REVIEW"
    RESPONDED = "RESPONDED"
    CLOSED = "CLOSED"


class AuditEventType(str, enum.Enum):
    CASE_CREATED = "CASE_CREATED"
    MESSAGE_RECEIVED = "MESSAGE_RECEIVED"
    ATTACHMENT_ADDED = "ATTACHMENT_ADDED"
    STATUS_CHANGED = "STATUS_CHANGED"


class Investigator(Base):
    """
    Investigator account record in Zero-Knowledge blind storage.
    Stores public key and password-encrypted private key blob.
    The server NEVER has access to raw passwords or decrypted private keys.
    """
    __tablename__ = "investigators"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    username: Mapped[str] = mapped_column(
        String(255), unique=True, index=True, nullable=False
    )
    public_key: Mapped[str] = mapped_column(Text, nullable=False)
    encrypted_private_key: Mapped[str] = mapped_column(Text, nullable=False)
    private_key_nonce: Mapped[str] = mapped_column(String(64), nullable=False)
    kdf_salt: Mapped[str] = mapped_column(String(64), nullable=False)
    kdf_ops_limit: Mapped[int] = mapped_column(Integer, nullable=False)
    kdf_mem_limit: Mapped[int] = mapped_column(Integer, nullable=False)
    kdf_algorithm: Mapped[int] = mapped_column(Integer, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )


class Case(Base):
    """
    Case record stored anonymously.
    Server stores BLAKE2b hash of access token for verification and ciphertext sealed report.
    """
    __tablename__ = "cases"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    case_access_token_hash: Mapped[str] = mapped_column(
        String(128), index=True, nullable=False
    )
    reporter_public_key: Mapped[str] = mapped_column(Text, nullable=False)
    encrypted_report: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[CaseStatus] = mapped_column(
        SQLEnum(CaseStatus, native_enum=False),
        default=CaseStatus.OPEN,
        nullable=False,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    messages: Mapped[list["CaseMessage"]] = relationship(
        "CaseMessage",
        back_populates="case",
        cascade="all, delete-orphan",
        order_by="CaseMessage.created_at.asc()",
    )
    attachments: Mapped[list["CaseAttachment"]] = relationship(
        "CaseAttachment",
        back_populates="case",
        cascade="all, delete-orphan",
        order_by="CaseAttachment.created_at.asc()",
    )
    audit_logs: Mapped[list["CaseAuditLog"]] = relationship(
        "CaseAuditLog",
        back_populates="case",
        cascade="all, delete-orphan",
        order_by="CaseAuditLog.sequence_number.asc()",
    )


class CaseMessage(Base):
    """
    Case message / response record.
    Ciphertext encrypted via authenticated crypto_box_easy.
    """
    __tablename__ = "case_messages"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    case_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("cases.id", ondelete="CASCADE"),
        index=True,
        nullable=False,
    )
    encrypted_response: Mapped[str] = mapped_column(Text, nullable=False)
    nonce: Mapped[str] = mapped_column(String(64), nullable=False)
    investigator_public_key: Mapped[str] = mapped_column(Text, nullable=False)
    sender_type: Mapped[str] = mapped_column(
        String(32), default="INVESTIGATOR", nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    case: Mapped["Case"] = relationship("Case", back_populates="messages")

    @property
    def sender(self) -> str:
        return self.sender_type

    @sender.setter
    def sender(self, val: str) -> None:
        self.sender_type = val


class CaseAttachment(Base):
    """
    Blind encrypted evidence attachment.
    The server stores only the raw ciphertext blob/path and size in bytes.
    Filenames, MIME types, and decryption keys NEVER exist on the server.
    """
    __tablename__ = "case_attachments"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    case_id: Mapped[str | None] = mapped_column(
        String(36),
        ForeignKey("cases.id", ondelete="CASCADE"),
        index=True,
        nullable=True,
    )
    ciphertext_path: Mapped[str] = mapped_column(Text, nullable=False)
    size_bytes: Mapped[int] = mapped_column(Integer, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    case: Mapped["Case | None"] = relationship("Case", back_populates="attachments")


class CaseAuditLog(Base):
    """
    Tamper-evident audit log entry in a cryptographic hash-chain.
    Guarantees non-repudiation and detects retroactive database tampering.
    """
    __tablename__ = "case_audit_logs"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    case_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("cases.id", ondelete="CASCADE"),
        index=True,
        nullable=False,
    )
    sequence_number: Mapped[int] = mapped_column(
        Integer,
        default=1,
        index=True,
        nullable=False,
    )
    event_type: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )
    payload_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    prev_event_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    current_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    case: Mapped["Case"] = relationship("Case", back_populates="audit_logs")
