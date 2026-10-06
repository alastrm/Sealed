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

