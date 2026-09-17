"""ORM models: the user record, their sessions, and pending magic links.

Three deliberate choices run through this file:

* No token is ever stored in readable form. Magic-link tokens and refresh
  tokens are kept as SHA-256 hashes, which is enough to check that a value
  presented later is the one issued earlier.
* Access tokens are not stored at all, in any form. They are short-lived and
  the client holds them in memory.
* cognito_sub is the identity the application keys off, not the email address.
  Cognito's `sub` never changes; an email address can.
"""

import enum
import uuid
from datetime import UTC, datetime

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    Uuid,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db import Base


class AccountStatus(enum.StrEnum):
    """Lifecycle of an account.

    ONBOARDING_PENDING: authenticated with Cognito but has not given their age.
    ACTIVE: fully onboarded, allowed into the application.
    DISABLED: retained in the database but refused at the door.
    """

    ONBOARDING_PENDING = "onboarding_pending"
    ACTIVE = "active"
    DISABLED = "disabled"


def utcnow() -> datetime:
    """Timezone-aware now. Naive datetimes cause silent comparison bugs."""
    return datetime.now(UTC)


class User(Base):
    """An application user, mirrored from Cognito and holding the profile.

    Created the first time someone completes a magic-link sign-in. The only
    profile fields this product needs are the email address and the age; age
    stays null until onboarding is finished.
    """

    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    cognito_sub: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    email: Mapped[str] = mapped_column(String(320), unique=True, nullable=False, index=True)
    age: Mapped[int | None] = mapped_column(Integer, nullable=True)
    status: Mapped[str] = mapped_column(
        String(32), nullable=False, default=AccountStatus.ONBOARDING_PENDING.value
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now()
    )

    sessions: Mapped[list["UserSession"]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )

    __table_args__ = (
        CheckConstraint(
            "status IN ('onboarding_pending', 'active', 'disabled')", name="ck_users_status"
        ),
        CheckConstraint("age IS NULL OR (age >= 13 AND age <= 120)", name="ck_users_age_range"),
    )

    @property
    def is_active(self) -> bool:
        """True only for fully onboarded accounts."""
        return self.status == AccountStatus.ACTIVE

    @property
    def is_disabled(self) -> bool:
        """True when the account has been turned off and must be refused."""
        return self.status == AccountStatus.DISABLED


class UserSession(Base):
    """Metadata for one logged-in session, backed by a Cognito refresh token.

    The refresh token itself lives in an HttpOnly cookie on the client; only its
    hash is here, so a database dump cannot be replayed to mint access tokens.
    Rotation updates the hash in place rather than creating a new row, which
    keeps one row per real session.
    """

    __tablename__ = "user_sessions"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    # SHA-256 hex of the refresh token currently valid for this session.
    refresh_token_hash: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    # When the access token last issued for this session stops working. Recorded
    # so the client can be told, not because the server trusts it.
    access_token_expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    refresh_token_expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    last_used_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # Coarse client fingerprint, useful when showing a user their sessions.
    user_agent: Mapped[str | None] = mapped_column(String(512), nullable=True)
    ip_address: Mapped[str | None] = mapped_column(String(45), nullable=True)

    user: Mapped["User"] = relationship(back_populates="sessions")

    __table_args__ = (Index("ix_user_sessions_user_revoked", "user_id", "revoked_at"),)

    def is_usable(self, now: datetime | None = None) -> bool:
        """True while this session may still be refreshed."""
        now = now or utcnow()
        return self.revoked_at is None and self.refresh_token_expires_at > now


class LoginRequest(Base):
    """A magic link that has been emailed but not yet redeemed.

    Replaces the in-memory dict this app used to keep, which lost every pending
    login on each restart and could not be shared between workers. Holds the
    Cognito Session string that must be handed back when answering the custom
    challenge, and a hash of the emailed token -- never the token itself.
    """

    __tablename__ = "login_requests"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    email: Mapped[str] = mapped_column(String(320), nullable=False, index=True)
    # Cognito's opaque challenge session. Long, hence Text.
    cognito_session: Mapped[str] = mapped_column(Text, nullable=False)
    token_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    def is_redeemable(self, now: datetime | None = None) -> bool:
        """True while this link may still be exchanged for tokens."""
        now = now or utcnow()
        return self.consumed_at is None and self.expires_at > now
