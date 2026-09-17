"""The session layer: magic-link records, user sync, and session lifecycle.

All state changes around authentication live here so routes stay thin and there
is one place to audit. Nothing in this module writes a token to the database in
readable form; everything is hashed on the way in.
"""

import hashlib
import secrets
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi import Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import settings
from app.models import AccountStatus, LoginRequest, User, UserSession, utcnow


def hash_token(raw_token: str) -> str:
    """Return the SHA-256 hex digest used to store a token for later comparison.

    A plain hash is the right tool here, not a password hash: these values are
    long random strings rather than guessable secrets, so there is nothing for
    an attacker to brute force and no need for a slow KDF.
    """
    return hashlib.sha256(raw_token.encode()).hexdigest()


def tokens_match(raw_token: str, stored_hash: str) -> bool:
    """Compare a presented token against a stored hash in constant time."""
    return secrets.compare_digest(hash_token(raw_token), stored_hash)


# --- Magic links ---------------------------------------------------------


def create_login_request(db: Session, email: str, cognito_session: str, raw_token: str) -> LoginRequest:
    """Record a pending magic link and return it.

    Stores only the hash of the emailed token, plus the Cognito challenge
    session needed to answer later. Expired rows are cleared first so the table
    does not accumulate dead links.
    """
    db.query(LoginRequest).filter(LoginRequest.expires_at <= utcnow()).delete(synchronize_session=False)

    login_request = LoginRequest(
        email=email,
        cognito_session=cognito_session,
        token_hash=hash_token(raw_token),
        expires_at=utcnow() + timedelta(seconds=settings.LOGIN_LINK_TTL_SECONDS),
    )
    db.add(login_request)
    db.flush()
    return login_request


def consume_login_request(db: Session, request_id: str, raw_token: str) -> LoginRequest | None:
    """Claim a pending magic link, or return None if it cannot be used.

    Returns None when the id is unknown, the link has expired or already been
    redeemed, or the presented token does not match the stored hash. On success
    the row is marked consumed immediately, so the same link cannot be redeemed
    twice even if two requests arrive together.
    """
    try:
        parsed_id = uuid.UUID(request_id)
    except (ValueError, AttributeError):
        return None

    login_request = db.get(LoginRequest, parsed_id)
    if login_request is None or not login_request.is_redeemable():
        return None
    if not tokens_match(raw_token, login_request.token_hash):
        return None

    login_request.consumed_at = utcnow()
    db.flush()
    return login_request


# --- Users ---------------------------------------------------------------


def sync_user(db: Session, cognito_sub: str, email: str) -> tuple[User, bool]:
    """Find or create the local user for a Cognito identity.

    Returns (user, created). Lookup is by cognito_sub, which never changes, with
    a fallback to the email address so a record created before the sub was known
    is adopted rather than duplicated. A returning user therefore signs in
    through exactly the same path without gaining a second account.
    """
    user = db.scalar(select(User).where(User.cognito_sub == cognito_sub))
    if user is not None:
        # Keep the mirrored email in step if it changed in Cognito.
        if user.email != email:
            user.email = email
            db.flush()
        return user, False

    existing_by_email = db.scalar(select(User).where(User.email == email))
    if existing_by_email is not None:
        existing_by_email.cognito_sub = cognito_sub
        db.flush()
        return existing_by_email, False

    user = User(
        cognito_sub=cognito_sub,
        email=email,
        status=AccountStatus.ONBOARDING_PENDING.value,
    )
    db.add(user)
    db.flush()
    return user, True


def complete_onboarding(db: Session, user: User, age: int) -> User:
    """Save the age and promote the account to active.

    The only transition onboarding performs. A disabled account is never
    promoted; callers check that before getting here.
    """
    user.age = age
    user.status = AccountStatus.ACTIVE.value
    db.flush()
    return user


# --- Sessions ------------------------------------------------------------


def _client_metadata(request: Request | None) -> tuple[str | None, str | None]:
    """Pull a coarse user-agent and client IP off the request, if available."""
    if request is None:
        return None, None
    agent = request.headers.get("user-agent")
    # Trust the proxy header only for display; nothing security-relevant keys
    # off this value.
    forwarded = request.headers.get("x-forwarded-for")
    ip = forwarded.split(",")[0].strip() if forwarded else (request.client.host if request.client else None)
    return (agent[:512] if agent else None), (ip[:45] if ip else None)


def create_session(
    db: Session,
    user: User,
    refresh_token: str,
    expires_in: int,
    request: Request | None = None,
) -> UserSession:
    """Open a session for a user who has just authenticated.

    Records when the issued access token expires and when the refresh token
    will, so a stale session can be recognised without asking Cognito.
    """
    agent, ip = _client_metadata(request)
    now = utcnow()
    session = UserSession(
        user_id=user.id,
        refresh_token_hash=hash_token(refresh_token),
        access_token_expires_at=now + timedelta(seconds=expires_in),
        refresh_token_expires_at=now + timedelta(days=settings.REFRESH_TOKEN_TTL_DAYS),
        last_used_at=now,
        user_agent=agent,
        ip_address=ip,
    )
    db.add(session)
    db.flush()
    return session


def find_session(db: Session, session_id: str, refresh_token: str) -> UserSession | None:
    """Look up the session a pair of cookies refers to, or None.

    Both cookies must agree: the id must name a live session and the refresh
    token must hash to the value stored on it. That pairing means a stolen
    session id alone is useless, and a refresh token replayed against a rotated
    session fails because the stored hash has already moved on.
    """
    try:
        parsed_id = uuid.UUID(session_id)
    except (ValueError, AttributeError):
        return None

    session = db.get(UserSession, parsed_id)
    if session is None or not session.is_usable():
        return None
    if not tokens_match(refresh_token, session.refresh_token_hash):
        return None
    return session


def rotate_session(db: Session, session: UserSession, refresh_token: str, expires_in: int) -> UserSession:
    """Record a successful refresh against an existing session.

    Updates the stored hash to the token Cognito just returned, which retires
    the previous one, and moves the access-token expiry and last-used stamp
    forward. Rotation reuses the row so a long-lived login stays one session.
    """
    now = utcnow()
    session.refresh_token_hash = hash_token(refresh_token)
    session.access_token_expires_at = now + timedelta(seconds=expires_in)
    session.last_used_at = now
    db.flush()
    return session


def revoke_session(db: Session, session: UserSession) -> None:
    """Mark a session unusable, keeping the row for audit purposes.

    Revoking rather than deleting means a later refresh attempt is answered as
    a revoked session instead of an unknown one.
    """
    session.revoked_at = utcnow()
    db.flush()


def revoke_all_sessions(db: Session, user: User) -> int:
    """Revoke every live session for a user and return how many were closed."""
    now = utcnow()
    live = db.scalars(
        select(UserSession).where(UserSession.user_id == user.id, UserSession.revoked_at.is_(None))
    ).all()
    for session in live:
        session.revoked_at = now
    db.flush()
    return len(live)


def access_expiry(expires_in: int) -> datetime:
    """When an access token issued now with this lifetime will expire."""
    return datetime.now(UTC) + timedelta(seconds=expires_in)


def authentication_result(response: dict[str, Any]) -> dict[str, Any] | None:
    """Pull AuthenticationResult out of a Cognito reply, or None if absent."""
    result = response.get("AuthenticationResult")
    return result if isinstance(result, dict) else None
