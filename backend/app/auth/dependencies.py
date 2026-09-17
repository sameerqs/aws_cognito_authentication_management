"""The authentication dependency used by every protected route.

This is the only place a request's Authorization header is turned into a user.
Routes declare `user: User = Depends(get_current_user)` and receive a loaded,
vetted User or never run at all, so no route repeats token validation and none
can accidentally skip a check.
"""

import logging

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.auth.tokens import TokenError, verify_access_token
from app.db import get_db
from app.models import AccountStatus, User

logger = logging.getLogger(__name__)

# auto_error=False so a missing header arrives here and gets this module's own
# 401 rather than FastAPI's default message.
bearer_scheme = HTTPBearer(auto_error=False, description="Cognito access token")

# Sent once for every rejected request. Deliberately identical whatever went
# wrong, so a caller cannot distinguish an expired token from a forged one.
_UNAUTHORIZED = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Invalid or expired access token",
    headers={"WWW-Authenticate": "Bearer"},
)


def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    db: Session = Depends(get_db),
) -> User:
    """Resolve the bearer token on the request to the user it belongs to.

    Validates the token locally against the pool's JWKS, then loads the user
    whose cognito_sub matches the token's `sub`. A token that is absent,
    malformed, expired, signed by the wrong key, issued by another pool, issued
    to another client, or is an ID token rather than an access token all fail
    the same way: 401.

    An account with no local row also gets 401, because a valid Cognito token
    for someone who never finished creating an account is not a usable identity
    here. A disabled account gets 403: the credential is genuine, the account
    simply is not allowed in.

    Accounts still in onboarding_pending are returned successfully, so the
    frontend can read their status from /users/me and send them to onboarding.
    Routes that need a fully onboarded account use get_active_user instead.
    """
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise _UNAUTHORIZED

    try:
        claims = verify_access_token(credentials.credentials)
    except TokenError as error:
        # The reason is logged, never returned. No token material is logged.
        logger.info("Access token rejected: %s", error)
        raise _UNAUTHORIZED from error

    cognito_sub = claims.get("sub")
    if not cognito_sub:
        raise _UNAUTHORIZED

    user = db.scalar(select(User).where(User.cognito_sub == cognito_sub))
    if user is None:
        logger.info("Valid token for unknown local user sub=%s", cognito_sub)
        raise _UNAUTHORIZED

    if user.is_disabled:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This account has been disabled",
        )

    return user


def get_active_user(user: User = Depends(get_current_user)) -> User:
    """Require a fully onboarded account.

    For application routes that need a complete profile. Answers 403 with a
    machine-readable code so the frontend can redirect to onboarding instead of
    treating it as a dead end.
    """
    if user.status != AccountStatus.ACTIVE:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"code": "onboarding_required", "message": "Finish onboarding to continue"},
        )
    return user
