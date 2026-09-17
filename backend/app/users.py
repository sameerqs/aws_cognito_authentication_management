"""User-facing routes. Every one of them is protected by get_current_user.

None of these functions look at a token. They declare the dependency and
receive a loaded User, which is what keeps token handling in one place.
"""

import logging

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.auth import sessions as session_service
from app.auth.dependencies import get_active_user, get_current_user
from app.db import get_db
from app.models import User
from app.schemas import OnboardingRequest, UserResponse

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/users", tags=["Users"])


@router.get("/me", response_model=UserResponse)
def read_current_user(user: User = Depends(get_current_user)) -> UserResponse:
    """Return the signed-in user's profile.

    Uses get_current_user rather than get_active_user on purpose: this is the
    endpoint the frontend calls immediately after authenticating to find out
    where to send someone, so it has to answer for an account that is still in
    onboarding_pending. The status field in the response is what decides
    between the onboarding screen and the dashboard.
    """
    return UserResponse.model_validate(user)


@router.post("/onboarding", response_model=UserResponse)
def complete_onboarding(
    data: OnboardingRequest,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> UserResponse:
    """Save the age and finish onboarding, moving the account to active.

    Only valid for an account that has not onboarded yet; calling it again
    answers 409 rather than silently overwriting a profile, since this route
    exists to complete signup and not to edit a profile later.
    """
    if user.is_active:
        raise HTTPException(status_code=409, detail="Onboarding is already complete")

    session_service.complete_onboarding(db, user=user, age=data.age)
    db.commit()
    logger.info("Onboarding completed for user=%s", user.id)
    return UserResponse.model_validate(user)


@router.get("/me/sessions")
def list_sessions(user: User = Depends(get_active_user)) -> dict[str, object]:
    """List the user's live sessions.

    An example of an ordinary protected application route: it uses
    get_active_user, so a half-onboarded account is turned away with the
    onboarding_required code instead of seeing application data. Returns
    metadata only -- no token material is stored, so none can be exposed.
    """
    live = [s for s in user.sessions if s.is_usable()]
    return {
        "count": len(live),
        "sessions": [
            {
                "id": str(s.id),
                "created_at": s.created_at,
                "last_used_at": s.last_used_at,
                "access_token_expires_at": s.access_token_expires_at,
                "refresh_token_expires_at": s.refresh_token_expires_at,
                "user_agent": s.user_agent,
                "ip_address": s.ip_address,
            }
            for s in sorted(live, key=lambda s: s.last_used_at, reverse=True)
        ],
    }
