"""The authentication endpoints.

The magic-link CUSTOM_AUTH flow is unchanged in substance: request a link, click
it, answer Cognito's custom challenge. What is new around it is a session layer,
so a signed-in user keeps their session through short-lived access tokens and a
rotating refresh token in an HttpOnly cookie, and never has to request another
link until they log out or the refresh token finally expires.

No token value is ever logged in this module.
"""

import logging

from botocore.exceptions import ClientError
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy.orm import Session

from app.auth import sessions as session_service
from app.auth.cognito import (
    create_user,
    get_user,
    initiate_auth,
    refresh_tokens,
    respond_to_challenge,
    revoke_refresh_token,
)
from app.auth.cookies import clear_session_cookies, read_session_cookies, set_session_cookies
from app.auth.email import send_account_created, send_magic_link
from app.db import get_db
from app.schemas import LoginLinkRequest, MessageResponse, SessionResponse, UserResponse, VerifyLinkRequest

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth", tags=["Authentication"])

# Cognito's way of saying a refresh token is expired, revoked, already rotated,
# or otherwise no longer usable. All of them mean the same thing to us: this
# session is finished and the user must request a new magic link.
_DEAD_REFRESH_TOKEN_CODES = {
    "NotAuthorizedException",
    "InvalidParameterException",
    "ResourceNotFoundException",
    "UserNotFoundException",
}

_SESSION_ENDED = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Session expired, please sign in again",
)


@router.post("/request-link", response_model=MessageResponse)
def request_link(
    data: LoginLinkRequest,
    db: Session = Depends(get_db),
) -> MessageResponse:
    """Start a login: create the Cognito user if new, then email a magic link.

    Unchanged in behaviour from the original implementation apart from where the
    pending link is kept. Looks the user up in Cognito and creates them on first
    sign-in, starts the CUSTOM_AUTH flow, and lets the pool's Lambda triggers
    mint a one-time magic_token.

    The pending link now lives in the login_requests table instead of a
    process-local dict, which means it survives a restart and works with more
    than one worker, and only a hash of the token is stored.

    The reply is identical whether or not the address exists, so this endpoint
    cannot be used to find out who has an account.
    """
    email = str(data.email).lower().strip()

    if not get_user(email):
        create_user(email)

    response = initiate_auth(email)
    if response.get("ChallengeName") != "CUSTOM_CHALLENGE":
        raise HTTPException(status_code=400, detail="Cognito custom challenge was not returned")
    token = response.get("ChallengeParameters", {}).get("magic_token")
    if not token:
        raise HTTPException(status_code=500, detail="Magic token was not returned by Cognito")

    login_request = session_service.create_login_request(
        db, email=email, cognito_session=response["Session"], raw_token=token
    )
    request_id = str(login_request.id)
    db.commit()

    send_magic_link(email=email, token=token, request_id=request_id)
    return MessageResponse(message="If the request is valid, a sign-in link has been sent.")


@router.post("/verify", response_model=SessionResponse)
def verify_link(
    data: VerifyLinkRequest,
    response: Response,
    request: Request,
    db: Session = Depends(get_db),
) -> SessionResponse:
    """Redeem a magic link: authenticate, sync the user, and open a session.

    Claims the pending link, which checks the presented token against the stored
    hash and marks it consumed so it cannot be reused, then answers Cognito's
    custom challenge with it. On success Cognito returns the token set.

    The local user record is created or matched here by cognito_sub, so a
    returning user signs in through this same path without getting a second
    account. A brand new account starts in onboarding_pending and is sent the
    account-created email.

    The refresh token leaves as an HttpOnly cookie; the access token is returned
    in the body for the client to hold in memory.
    """
    login_request = session_service.consume_login_request(db, data.request_id, data.token)
    if login_request is None:
        # Commit so the consumed marker on a replayed link is not rolled back.
        db.commit()
        raise HTTPException(status_code=401, detail="Invalid or expired login link")

    cognito_response = respond_to_challenge(
        login_request.email, login_request.cognito_session, data.token
    )
    authentication = session_service.authentication_result(cognito_response)
    if not authentication:
        db.commit()
        raise HTTPException(status_code=401, detail="Authentication failed")

    refresh_token = authentication.get("RefreshToken")
    if not refresh_token:
        # Without one there is nothing to build a session on; the app client must
        # be configured to issue refresh tokens.
        raise HTTPException(status_code=500, detail="Cognito did not return a refresh token")

    # The access token is the authority on who this is: it carries the sub.
    claims = _claims_without_reverification(authentication["AccessToken"])
    user, created = session_service.sync_user(
        db, cognito_sub=claims["sub"], email=login_request.email
    )

    expires_in = int(authentication.get("ExpiresIn", 3600))
    session = session_service.create_session(
        db, user=user, refresh_token=refresh_token, expires_in=expires_in, request=request
    )
    db.commit()

    set_session_cookies(response, session_id=str(session.id), refresh_token=refresh_token)

    if created:
        # Best effort: the account exists whether or not this email goes out.
        try:
            send_account_created(user.email)
        except Exception:
            logger.warning("Account-created email failed for a new user", exc_info=True)

    logger.info("Session opened for user=%s new_account=%s", user.id, created)
    return SessionResponse(
        access_token=authentication["AccessToken"],
        id_token=authentication["IdToken"],
        token_type=authentication.get("TokenType", "Bearer"),
        expires_in=expires_in,
        expires_at=session.access_token_expires_at,
        user=UserResponse.model_validate(user),
    )


@router.post("/refresh", response_model=SessionResponse)
def refresh_session(
    response: Response,
    request: Request,
    db: Session = Depends(get_db),
) -> SessionResponse:
    """Trade the refresh cookie for a new access token, without a new magic link.

    Reads both cookies, requires them to agree with a live session row, then
    asks Cognito for a fresh token set. With rotation enabled Cognito returns a
    new refresh token, whose hash replaces the old one, retiring it; the cookies
    are rewritten either way.

    If Cognito refuses the refresh token for any reason -- expired, revoked,
    already rotated -- the local session is revoked, the cookies are cleared and
    the answer is 401, which is the frontend's signal to send the user back to
    the magic-link screen.
    """
    session_id, refresh_token = read_session_cookies(request)
    if not session_id or not refresh_token:
        raise _SESSION_ENDED

    session = session_service.find_session(db, session_id, refresh_token)
    if session is None:
        db.commit()
        clear_session_cookies(response)
        raise _SESSION_ENDED

    try:
        cognito_response = refresh_tokens(refresh_token)
    except ClientError as error:
        code = error.response.get("Error", {}).get("Code", "")
        if code in _DEAD_REFRESH_TOKEN_CODES:
            session_service.revoke_session(db, session)
            db.commit()
            clear_session_cookies(response)
            logger.info("Refresh refused by Cognito (%s); session %s revoked", code, session.id)
            raise _SESSION_ENDED from error
        # Anything else is an upstream fault rather than a dead session, so the
        # session is left intact for the handlers in main.py to report.
        raise

    authentication = session_service.authentication_result(cognito_response)
    if not authentication:
        session_service.revoke_session(db, session)
        db.commit()
        clear_session_cookies(response)
        raise _SESSION_ENDED

    user = session.user
    if user.is_disabled:
        session_service.revoke_session(db, session)
        db.commit()
        clear_session_cookies(response)
        raise HTTPException(status_code=403, detail="This account has been disabled")

    # Rotation returns a new refresh token; if rotation is off, Cognito omits it
    # and the presented one stays valid.
    new_refresh_token = authentication.get("RefreshToken") or refresh_token
    expires_in = int(authentication.get("ExpiresIn", 3600))
    session_service.rotate_session(
        db, session=session, refresh_token=new_refresh_token, expires_in=expires_in
    )
    db.commit()

    set_session_cookies(response, session_id=str(session.id), refresh_token=new_refresh_token)

    return SessionResponse(
        access_token=authentication["AccessToken"],
        id_token=authentication.get("IdToken", ""),
        token_type=authentication.get("TokenType", "Bearer"),
        expires_in=expires_in,
        expires_at=session.access_token_expires_at,
        user=UserResponse.model_validate(user),
    )


@router.post("/logout", response_model=MessageResponse)
def logout(
    response: Response,
    request: Request,
    db: Session = Depends(get_db),
) -> MessageResponse:
    """End the session: revoke it locally, clear the cookies, keep the user.

    Deliberately idempotent and always successful. Someone logging out with
    cookies that are already dead still ends up logged out, so this never
    answers an error.

    The Cognito refresh token is revoked too where possible, which stops it
    being used again from anywhere else. That call is best effort: it needs
    token revocation enabled on the app client, and it fails harmlessly on a
    token that has already expired.

    The PostgreSQL user record is untouched.
    """
    session_id, refresh_token = read_session_cookies(request)

    if session_id and refresh_token:
        session = session_service.find_session(db, session_id, refresh_token)
        if session is not None:
            session_service.revoke_session(db, session)
            db.commit()
            logger.info("Session %s revoked by logout", session.id)

    if refresh_token:
        try:
            revoke_refresh_token(refresh_token)
        except ClientError as error:
            code = error.response.get("Error", {}).get("Code", "")
            logger.info("Cognito refresh-token revocation skipped (%s)", code)
        except Exception:
            logger.warning("Cognito refresh-token revocation failed", exc_info=True)

    clear_session_cookies(response)
    return MessageResponse(message="Signed out.")


def _claims_without_reverification(access_token: str) -> dict[str, object]:
    """Read the claims of a token Cognito just handed us, verifying it properly.

    Cognito minted this token seconds ago over TLS, but it is still put through
    the same verification as any inbound token rather than trusted on sight, so
    there is exactly one code path that decides what a token says.
    """
    from app.auth.tokens import verify_access_token

    return verify_access_token(access_token)
