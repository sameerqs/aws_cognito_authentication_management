import base64
import hashlib
import hmac
from typing import Any

from app.aws import get_client
from app.config import settings


def _cognito() -> Any:
    """Return the shared Cognito Identity Provider client.

    Built on first call and cached in app.aws, so no connection or credential
    lookup happens per request.
    """
    return get_client("cognito-idp")


def secret_hash(username: str) -> str:
    """Compute the SECRET_HASH that Cognito requires from clients with a secret.

    Cognito expects an HMAC-SHA256 of (username + client id) keyed by the client
    secret, base64 encoded. App clients configured with a secret reject auth
    calls that omit it, which surfaces as NotAuthorizedException.
    """
    digest = hmac.new(
        settings.COGNITO_CLIENT_SECRET.encode(),
        (username + settings.COGNITO_CLIENT_ID).encode(),
        hashlib.sha256,
    ).digest()
    return base64.b64encode(digest).decode()


def initiate_auth(email: str) -> dict[str, Any]:
    """Begin the CUSTOM_AUTH flow and return Cognito's first challenge.

    Triggers the pool's DefineAuthChallenge and CreateAuthChallenge Lambdas. The
    reply carries a Session string, which must be passed back when answering,
    and ChallengeParameters, where those Lambdas place the magic_token.
    Needs no IAM credentials: InitiateAuth is an unsigned Cognito operation.
    """
    return _cognito().initiate_auth(
        ClientId=settings.COGNITO_CLIENT_ID,
        AuthFlow="CUSTOM_AUTH",
        AuthParameters={"USERNAME": email, "SECRET_HASH": secret_hash(email)},
    )


def respond_to_challenge(email: str, session: str, token: str) -> dict[str, Any]:
    """Answer the custom challenge and, on success, receive the user's tokens.

    Sends the token from the emailed link as the ANSWER, which the pool's
    VerifyAuthChallengeResponse Lambda checks. A correct answer returns an
    AuthenticationResult holding the access, ID and refresh tokens; a wrong one
    returns no AuthenticationResult. Also an unsigned operation.
    """
    return _cognito().respond_to_auth_challenge(
        ClientId=settings.COGNITO_CLIENT_ID,
        ChallengeName="CUSTOM_CHALLENGE",
        Session=session,
        ChallengeResponses={
            "USERNAME": email,
            "ANSWER": token,
            "SECRET_HASH": secret_hash(email),
        },
    )


def get_user(email: str) -> dict[str, Any] | None:
    """Look up a user in the pool, returning None when they do not exist.

    UserNotFoundException is the expected answer for a first-time sign-in, so it
    is translated to None rather than raised. Every other error propagates.
    This is an admin operation and does require IAM credentials with
    cognito-idp:AdminGetUser.
    """
    client = _cognito()
    try:
        return client.admin_get_user(UserPoolId=settings.COGNITO_USER_POOL_ID, Username=email)
    except client.exceptions.UserNotFoundException:
        return None


def create_user(email: str) -> dict[str, Any]:
    """Create a passwordless user with their email address as the username.

    MessageAction="SUPPRESS" stops Cognito sending its own invitation mail, since
    this app sends the magic link itself. Users created this way have no password
    and land in FORCE_CHANGE_PASSWORD status, which is fine for custom auth
    because the challenge Lambdas never check a password.
    Requires cognito-idp:AdminCreateUser.
    """
    return _cognito().admin_create_user(
        UserPoolId=settings.COGNITO_USER_POOL_ID,
        Username=email,
        UserAttributes=[{"Name": "email", "Value": email}],
        MessageAction="SUPPRESS",
    )


def get_authenticated_user(access_token: str) -> dict[str, Any]:
    """Resolve an access token to its user, returning Username and attributes.

    Cognito itself validates the token, so an expired or forged one raises
    NotAuthorizedException. Authorised by the token alone, not by IAM.
    """
    return _cognito().get_user(AccessToken=access_token)


def refresh_tokens(refresh_token: str) -> dict[str, Any]:
    """Exchange a refresh token for a new access and ID token.

    Uses GetTokensFromRefreshToken rather than the older REFRESH_TOKEN_AUTH
    flow, because that flow is unsafe once the app client has refresh token
    rotation switched on: it can return a token that has already been retired.
    This operation is rotation-aware, and when rotation is enabled the reply
    carries a brand new refresh token that replaces the one just used.

    The client secret is sent directly here; unlike the auth flows, this
    operation takes no SECRET_HASH. Raises NotAuthorizedException when the
    refresh token has expired, been revoked, or was already rotated away.
    """
    return _cognito().get_tokens_from_refresh_token(
        RefreshToken=refresh_token,
        ClientId=settings.COGNITO_CLIENT_ID,
        ClientSecret=settings.COGNITO_CLIENT_SECRET,
    )


def revoke_refresh_token(refresh_token: str) -> None:
    """Ask Cognito to invalidate a refresh token and everything derived from it.

    Best effort on purpose. A token that is already expired or revoked makes
    this call fail, and logout must still succeed locally in that case, so the
    caller is expected to swallow those errors. Requires token revocation to be
    enabled on the app client, otherwise Cognito answers
    UnsupportedOperationException.
    """
    _cognito().revoke_token(
        Token=refresh_token,
        ClientId=settings.COGNITO_CLIENT_ID,
        ClientSecret=settings.COGNITO_CLIENT_SECRET,
    )
