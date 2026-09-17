"""Local verification of Cognito access tokens against the pool's JWKS.

Verifying locally means a protected route costs no network call to AWS: the
signing keys are fetched once from the pool's well-known JWKS endpoint, cached,
and reused. Only the signature and claims decide whether a token is accepted,
so a forged or edited token fails here rather than deeper in the app.

This module is the single place that understands token formats. Routes never
decode a token themselves.
"""

from typing import Any

import jwt
from jwt import PyJWKClient

from app.config import settings


class TokenError(Exception):
    """An access token was missing, malformed, expired or not acceptable.

    Carries a short reason for the logs. The reason is never returned to the
    caller, who only ever sees a generic 401, so a probe cannot learn which
    specific check failed.
    """


# Claims that must be present before the values are even looked at. A token
# lacking any of them is rejected outright rather than treated as a default.
_REQUIRED_CLAIMS = ["exp", "iat", "sub", "iss", "token_use", "client_id"]

# Built lazily so importing this module never performs network I/O, and cached
# for the process so the JWKS is fetched once rather than per request.
_jwk_client: PyJWKClient | None = None


def _get_jwk_client() -> PyJWKClient:
    """Return the process-wide JWKS client, creating it on first use."""
    global _jwk_client
    if _jwk_client is None:
        _jwk_client = PyJWKClient(
            settings.cognito_jwks_url,
            cache_keys=True,
            cache_jwk_set=True,
            lifespan=3600,
            timeout=10,
        )
    return _jwk_client


def _signing_key(token: str) -> Any:
    """Find the public key that matches this token's `kid` header.

    Kept separate so tests can substitute a key without reaching the network.
    """
    return _get_jwk_client().get_signing_key_from_jwt(token).key


def verify_access_token(token: str) -> dict[str, Any]:
    """Validate a Cognito access token and return its claims.

    Checks, in order: the RS256 signature against the pool's published key, the
    issuer, the expiry, that this is an access token rather than an ID token,
    and that it was issued to this app client. Any failure raises TokenError.

    token_use is checked explicitly because ID tokens from the same pool carry a
    valid signature and issuer; accepting one in an Authorization header would
    let a client authenticate with a token never meant for API access.
    """
    if not token or token.count(".") != 2:
        raise TokenError("not a well-formed JWT")

    try:
        key = _signing_key(token)
    except jwt.PyJWKClientError as error:
        raise TokenError(f"no usable signing key: {error}") from error

    try:
        claims: dict[str, Any] = jwt.decode(
            token,
            key,
            algorithms=["RS256"],
            issuer=settings.cognito_issuer,
            # Cognito access tokens identify the client in `client_id`, not
            # `aud`, so audience verification is done by hand below.
            options={"require": _REQUIRED_CLAIMS, "verify_aud": False},
        )
    except jwt.ExpiredSignatureError as error:
        raise TokenError("token expired") from error
    except jwt.InvalidIssuerError as error:
        raise TokenError("issuer mismatch") from error
    except jwt.MissingRequiredClaimError as error:
        raise TokenError(f"missing claim: {error.claim}") from error
    except jwt.InvalidTokenError as error:
        raise TokenError(f"invalid token: {error}") from error

    if claims.get("token_use") != "access":
        raise TokenError(f"wrong token_use: {claims.get('token_use')!r}")
    if claims.get("client_id") != settings.COGNITO_CLIENT_ID:
        raise TokenError("client_id mismatch")

    return claims
