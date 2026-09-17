"""Reading and writing the authentication cookies.

Two cookies carry a session, and both are HttpOnly so no JavaScript on the page
can read them:

* session_id   -- which user_sessions row this browser is using.
* refresh_token -- the Cognito refresh token itself.

Keeping the refresh token in an HttpOnly cookie rather than localStorage is what
stops a cross-site scripting bug from walking away with long-lived credentials.
The access token is deliberately not a cookie: it is returned in the response
body for the client to hold in memory and send as a bearer header.
"""

from fastapi import Request, Response

from app.config import settings


def set_session_cookies(response: Response, session_id: str, refresh_token: str) -> None:
    """Attach the session and refresh cookies to an outgoing response.

    max_age matches the refresh token's lifetime so the browser discards them at
    roughly the moment the server would stop honouring them. Both are scoped to
    "/" because the refresh endpoint and the API routes sit on the same origin.
    """
    common = {
        "httponly": True,
        "secure": settings.COOKIE_SECURE,
        "samesite": settings.COOKIE_SAMESITE,
        "domain": settings.COOKIE_DOMAIN,
        "path": "/",
        "max_age": settings.REFRESH_TOKEN_TTL_DAYS * 24 * 60 * 60,
    }
    response.set_cookie(settings.SESSION_COOKIE_NAME, session_id, **common)
    response.set_cookie(settings.REFRESH_COOKIE_NAME, refresh_token, **common)


def clear_session_cookies(response: Response) -> None:
    """Delete both cookies.

    The attributes must match those used when setting them or some browsers keep
    the original cookie alongside the deletion.
    """
    for name in (settings.SESSION_COOKIE_NAME, settings.REFRESH_COOKIE_NAME):
        response.delete_cookie(
            name,
            path="/",
            domain=settings.COOKIE_DOMAIN,
            httponly=True,
            secure=settings.COOKIE_SECURE,
            samesite=settings.COOKIE_SAMESITE,
        )


def read_session_cookies(request: Request) -> tuple[str | None, str | None]:
    """Return (session_id, refresh_token) from the request, either may be None."""
    return (
        request.cookies.get(settings.SESSION_COOKIE_NAME),
        request.cookies.get(settings.REFRESH_COOKIE_NAME),
    )
