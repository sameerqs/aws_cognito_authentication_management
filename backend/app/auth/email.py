import smtplib
from email.message import EmailMessage
from urllib.parse import urlencode

from app.config import settings


def send_magic_link(email: str, token: str, request_id: str) -> None:
    """Email the one-time sign-in link to the address that asked for it.

    Builds a link to the frontend's /auth/callback carrying the request_id and
    token, then sends it over SMTP with STARTTLS. Returns immediately without
    sending when ENABLE_EMAIL is false, which is the way to exercise the login
    flow without working mail credentials.

    Raises SMTPAuthenticationError on bad credentials; with Gmail this needs a
    16-character App Password, not the account password. The socket has an
    explicit timeout so unreachable mail servers fail instead of hanging the
    request forever.
    """
    if not settings.ENABLE_EMAIL:
        return

    query = urlencode({"request_id": request_id, "token": token})
    link = f"{settings.FRONTEND_URL.rstrip('/')}/auth/callback?{query}"
    message = EmailMessage()
    message["Subject"] = "Sign in to MyApp"
    message["From"] = settings.EMAIL_FROM
    message["To"] = email
    message.set_content(
        "Sign in to MyApp\n\n"
        f"Click the link below to continue:\n\n{link}\n\n"
        "This link expires shortly.\n\nIf you did not request this email, ignore this message.\n"
    )

    with smtplib.SMTP(settings.EMAIL_HOST, settings.EMAIL_PORT, timeout=15) as smtp:
        smtp.starttls()
        smtp.login(settings.EMAIL_USER, settings.EMAIL_PASS)
        smtp.send_message(message)


def send_account_created(email: str) -> None:
    """Tell a brand new user their account exists.

    Sent once, after the first successful magic-link sign-in creates the local
    record. Failure here must not fail the sign-in, so the caller treats it as
    best effort; the account has already been created by the time this runs.
    """
    if not settings.ENABLE_EMAIL:
        return

    message = EmailMessage()
    message["Subject"] = "Your MyApp account is ready"
    message["From"] = settings.EMAIL_FROM
    message["To"] = email
    message.set_content(
        "Welcome to MyApp\n\n"
        "Your account has been created and you are signed in.\n\n"
        "There is one step left: tell us your age to finish setting up your "
        f"profile.\n\n{settings.FRONTEND_URL.rstrip('/')}/onboarding\n\n"
        "You will sign in from now on with a one-time link, so there is no "
        "password to remember.\n"
    )

    with smtplib.SMTP(settings.EMAIL_HOST, settings.EMAIL_PORT, timeout=15) as smtp:
        smtp.starttls()
        smtp.login(settings.EMAIL_USER, settings.EMAIL_PASS)
        smtp.send_message(message)
