"""Request and response bodies.

Declared separately from the ORM models so the wire format is deliberate: the
API returns the fields listed here and nothing else, which is what keeps
internal columns and token material from leaking into a response by accident.
"""

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, EmailStr, Field


class LoginLinkRequest(BaseModel):
    """POST /auth/request-link. EmailStr rejects malformed addresses."""

    email: EmailStr


class VerifyLinkRequest(BaseModel):
    """POST /auth/verify. Both values come from the emailed link."""

    request_id: str
    token: str


class OnboardingRequest(BaseModel):
    """POST /users/onboarding. Age is bounded to match the database constraint."""

    age: int = Field(ge=13, le=120)


class MessageResponse(BaseModel):
    """A plain acknowledgement, used where there is nothing to return."""

    message: str


class UserResponse(BaseModel):
    """The public view of a user. No tokens, no internal session data."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    email: EmailStr
    age: int | None
    status: str
    created_at: datetime


class SessionResponse(BaseModel):
    """What a successful verify or refresh returns.

    The access token is in the body for the client to keep in memory. The
    refresh token is not here at all -- it goes back as an HttpOnly cookie, so
    it never passes through JavaScript.
    """

    access_token: str
    id_token: str
    token_type: str
    expires_in: int
    expires_at: datetime
    user: UserResponse
