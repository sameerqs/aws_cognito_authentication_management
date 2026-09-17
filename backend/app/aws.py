"""Shared AWS session and client factory.

Credential resolution happens here, once, and nowhere else in the application.
Two modes are supported, in this order:

1. Explicit IAM user keys from .env (AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY).
   Convenient for local development, where keeping every setting in one file is
   easier than maintaining a separate ~/.aws/credentials.
2. The default boto3 provider chain, used whenever those are blank: real
   environment variables, ~/.aws/credentials (optionally AWS_PROFILE), then the
   IAM role attached to the runtime.

Mode 2 is what runs in Lambda: leave the key settings empty and the execution
role supplies short-lived credentials automatically, so no secret is deployed.
Nothing below is called per request -- the session and its clients are built
once and reused.
"""

from functools import lru_cache
from typing import Any

import boto3

from app.config import settings


@lru_cache(maxsize=1)
def get_session() -> boto3.session.Session:
    """Return the process-wide boto3 session, created on first use."""
    if settings.AWS_ACCESS_KEY_ID and settings.AWS_SECRET_ACCESS_KEY:
        return boto3.session.Session(
            region_name=settings.AWS_REGION,
            aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
            aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
            aws_session_token=settings.AWS_SESSION_TOKEN,
        )
    return boto3.session.Session(
        region_name=settings.AWS_REGION,
        profile_name=settings.AWS_PROFILE,
    )


@lru_cache(maxsize=None)
def get_client(service_name: str) -> Any:
    """Return a cached client. Clients are thread-safe and meant to be reused."""
    return get_session().client(service_name)
