"""Application entry point: middleware, routers, error handling, startup."""

import logging
from contextlib import asynccontextmanager

from botocore.exceptions import BotoCoreError, ClientError, NoCredentialsError, PartialCredentialsError
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.auth.router import router as auth_router
from app.config import settings
from app.db import create_all
from app.users import router as users_router

# Uvicorn configures only its own loggers, so without this the app's own INFO
# messages would never reach the console. No token material is ever logged.
logging.basicConfig(level=logging.INFO, format="%(levelname)s:     %(message)s")
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Create any missing tables before the first request is served."""
    create_all()
    logger.info("Database ready")
    yield


app = FastAPI(title="MyApp API", lifespan=lifespan)

# The browser calls this API from a different origin (:3000 -> :8000).
# allow_credentials is required for the session cookies to be sent at all, and
# it forbids a wildcard origin, so the frontend URL is named explicitly. A
# trailing slash would stop the origin matching, hence the rstrip.
app.add_middleware(
    CORSMiddleware,
    allow_origins=[settings.FRONTEND_URL.rstrip("/")],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.include_router(auth_router)
app.include_router(users_router)


@app.exception_handler(NoCredentialsError)
@app.exception_handler(PartialCredentialsError)
def aws_credentials_missing(request: Request, exc: Exception) -> JSONResponse:
    """Handle the case where boto3 found no usable credentials.

    The request never left the machine, so this is a local setup fault rather
    than an AWS failure.
    """
    return JSONResponse(
        status_code=503,
        content={
            "detail": "AWS credentials are not configured. Set AWS_ACCESS_KEY_ID and "
            "AWS_SECRET_ACCESS_KEY in .env, or configure ~/.aws/credentials."
        },
    )


@app.exception_handler(ClientError)
def aws_client_error(request: Request, exc: ClientError) -> JSONResponse:
    """Translate an error returned by AWS into a sensible status code.

    Rejected or under-permissioned credentials are a server-side configuration
    fault (503), token and user errors belong to the caller (401), and anything
    else is reported as a failed upstream call (502).
    """
    code = exc.response.get("Error", {}).get("Code", "UnknownError")
    if code in {"AccessDeniedException", "UnrecognizedClientException", "InvalidSignatureException"}:
        return JSONResponse(
            status_code=503,
            content={"detail": f"AWS rejected the request ({code}). Check the IAM user's keys and permissions."},
        )
    if code in {"NotAuthorizedException", "UserNotFoundException"}:
        return JSONResponse(status_code=401, content={"detail": "Authentication failed"})
    return JSONResponse(status_code=502, content={"detail": f"AWS request failed ({code})"})


@app.exception_handler(BotoCoreError)
def aws_transport_error(request: Request, exc: BotoCoreError) -> JSONResponse:
    """Handle failures that happened before AWS answered.

    Covers DNS, connection, timeout and client-configuration errors, none of
    which the caller can act on, so they become a plain 502.
    """
    return JSONResponse(status_code=502, content={"detail": "Could not reach AWS"})


@app.get("/health")
def health() -> dict[str, str]:
    """Liveness probe. Touches nothing external, so it answers even if AWS is down."""
    return {"status": "ok"}
