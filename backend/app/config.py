from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Every value the app reads from the environment.

    Reads backend/.env on startup. Any field without a default is required, so a
    missing one fails loudly at import time rather than mid-request. Unknown keys
    in .env are ignored.
    """

    ENABLE_EMAIL: bool = True

    # --- Database -----------------------------------------------------------
    DATABASE_URL: str
    # Echoes SQL to the log. Development aid only.
    DB_ECHO: bool = False

    # --- AWS ----------------------------------------------------------------
    AWS_REGION: str
    # Optional. Leave blank to use the default boto3 credential chain
    # (~/.aws/credentials, real environment variables, or an IAM role in Lambda).
    AWS_PROFILE: str | None = None
    AWS_ACCESS_KEY_ID: str | None = None
    AWS_SECRET_ACCESS_KEY: str | None = None
    AWS_SESSION_TOKEN: str | None = None

    # --- Cognito ------------------------------------------------------------
    COGNITO_USER_POOL_ID: str
    COGNITO_CLIENT_ID: str
    COGNITO_CLIENT_SECRET: str

    # --- Sessions and cookies ----------------------------------------------
    # How long a magic link stays valid.
    LOGIN_LINK_TTL_SECONDS: int = 600
    # Must not exceed the app client's configured refresh token validity, or
    # local sessions will outlive the Cognito token backing them.
    REFRESH_TOKEN_TTL_DAYS: int = 30
    SESSION_COOKIE_NAME: str = "session_id"
    REFRESH_COOKIE_NAME: str = "refresh_token"
    # Secure must be true wherever the site is served over HTTPS; it is false by
    # default only so the cookies work on http://localhost during development.
    COOKIE_SECURE: bool = False
    # "lax" is enough while the frontend and API share a site (localhost:3000
    # and localhost:8000 do, because ports are not part of a site). Split them
    # across domains and this must become "none", which also requires Secure.
    COOKIE_SAMESITE: str = "lax"
    COOKIE_DOMAIN: str | None = None

    # --- Email --------------------------------------------------------------
    EMAIL_HOST: str
    EMAIL_PORT: int = 587
    EMAIL_USER: str
    EMAIL_PASS: str
    EMAIL_FROM: str

    FRONTEND_URL: str = "http://localhost:3000"

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    @property
    def cognito_issuer(self) -> str:
        """The `iss` claim every token from this pool must carry."""
        return f"https://cognito-idp.{self.AWS_REGION}.amazonaws.com/{self.COGNITO_USER_POOL_ID}"

    @property
    def cognito_jwks_url(self) -> str:
        """Where the pool publishes the public keys used to sign its tokens."""
        return f"{self.cognito_issuer}/.well-known/jwks.json"


settings = Settings()
