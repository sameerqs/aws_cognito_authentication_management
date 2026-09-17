# Cognito magic-link demo

A FastAPI backend and Next.js frontend implementing passwordless sign-in over
Cognito CUSTOM_AUTH, with a session layer on top:

```
/login -> email link -> /auth/callback -> session cookies + access token
       -> /onboarding (first time) -> /dashboard
```

## How authentication works

Cognito authenticates the user; PostgreSQL holds the profile and the session.

1. `POST /auth/request-link` creates the Cognito user if new, starts CUSTOM_AUTH,
   and emails a one-time link. The pending link is stored in `login_requests`
   with only a **hash** of the token.
2. `POST /auth/verify` redeems the link, creates or matches the local user by
   `cognito_sub`, and opens a session. A new account starts as
   `onboarding_pending` and gets the account-created email.
3. The **access token** is returned in the response body for the client to hold
   in memory. The **refresh token** goes back as an `HttpOnly` cookie and is
   never exposed to JavaScript. Only its hash reaches the database.
4. `POST /auth/refresh` trades the cookie for a new access token via
   `GetTokensFromRefreshToken`, which is rotation-safe. Rotation replaces the
   stored hash, retiring the previous token.
5. `POST /auth/logout` revokes the session, clears the cookies, and asks Cognito
   to revoke the refresh token. The user row is kept.

Access tokens are validated locally against the pool's JWKS, checking signature,
`iss`, `exp`, `token_use=access` and `client_id`. That happens in exactly one
place, `get_current_user`, which every protected route depends on.

| Endpoint | Auth |
| --- | --- |
| `POST /auth/request-link` | public |
| `POST /auth/verify` | magic link |
| `POST /auth/refresh` | refresh cookie |
| `POST /auth/logout` | refresh cookie (idempotent) |
| `GET /users/me` | `get_current_user` |
| `POST /users/onboarding` | `get_current_user` |
| `GET /users/me/sessions` | `get_active_user` |

### Account status

`onboarding_pending` -> `active` once the age is saved; `disabled` is refused at
the door with 403. The frontend reads `status` from `/users/me` after signing in
to decide between the onboarding screen and the dashboard.

## Backend

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate          # or call .venv/bin/uvicorn directly
pip install -r requirements.txt

sudo -u postgres createuser --pwprompt cognito_app
sudo -u postgres createdb -O cognito_app cognito_auth

cp .env.example .env               # then fill it in
uvicorn app.main:app --reload --port 8000
```

Tables are created at startup. `backend/schema.sql` is the same schema as
reference and as a starting point for a real migration.

The Cognito app client must allow `CUSTOM_AUTH`, have a client secret, issue
refresh tokens, and have token revocation enabled for logout to reach Cognito.
The pool's custom-auth Lambda triggers must return `magic_token` in
`ChallengeParameters` and validate the submitted `ANSWER`. The IAM identity needs
`cognito-idp:AdminGetUser` and `cognito-idp:AdminCreateUser`.

## Frontend

```bash
cd frontend
cp .env.example .env.local
npm run dev
```

Open http://localhost:3000. All API calls go through `lib/auth.ts`, which keeps
the access token in memory, sends `credentials: "include"` so the session
cookies travel, and refreshes once on a 401 before giving up.

## Security notes

- Access tokens are never written to PostgreSQL, and no token of any kind is
  logged.
- Magic-link and refresh tokens are stored as SHA-256 hashes only.
- Refresh tokens live in `HttpOnly` cookies, never in `localStorage`.
- Set `COOKIE_SECURE=true` in any environment served over HTTPS. If the frontend
  and API are on different domains, `COOKIE_SAMESITE` must be `none` as well.
- Logout revokes only the session that presented the cookies. Revoking every
  session for a user is available as `revoke_all_sessions` but is not wired to an
  endpoint.
