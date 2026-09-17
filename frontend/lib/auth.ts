/**
 * The frontend's single authentication client.
 *
 * Where the tokens live, and why:
 *
 * - The access token is held in a module variable, never in localStorage or
 *   sessionStorage. It is short-lived, and keeping it out of storage means a
 *   cross-site scripting bug cannot read it back later.
 * - The refresh token is never touched by this code at all. It arrives as an
 *   HttpOnly cookie that JavaScript cannot read, which is why every request
 *   below sends `credentials: "include"`.
 *
 * Because the access token lives in memory, a full page load starts with none.
 * That is handled by asking /auth/refresh for a new one on first use, which
 * works precisely because the cookie survives the navigation. No token is ever
 * logged.
 */

const apiUrl = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";

export type AccountStatus = "onboarding_pending" | "active" | "disabled";

export interface User {
  id: string;
  email: string;
  age: number | null;
  status: AccountStatus;
  created_at: string;
}

let accessToken: string | null = null;
// Concurrent 401s must not each trigger their own refresh: with rotation
// enabled the second call would present a token the first has already
// retired, killing a perfectly good session. They share this promise instead.
let refreshInFlight: Promise<string | null> | null = null;

export function setAccessToken(token: string | null): void {
  accessToken = token;
}

export function hasAccessToken(): boolean {
  return accessToken !== null;
}

/** Ask the server for a new access token using the refresh cookie. */
async function refreshAccessToken(): Promise<string | null> {
  if (refreshInFlight) return refreshInFlight;

  refreshInFlight = (async () => {
    try {
      const response = await fetch(`${apiUrl}/auth/refresh`, {
        method: "POST",
        credentials: "include",
      });
      if (!response.ok) {
        // 401 here means the session is genuinely over: expired, revoked or
        // already rotated. The server has cleared the cookies.
        accessToken = null;
        return null;
      }
      const data = await response.json();
      accessToken = data.access_token as string;
      return accessToken;
    } catch {
      // Network failure, not an auth failure. Leave any existing token alone.
      return null;
    } finally {
      refreshInFlight = null;
    }
  })();

  return refreshInFlight;
}

/**
 * Call the API as the signed-in user.
 *
 * Obtains an access token if there isn't one, attaches it, and on a 401 makes
 * exactly one refresh-and-retry attempt before giving up. The single retry is
 * what keeps an expired access token invisible to the rest of the app.
 */
export async function apiFetch(
  path: string,
  init: RequestInit = {},
  allowRetry = true,
): Promise<Response> {
  const token = accessToken ?? (await refreshAccessToken());

  const response = await fetch(`${apiUrl}${path}`, {
    ...init,
    credentials: "include",
    headers: {
      ...(init.body ? { "Content-Type": "application/json" } : {}),
      ...(init.headers ?? {}),
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
  });

  if (response.status === 401 && allowRetry) {
    const renewed = await refreshAccessToken();
    if (renewed) return apiFetch(path, init, false);
  }

  return response;
}

/** Fetch the signed-in user, or null if the session is over. */
export async function fetchCurrentUser(): Promise<User | null> {
  const response = await apiFetch("/users/me");
  if (response.status === 401 || response.status === 403) return null;
  if (!response.ok) throw new Error(`Could not load your account (${response.status})`);
  return (await response.json()) as User;
}

/** End the session and return to the sign-in screen. */
export async function logout(): Promise<void> {
  try {
    await fetch(`${apiUrl}/auth/logout`, { method: "POST", credentials: "include" });
  } finally {
    // Always forget the token locally, even if the call failed.
    accessToken = null;
    window.location.replace("/login");
  }
}

/** Where a user with this status belongs. */
export function landingPathFor(user: User): string {
  return user.status === "active" ? "/dashboard" : "/onboarding";
}
