"use client";

import { useEffect, useState } from "react";

import { landingPathFor, setAccessToken, type User } from "@/lib/auth";

const apiUrl = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";

export default function CallbackPage() {
  const [error, setError] = useState("");

  useEffect(() => {
    async function verify() {
      // The emailed link carries both halves of the credential: request_id
      // names the pending login the server is holding, token is the secret
      // answer. Parsed in here rather than in the effect body so no state is
      // set synchronously during the effect.
      const params = new URLSearchParams(window.location.search);
      const requestId = params.get("request_id");
      const token = params.get("token");
      if (!requestId || !token) {
        setError("This sign-in link is incomplete.");
        return;
      }

      // Redeems the link once. credentials: "include" matters here: the reply
      // sets the HttpOnly session cookies, and without it the browser would
      // discard them and the session would not survive this page.
      try {
        const response = await fetch(`${apiUrl}/auth/verify`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          credentials: "include",
          body: JSON.stringify({ request_id: requestId, token }),
        });
        const data = await response.json().catch(() => ({}));
        if (!response.ok) {
          throw new Error(data.detail ?? "This sign-in link is invalid or expired.");
        }

        // Held in memory only, and never logged.
        setAccessToken(data.access_token as string);

        // The status decides where they go: a brand new account finishes
        // onboarding first, an existing one goes straight to the dashboard.
        const user = data.user as User;
        window.location.replace(landingPathFor(user));
      } catch (requestError) {
        setError(
          requestError instanceof TypeError
            ? `Could not reach the API at ${apiUrl}. Is the backend running?`
            : requestError instanceof Error
              ? requestError.message
              : "Verification failed.",
        );
      }
    }
    void verify();
  }, []);

  return (
    <main className="flex min-h-screen items-center justify-center px-6">
      <div className="w-full max-w-md border border-[#c6c8bd] bg-[#fffdf8] p-8 text-center">
        <p className="text-xs font-bold uppercase tracking-[0.22em] text-[#66805a]">MyApp / Access</p>
        <h1 className="mt-8 text-3xl">{error ? "Link unavailable" : "Confirming your sign-in..."}</h1>
        {error && (
          <>
            <p className="mt-3 text-[#7e2826]">{error}</p>
            <a href="/login" className="mt-6 inline-block font-bold text-[#21452d] underline">
              Request a new link
            </a>
          </>
        )}
      </div>
    </main>
  );
}
