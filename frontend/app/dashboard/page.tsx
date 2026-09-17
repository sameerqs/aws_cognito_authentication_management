"use client";

import { useEffect, useState } from "react";

import { fetchCurrentUser, logout, type User } from "@/lib/auth";

/**
 * The signed-in application screen.
 *
 * Holds no token of its own: it asks the auth client for the user, which
 * obtains an access token from the refresh cookie if the page was just loaded.
 * A session that has genuinely ended sends the visitor back to /login; a
 * network failure reports itself instead, so an unreachable API is never
 * mistaken for being signed out.
 */
export default function DashboardPage() {
  const [user, setUser] = useState<User | null>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    async function load() {
      try {
        const current = await fetchCurrentUser();
        if (!current) {
          window.location.replace("/login");
          return;
        }
        if (current.status !== "active") {
          window.location.replace("/onboarding");
          return;
        }
        setUser(current);
      } catch (loadError) {
        setError(loadError instanceof Error ? loadError.message : "Something went wrong.");
      }
    }
    void load();
  }, []);

  return (
    <main className="min-h-screen px-6 py-12">
      <div className="mx-auto max-w-3xl">
        <div className="flex items-center justify-between border-b border-[#c6c8bd] pb-5">
          <p className="text-xs font-bold uppercase tracking-[0.22em] text-[#66805a]">
            MyApp / Dashboard
          </p>
          <button onClick={() => void logout()} className="text-sm font-bold underline">
            Sign out
          </button>
        </div>

        <section className="mt-20">
          {error ? (
            <>
              <p className="text-sm font-bold uppercase tracking-[0.18em] text-[#66805a]">
                Connection problem
              </p>
              <h1 className="mt-3 text-5xl">Can&apos;t load your account.</h1>
              <p className="mt-5 border-l-4 border-[#b94a48] bg-[#f7e4df] p-3 text-[#7e2826]">{error}</p>
              <button
                onClick={() => window.location.reload()}
                className="mt-6 inline-block font-bold text-[#21452d] underline"
              >
                Try again
              </button>
            </>
          ) : !user ? (
            <p className="text-xl text-[#667066]">Loading your account...</p>
          ) : (
            <>
              <p className="text-sm font-bold uppercase tracking-[0.18em] text-[#66805a]">
                Authenticated
              </p>
              <h1 className="mt-3 text-5xl">You&apos;re in.</h1>
              <dl className="mt-8 space-y-3 text-lg">
                <div className="flex gap-3">
                  <dt className="w-24 font-bold text-[#66805a]">Email</dt>
                  <dd className="text-[#17221b]">{user.email}</dd>
                </div>
                <div className="flex gap-3">
                  <dt className="w-24 font-bold text-[#66805a]">Age</dt>
                  <dd className="text-[#17221b]">{user.age ?? "not set"}</dd>
                </div>
                <div className="flex gap-3">
                  <dt className="w-24 font-bold text-[#66805a]">Status</dt>
                  <dd className="text-[#17221b]">{user.status}</dd>
                </div>
              </dl>
            </>
          )}
        </section>
      </div>
    </main>
  );
}
