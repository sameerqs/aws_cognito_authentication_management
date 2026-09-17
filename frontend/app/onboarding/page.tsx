"use client";

import { FormEvent, useEffect, useState } from "react";

import { apiFetch, fetchCurrentUser, logout } from "@/lib/auth";

/**
 * The one onboarding step: collect the age and activate the account.
 *
 * Reached straight after a first sign-in, when the account is still
 * onboarding_pending. Anyone who arrives here already active is sent on to the
 * dashboard, and anyone without a live session goes back to /login.
 */
export default function OnboardingPage() {
  const [email, setEmail] = useState("");
  const [age, setAge] = useState("");
  const [loading, setLoading] = useState(false);
  const [checking, setChecking] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    async function load() {
      try {
        const user = await fetchCurrentUser();
        if (!user) {
          window.location.replace("/login");
          return;
        }
        if (user.status === "active") {
          window.location.replace("/dashboard");
          return;
        }
        setEmail(user.email);
        setChecking(false);
      } catch (loadError) {
        setError(loadError instanceof Error ? loadError.message : "Something went wrong.");
        setChecking(false);
      }
    }
    void load();
  }, []);

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setLoading(true);
    setError("");

    try {
      const response = await apiFetch("/users/onboarding", {
        method: "POST",
        body: JSON.stringify({ age: Number(age) }),
      });
      if (response.status === 401) {
        window.location.replace("/login");
        return;
      }
      if (!response.ok) {
        const data = await response.json().catch(() => ({}));
        const detail = typeof data.detail === "string" ? data.detail : "Could not save your details.";
        throw new Error(detail);
      }
      window.location.replace("/dashboard");
    } catch (submitError) {
      setError(submitError instanceof Error ? submitError.message : "Could not save your details.");
    } finally {
      setLoading(false);
    }
  }

  if (checking) {
    return (
      <main className="flex min-h-screen items-center justify-center px-6">
        <p className="text-[#667066]">Loading...</p>
      </main>
    );
  }

  return (
    <main className="flex min-h-screen items-center justify-center px-6 py-12">
      <section className="w-full max-w-md border border-[#c6c8bd] bg-[#fffdf8] p-8 shadow-[10px_10px_0_#d7dfc9]">
        <p className="mb-10 text-xs font-bold uppercase tracking-[0.22em] text-[#66805a]">
          MyApp / Set up
        </p>
        <h1 className="text-5xl leading-none text-[#17221b]">One last thing.</h1>
        <p className="mt-4 text-lg text-[#667066]">
          You&apos;re signed in as {email}. Tell us your age to finish setting up your account.
        </p>
        <form onSubmit={handleSubmit} className="mt-8 space-y-4">
          <label className="block text-sm font-bold" htmlFor="age">
            Your age
          </label>
          <input
            id="age"
            type="number"
            min={13}
            max={120}
            required
            value={age}
            onChange={(event) => setAge(event.target.value)}
            placeholder="30"
            className="w-full border border-[#aeb7a8] bg-[#f7f5ef] p-3 outline-none focus:border-[#52744b]"
          />
          <button
            type="submit"
            disabled={loading}
            className="w-full bg-[#21452d] p-3 font-bold text-white transition hover:bg-[#386542] disabled:cursor-wait disabled:opacity-60"
          >
            {loading ? "Saving..." : "Finish setting up"}
          </button>
        </form>
        {error && (
          <p className="mt-5 border-l-4 border-[#b94a48] bg-[#f7e4df] p-3 text-sm text-[#7e2826]">{error}</p>
        )}
        <button onClick={() => void logout()} className="mt-6 text-sm font-bold underline">
          Sign out
        </button>
      </section>
    </main>
  );
}
