"use client";

import { FormEvent, useState } from "react";

const apiUrl = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";

export default function LoginPage() {
  const [email, setEmail] = useState("");
  const [loading, setLoading] = useState(false);
  const [sent, setSent] = useState(false);
  const [error, setError] = useState("");

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setLoading(true);
    setError("");
    setSent(false);

    try {
      const response = await fetch(`${apiUrl}/auth/request-link`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({ email }),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.detail ?? "Unable to send link");
      setSent(true);
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : "Unable to send link");
    } finally {
      setLoading(false);
    }
  }

  return (
    <main className="flex min-h-screen items-center justify-center px-6 py-12">
      <section className="w-full max-w-md border border-[#c6c8bd] bg-[#fffdf8] p-8 shadow-[10px_10px_0_#d7dfc9]">
        <p className="mb-10 text-xs font-bold uppercase tracking-[0.22em] text-[#66805a]">MyApp / Access</p>
        <h1 className="text-5xl leading-none text-[#17221b]">Welcome back.</h1>
        <p className="mt-4 text-lg text-[#667066]">Enter your email and we&apos;ll send a one-time sign-in link.</p>
        <form onSubmit={handleSubmit} className="mt-8 space-y-4">
          <label className="block text-sm font-bold" htmlFor="email">Email address</label>
          <input id="email" type="email" required value={email} onChange={(event) => setEmail(event.target.value)} placeholder="you@example.com" className="w-full border border-[#aeb7a8] bg-[#f7f5ef] p-3 outline-none focus:border-[#52744b]" />
          <button type="submit" disabled={loading} className="w-full bg-[#21452d] p-3 font-bold text-white transition hover:bg-[#386542] disabled:cursor-wait disabled:opacity-60">
            {loading ? "Sending link..." : "Send magic link"}
          </button>
        </form>
        {sent && <p className="mt-5 border-l-4 border-[#6c9c61] bg-[#e6f0df] p-3 text-sm text-[#31572e]">Check your inbox. The link expires in 10 minutes.</p>}
        {error && <p className="mt-5 border-l-4 border-[#b94a48] bg-[#f7e4df] p-3 text-sm text-[#7e2826]">{error}</p>}
      </section>
    </main>
  );
}