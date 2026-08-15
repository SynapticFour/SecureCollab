// SPDX-License-Identifier: Apache-2.0
"use client";

import { useEmail } from "@/lib/email-context";
import { login, register } from "@/lib/api";
import { useEffect, useState } from "react";

export function EmailModal() {
  const { email, token, setSession, isReady } = useEmail();
  const [mode, setMode] = useState<"login" | "register">("login");
  const [input, setInput] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [open, setOpen] = useState(false);

  useEffect(() => {
    if (isReady && (!email || !token)) setOpen(true);
    if (isReady && email && token) setOpen(false);
  }, [isReady, email, token]);

  const submit = async () => {
    const v = input.trim();
    if (!v || password.length < 8) {
      setError("Email and a password of at least 8 characters are required.");
      return;
    }
    setError("");
    try {
      const result = mode === "register" ? await register(v, password) : await login(v, password);
      setSession(result.email, result.token);
      setOpen(false);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Authentication failed");
    }
  };

  if (!open) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4">
      <div className="w-full max-w-md rounded-xl bg-white p-6 shadow-xl">
        <h2 className="text-lg font-semibold text-slate-900">
          {mode === "login" ? "Sign in to SecureCollab" : "Create a local account"}
        </h2>
        <p className="mt-2 text-sm text-slate-600">
          Identity is a signed token after password login. Email is not verified;
          do not use real institutional addresses on this prototype.
        </p>
        <input
          type="email"
          value={input}
          onChange={(e) => setInput(e.target.value)}
          placeholder="you@example.com"
          className="mt-4 w-full rounded-lg border border-slate-300 px-3 py-2 text-slate-900 placeholder-slate-400 focus:border-accent focus:outline-none focus:ring-1 focus:ring-accent"
        />
        <input
          type="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          placeholder="Password (min 8 characters)"
          className="mt-2 w-full rounded-lg border border-slate-300 px-3 py-2 text-slate-900 placeholder-slate-400 focus:border-accent focus:outline-none focus:ring-1 focus:ring-accent"
        />
        {error ? <p className="mt-2 text-sm text-red-600">{error}</p> : null}
        <div className="mt-4 flex items-center justify-between">
          <button
            type="button"
            onClick={() => setMode(mode === "login" ? "register" : "login")}
            className="text-sm text-slate-600 underline"
          >
            {mode === "login" ? "Need an account? Register" : "Have an account? Sign in"}
          </button>
          <button
            onClick={submit}
            className="rounded-lg bg-primary px-4 py-2 text-sm font-medium text-white hover:bg-primary-hover"
          >
            {mode === "login" ? "Sign in" : "Register"}
          </button>
        </div>
      </div>
    </div>
  );
}
