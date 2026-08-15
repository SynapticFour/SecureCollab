// SPDX-License-Identifier: Apache-2.0
"use client";

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useState,
} from "react";

const EMAIL_KEY = "securecollab_user_email";
const TOKEN_KEY = "securecollab_token";

type EmailContextType = {
  email: string | null;
  token: string | null;
  setEmail: (email: string) => void;
  setSession: (email: string, token: string) => void;
  logout: () => void;
  isReady: boolean;
};

const EmailContext = createContext<EmailContextType | null>(null);

export function EmailProvider({ children }: { children: React.ReactNode }) {
  const [email, setEmailState] = useState<string | null>(null);
  const [token, setTokenState] = useState<string | null>(null);
  const [isReady, setIsReady] = useState(false);

  useEffect(() => {
    const storedEmail = typeof window !== "undefined" ? localStorage.getItem(EMAIL_KEY) : null;
    const storedToken = typeof window !== "undefined" ? localStorage.getItem(TOKEN_KEY) : null;
    setEmailState(storedEmail);
    setTokenState(storedToken);
    setIsReady(true);
  }, []);

  const setSession = useCallback((value: string, accessToken: string) => {
    const trimmed = value.trim();
    setEmailState(trimmed);
    setTokenState(accessToken);
    if (typeof window !== "undefined") {
      localStorage.setItem(EMAIL_KEY, trimmed);
      localStorage.setItem(TOKEN_KEY, accessToken);
    }
  }, []);

  const setEmail = useCallback((value: string) => {
    setEmailState(value.trim());
    if (typeof window !== "undefined") localStorage.setItem(EMAIL_KEY, value.trim());
  }, []);

  const logout = useCallback(() => {
    setEmailState(null);
    setTokenState(null);
    if (typeof window !== "undefined") {
      localStorage.removeItem(EMAIL_KEY);
      localStorage.removeItem(TOKEN_KEY);
    }
  }, []);

  return (
    <EmailContext.Provider value={{ email, token, setEmail, setSession, logout, isReady }}>
      {children}
    </EmailContext.Provider>
  );
}

export function useEmail() {
  const ctx = useContext(EmailContext);
  if (!ctx) throw new Error("useEmail must be used within EmailProvider");
  return ctx;
}
