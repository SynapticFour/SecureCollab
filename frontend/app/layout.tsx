// SPDX-License-Identifier: Apache-2.0
import type { Metadata } from "next";
import { Inter } from "next/font/google";
import { EmailProvider } from "@/lib/email-context";
import "./globals.css";

const inter = Inter({ subsets: ["latin"], variable: "--font-geist-sans" });

export const metadata: Metadata = {
  title: "SecureCollab – Encrypted Clinical Data Analysis",
  description:
    "Collaborate on sensitive clinical data without ever exposing it. Secure B2B platform for pharma.",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className={inter.variable}>
      <body className="min-h-screen font-sans antialiased">
        <EmailProvider>
          <div className="border-b border-amber-300 bg-amber-50 px-4 py-2 text-xs text-amber-900 md:px-6">
            <p className="max-w-5xl">
              This is a hobby / proof-of-concept instance of SecureCollab. It is intended for experiments with synthetic or test data only and has not undergone a formal security or legal review. Do not upload real patient data or rely on this deployment for regulatory compliance.
            </p>
          </div>
          {children}
        </EmailProvider>
      </body>
    </html>
  );
}
