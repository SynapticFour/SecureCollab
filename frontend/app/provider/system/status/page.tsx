// SPDX-License-Identifier: Apache-2.0
"use client";

import { useEffect, useState } from "react";

type Health = { status: string } | null;
type Integrity = {
  codebase_hash: string;
  git_commit: string;
  computed_at: string;
  python_version: string;
  fastapi_version?: string;
} | null;
type ConfigSummary = {
  db_type: string;
  upload_dir: string;
  max_upload_size_mb: number;
  max_concurrent_computations: number;
  rate_limiting_enabled: boolean;
  app_title: string;
  app_version: string;
} | null;

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

export default function SystemStatusPage() {
  const [health, setHealth] = useState<Health>(null);
  const [integrity, setIntegrity] = useState<Integrity>(null);
  const [config, setConfig] = useState<ConfigSummary>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    async function load() {
      try {
        const [h, i, c] = await Promise.all([
          fetch(`${API_BASE}/system/health`).then((r) => r.json()),
          fetch(`${API_BASE}/system/integrity`).then((r) => r.json()),
          fetch(`${API_BASE}/system/config-summary`).then((r) => r.json()),
        ]);
        setHealth(h);
        setIntegrity(i);
        setConfig(c);
        setError(null);
      } catch (e) {
        setError(e instanceof Error ? e.message : "Failed to load system status");
      }
    }
    load();
  }, []);

  return (
    <div className="mx-auto max-w-4xl">
      <h1 className="text-2xl font-semibold text-slate-900">System Status</h1>
      <p className="mt-1 text-sm text-slate-600">
        Technical overview of this SecureCollab deployment. This page is for operators and does not make any statement
        about legal compliance or SLAs.
      </p>
      {error && (
        <div className="mt-4 rounded-lg border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-800">
          {error}
        </div>
      )}

      <div className="mt-6 grid gap-4 md:grid-cols-2">
        <div className="rounded-xl border border-slate-200 bg-white p-4">
          <h2 className="text-sm font-semibold text-slate-900">API</h2>
          <dl className="mt-2 space-y-1 text-sm text-slate-700">
            <div>
              <dt className="font-medium text-slate-500">Health</dt>
              <dd>{health?.status ?? "unknown"}</dd>
            </div>
            <div>
              <dt className="font-medium text-slate-500">Title</dt>
              <dd>{config?.app_title ?? "SecureCollab API"}</dd>
            </div>
            <div>
              <dt className="font-medium text-slate-500">Version</dt>
              <dd>{config?.app_version ?? "0.1.0"}</dd>
            </div>
          </dl>
        </div>

        <div className="rounded-xl border border-slate-200 bg-white p-4">
          <h2 className="text-sm font-semibold text-slate-900">Codebase</h2>
          <dl className="mt-2 space-y-1 text-sm text-slate-700">
            <div>
              <dt className="font-medium text-slate-500">Codebase hash</dt>
              <dd className="break-all text-xs">{integrity?.codebase_hash ?? "unknown"}</dd>
            </div>
            <div>
              <dt className="font-medium text-slate-500">Git commit</dt>
              <dd className="break-all text-xs">{integrity?.git_commit ?? "unknown"}</dd>
            </div>
            <div>
              <dt className="font-medium text-slate-500">Computed at</dt>
              <dd>{integrity?.computed_at ?? "unknown"}</dd>
            </div>
          </dl>
        </div>

        <div className="rounded-xl border border-slate-200 bg-white p-4">
          <h2 className="text-sm font-semibold text-slate-900">Runtime</h2>
          <dl className="mt-2 space-y-1 text-sm text-slate-700">
            <div>
              <dt className="font-medium text-slate-500">Python</dt>
              <dd>{integrity?.python_version ?? "unknown"}</dd>
            </div>
            <div>
              <dt className="font-medium text-slate-500">Rate limiting</dt>
              <dd>{config?.rate_limiting_enabled ? "enabled" : "disabled"}</dd>
            </div>
          </dl>
        </div>

        <div className="rounded-xl border border-slate-200 bg-white p-4">
          <h2 className="text-sm font-semibold text-slate-900">Storage & Limits</h2>
          <dl className="mt-2 space-y-1 text-sm text-slate-700">
            <div>
              <dt className="font-medium text-slate-500">Database type</dt>
              <dd>{config?.db_type ?? "unknown"}</dd>
            </div>
            <div>
              <dt className="font-medium text-slate-500">Upload dir</dt>
              <dd className="break-all text-xs">{config?.upload_dir ?? "unknown"}</dd>
            </div>
            <div>
              <dt className="font-medium text-slate-500">Max upload size (MB)</dt>
              <dd>{config?.max_upload_size_mb ?? "unknown"}</dd>
            </div>
            <div>
              <dt className="font-medium text-slate-500">Max concurrent computations</dt>
              <dd>{config?.max_concurrent_computations ?? "unknown"}</dd>
            </div>
          </dl>
        </div>
      </div>
    </div>
  );
}
