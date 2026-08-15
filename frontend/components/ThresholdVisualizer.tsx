// SPDX-License-Identifier: Apache-2.0
"use client";

/**
 * Visual explanation of t-of-n authorization to release an encrypted result.
 */
export function ThresholdVisualizer({
  t,
  n,
  description,
}: {
  t: number;
  n: number;
  description?: React.ReactNode;
}) {
  const defaultDesc = (
    <>
      With t={t} of n={n}: any {t} of {n} participants must authorize release of the
      still-encrypted result blob. This is not threshold decryption. Only the
      study creator&apos;s secret key can finalize plaintext locally. The server
      never decrypts.
    </>
  );

  return (
    <div className="rounded-xl border border-slate-200 bg-slate-50/50 p-4">
      <p className="mb-3 text-sm font-medium text-slate-700">Threshold configuration</p>
      <div className="mb-3 flex items-center justify-center gap-2">
        {Array.from({ length: n }).map((_, i) => (
          <div
            key={i}
            className={`flex h-10 w-10 items-center justify-center rounded-full border-2 text-sm font-medium ${
              i < t
                ? "border-success bg-success/20 text-success"
                : "border-slate-300 bg-white text-slate-500"
            }`}
            title={i < t ? `One of ${t} required` : "Participant"}
          >
            {i < t ? "✓" : i + 1}
          </div>
        ))}
      </div>
      <p className="text-sm text-slate-600">
        {description ?? defaultDesc}
      </p>
    </div>
  );
}
