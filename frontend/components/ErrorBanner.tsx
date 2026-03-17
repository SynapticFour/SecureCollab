// SPDX-License-Identifier: Apache-2.0
type Props = {
  message: string;
};

export function ErrorBanner({ message }: Props) {
  if (!message) return null;
  return (
    <div className="mt-4 rounded-lg border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-800">
      <p className="font-medium">Action could not be completed.</p>
      <p className="mt-1 whitespace-pre-line">
        {message}
      </p>
      <p className="mt-1 text-xs text-red-700">
        If an <code className="font-mono">error_id</code> is shown above, please include it when contacting support.
      </p>
    </div>
  );
}

