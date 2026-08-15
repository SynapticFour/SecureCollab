# SPDX-License-Identifier: Apache-2.0
"""HTTP helpers with timeouts. Identity via Authorization Bearer token."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

HTTP_TIMEOUT = 30


def _auth_headers(token: str = "") -> list[tuple[str, str]]:
    if not token:
        return []
    return [("Authorization", f"Bearer {token}")]


def api_get(api_base_url: str, path: str, email: str = "", token: str = "") -> dict[str, Any] | list[Any]:
    url = f"{api_base_url.rstrip('/')}{path}"
    req = Request(url, method="GET")
    for k, v in _auth_headers(token):
        req.add_header(k, v)
    with urlopen(req, timeout=HTTP_TIMEOUT) as resp:
        return json.loads(resp.read().decode())


def api_post(
    api_base_url: str,
    path: str,
    data: dict[str, Any] | None = None,
    form: dict[str, Any] | None = None,
    file_path: Path | None = None,
    file_field: str = "file",
    email: str = "",
    token: str = "",
) -> dict[str, Any]:
    url = f"{api_base_url.rstrip('/')}{path}"
    if form is not None or file_path is not None:
        boundary = "----SecureCollabSDK"
        body_parts: list[bytes | str] = []
        if form:
            for k, v in form.items():
                body_parts.append(
                    f"--{boundary}\r\nContent-Disposition: form-data; name=\"{k}\"\r\n\r\n{v}\r\n"
                )
        if file_path is not None and file_path.exists():
            raw = file_path.read_bytes()
            body_parts.append(
                f"--{boundary}\r\nContent-Disposition: form-data; name=\"{file_field}\"; "
                f"filename=\"{file_path.name}\"\r\nContent-Type: application/octet-stream\r\n\r\n".encode()
            )
            body_parts.append(raw)
            body_parts.append(b"\r\n")
        body_parts.append(f"--{boundary}--\r\n".encode())
        body = b"".join(p if isinstance(p, bytes) else p.encode() for p in body_parts)
        req = Request(url, data=body, method="POST")
        req.add_header("Content-Type", f"multipart/form-data; boundary={boundary}")
        req.add_header("Content-Length", str(len(body)))
    else:
        req = Request(url, data=json.dumps(data or {}).encode(), method="POST")
        req.add_header("Content-Type", "application/json")
    for k, v in _auth_headers(token):
        req.add_header(k, v)
    try:
        with urlopen(req, timeout=HTTP_TIMEOUT) as resp:
            return json.loads(resp.read().decode())
    except HTTPError as e:
        raise URLError(f"HTTP {e.code}: {e.reason}") from e


def api_login(api_base_url: str, email: str, password: str) -> str:
    body = api_post(api_base_url, "/auth/login", data={"email": email, "password": password})
    token = body.get("token")
    if not isinstance(token, str) or not token:
        raise URLError("Login did not return a token")
    return token
