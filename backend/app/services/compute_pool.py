# SPDX-License-Identifier: Apache-2.0
"""Bound concurrent HE work so CKKS cannot stall the API unbounded."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeout
from threading import BoundedSemaphore
from typing import Any, Callable, TypeVar

from app.config import settings

T = TypeVar("T")

_HE_TIMEOUT_SECONDS = 120

_executor = ThreadPoolExecutor(
    max_workers=settings.max_concurrent_computations,
    thread_name_prefix="he-compute",
)
_slots = BoundedSemaphore(settings.max_concurrent_computations)


class ComputeBusyError(RuntimeError):
    """Too many concurrent HE jobs."""


class ComputeTimeoutError(RuntimeError):
    """HE job exceeded the wall-clock timeout."""


def run_he(fn: Callable[..., T], *args: Any, timeout: int = _HE_TIMEOUT_SECONDS) -> T:
    """Run a CPU-bound HE callable with a concurrency cap and timeout."""
    if not _slots.acquire(timeout=5):
        raise ComputeBusyError("Computation queue is full; retry later")
    try:
        fut = _executor.submit(fn, *args)
        try:
            return fut.result(timeout=timeout)
        except FuturesTimeout as e:
            fut.cancel()
            raise ComputeTimeoutError(f"Computation exceeded {timeout}s") from e
    finally:
        _slots.release()
