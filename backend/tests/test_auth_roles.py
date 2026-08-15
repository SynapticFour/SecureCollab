# SPDX-License-Identifier: Apache-2.0
"""Lightweight header-based auth is gone; admin uses signed tokens."""
from tests.test_auth import test_config_summary_requires_admin_token


def test_config_summary_requires_admin_header():
    test_config_summary_requires_admin_token()
