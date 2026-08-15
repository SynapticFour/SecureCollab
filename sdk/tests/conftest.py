# SPDX-License-Identifier: Apache-2.0
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest
from securecollab import SecureCollabClient

@pytest.fixture
def client():
    return SecureCollabClient("http://localhost:8000")
