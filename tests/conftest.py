"""Test configuration.

The application reads AMBER_DATA at import time, so it must point to a scratch directory
before any `app` module is imported.
"""
import os
import sys
import tempfile
from pathlib import Path

_DATA = tempfile.mkdtemp(prefix="amberventory-tests-")
os.environ["AMBER_DATA"] = _DATA
os.environ.pop("AMBER_USER", None)
os.environ.pop("AMBER_PASSWORD", None)

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import pytest  # noqa: E402


@pytest.fixture(scope="session")
def data_dir() -> Path:
    return Path(_DATA)
