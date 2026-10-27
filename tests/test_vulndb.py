"""Integrity checks for downloaded vulnerability feeds."""

import gzip

import pytest

from app.vulndb import verify_gzip_complete


def _write_gz(path, payload: bytes):
    with gzip.open(path, "wb") as f:
        f.write(payload)


def test_complete_gzip_is_accepted(tmp_path):
    p = tmp_path / "epss.csv.gz"
    _write_gz(p, b"cve,epss,percentile\nCVE-2024-1,0.5,0.9\n" * 1000)
    verify_gzip_complete(str(p))  # does not raise


def test_truncated_gzip_is_rejected(tmp_path):
    full = tmp_path / "full.gz"
    _write_gz(full, b"cve,epss,percentile\nCVE-2024-1,0.5,0.9\n" * 5000)
    data = full.read_bytes()
    cut = tmp_path / "cut.csv.gz"
    cut.write_bytes(data[: len(data) // 2])  # simulate a dropped connection
    with pytest.raises((EOFError, OSError)):
        verify_gzip_complete(str(cut))


def test_garbage_is_rejected(tmp_path):
    p = tmp_path / "bad.csv.gz"
    p.write_bytes(b"<html>proxy error</html>")
    with pytest.raises(OSError):
        verify_gzip_complete(str(p))
