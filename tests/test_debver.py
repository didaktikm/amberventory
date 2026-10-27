"""Debian version comparison must agree with dpkg."""
import shutil
import subprocess

import pytest

from app.debver import compare, lt

# (a, b, expected sign of compare(a, b)); every row verified with `dpkg --compare-versions`
CASES = [
    ("1.0", "1.0-1", -1),
    ("1.0~rc1", "1.0", -1),
    ("1:0.1", "2.0", 1),
    ("2:1.0", "1:9", 1),
    ("3.0.11-1~deb12u2", "3.0.14-1~deb12u2", -1),
    ("2.36-9+deb12u7", "2.36-9+deb12u10", -1),
    ("1.2.3+b1", "1.2.3", 1),
    ("1.0-1", "1.0-1+b1", -1),
    ("8.2.7-1~deb12u1", "8.2.26-1~deb12u1", -1),
    ("1.10", "1.9", 1),
    ("1.0a", "1.0+", -1),
    ("7.6p1-4", "7.6p1-4+deb7u1", -1),
    ("1~~", "1~", -1),
    ("1.0", "1.0", 0),
    ("0", "1.0", -1),
    ("5:7.0.15-1~deb12u4", "5:7.0.15-1~deb12u4", 0),
    ("6.1.137-1", "6.1.140-1", -1),
    ("1.1.1w-0+deb11u1", "1.1.1n-0+deb11u3", 1),
]


@pytest.mark.parametrize(("a", "b", "sign"), CASES)
def test_compare(a, b, sign):
    result = compare(a, b)
    assert (result > 0) - (result < 0) == sign
    reverse = compare(b, a)
    assert (reverse > 0) - (reverse < 0) == -sign


def test_lt_helper():
    assert lt("1.0-1", "1.0-2")
    assert not lt("1.0-2", "1.0-1")
    assert not lt("1.0-1", "1.0-1")


@pytest.mark.skipif(shutil.which("dpkg") is None, reason="dpkg is not installed")
@pytest.mark.parametrize(("a", "b", "sign"), CASES)
def test_agrees_with_dpkg(a, b, sign):
    def dpkg(op):
        return subprocess.run(["dpkg", "--compare-versions", a, op, b], capture_output=True).returncode == 0

    assert dpkg("lt") == (sign < 0)
    assert dpkg("eq") == (sign == 0)
    assert dpkg("gt") == (sign > 0)
