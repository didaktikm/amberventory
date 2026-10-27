"""Severity rules and the end-to-end analysis on the synthetic demo fleet (tools/make_demo.py)."""
import json

import pytest

from app.analyze import release_state, severity_of


@pytest.fixture(scope="session")
def demo_report(data_dir):
    from app.jobs import REPORTS_DIR
    from tools import make_demo

    make_demo.main()
    files = [f for f in REPORTS_DIR_FILES(REPORTS_DIR) if "demo" in f]
    assert files, "make_demo did not produce a report"
    with open(files[-1]) as f:
        return json.load(f)


def REPORTS_DIR_FILES(directory):
    import os

    return sorted(os.path.join(directory, f) for f in os.listdir(directory) if f.endswith(".json"))


# ---------------------------------------------------------------- severity rules
@pytest.mark.parametrize(
    ("urgency", "kev", "epss", "cvss", "expected"),
    [
        ("high", False, None, None, "high"),
        ("medium", False, None, None, "medium"),
        ("low", False, None, None, "low"),
        ("unimportant", False, None, None, "negligible"),
        ("", False, None, None, "unrated"),
        ("", False, None, 9.8, "critical"),
        ("", False, None, 7.5, "high"),
        ("", False, None, 5.0, "medium"),
        ("", False, None, 2.0, "low"),
        ("low", False, 0.62, None, "high"),  # EPSS >= 50% escalates to high
        ("high", False, 0.9, None, "high"),  # but never lowers
        ("medium", False, 0.1, None, "medium"),
        ("low", True, None, None, "critical"),  # KEV always wins
        ("unimportant", True, 0.0, None, "critical"),
    ],
)
def test_severity_rules(urgency, kev, epss, cvss, expected):
    severity, reason = severity_of(urgency, kev, epss, cvss)
    assert severity == expected
    assert reason


def test_debian_urgency_beats_cvss():
    assert severity_of("low", False, None, 9.9)[0] == "low"


def test_release_state_known_cases():
    assert release_state("bookworm", "debian")["state"] in ("supported", "lts")
    assert release_state("jessie", "debian")["state"] == "eol"
    assert release_state("sid", "debian")["state"] == "testing"
    assert release_state("noble", "ubuntu")["state"] == "non-debian"
    assert release_state("nonexistent", "debian")["state"] == "unknown"


# ---------------------------------------------------------------- full pipeline
def _host(report, name):
    return next(h for h in report["hosts"] if h["name"] == name)


def test_fleet_totals(demo_report):
    fleet = demo_report["fleet"]
    assert fleet["hosts_total"] == 4 and fleet["hosts_ok"] == 3 and fleet["hosts_failed"] == 1
    assert fleet["severity"]["critical"] == 1
    assert fleet["severity"]["high"] == 4
    assert fleet["severity"]["medium"] == 4
    assert fleet["severity"]["unrated"] == 1
    assert fleet["kev_cves"] == ["CVE-2099-2001"]
    assert fleet["eol_hosts"] == ["legacy-crm"]


def test_kev_vulnerability_is_critical_and_fixable(demo_report):
    v = next(v for v in _host(demo_report, "web-front-02")["vulns"] if v["cve"] == "CVE-2099-2001")
    assert v["severity"] == "critical" and v["kev"] and v["kev_ransomware"]
    assert v["status"] == "fixable" and v["fixed_by_apt"] is True


def test_kernel_is_judged_by_the_running_version(demo_report):
    host = _host(demo_report, "pg-main-01")
    v = next(v for v in host["vulns"] if v["cve"] == "CVE-2099-4001")
    # running 6.1.137-1, fix in 6.1.140-1, newer 6.1.153-1 is installed but not booted
    assert v["installed"] == "6.1.137-1" and v["status"] == "fixable"
    assert v["fixed_by_reboot"] is True and v["fixed_by_apt"] is False
    texts = " ".join(f["text"] for f in host["findings"])
    assert "более новое" in texts


def test_postponed_and_negligible_are_not_counted(demo_report):
    host = _host(demo_report, "pg-main-01")
    statuses = {v["cve"]: v["status"] for v in host["vulns"]}
    assert statuses["CVE-2099-1002"] == "postponed"
    assert host["summary"]["vuln_total"] == 4  # openssl, linux, sudo, postgresql
    assert host["summary"]["postponed"] == 1


def test_eol_host_without_security_repo(demo_report):
    host = _host(demo_report, "legacy-crm")
    assert host["release"]["state"] == "eol"
    areas = {(f["level"], f["area"]) for f in host["findings"]}
    assert ("crit", "APT") in areas and ("crit", "ОС") in areas
    openssl = next(v for v in host["vulns"] if v["src"] == "openssl")
    assert openssl["status"] == "no_fix"


def test_configuration_findings(demo_report):
    texts = [f["text"] for f in _host(demo_report, "web-front-02")["findings"]]
    joined = "\n".join(texts)
    assert "UID 0" in joined
    assert "PermitRootLogin" in joined
    assert "Docker API" in joined
    assert "просрочен" in joined


def test_third_party_packages_are_flagged(demo_report):
    web = _host(demo_report, "web-front-02")
    docker = next(p for p in web["packages"] if p["name"] == "docker-ce")
    assert docker["tracked"] is False
    sury = next(p for p in web["packages"] if p["name"] == "php8.3-fpm")
    assert sury["third_party"] is True


def test_unreachable_host_is_reported(demo_report):
    mq = _host(demo_report, "mq-03")
    assert mq["state"] == "unreachable" and "таймаут" in mq["error"]
