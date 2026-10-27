"""HTTP API: authentication, validation and report endpoints."""
import base64
import shutil

import pytest
from fastapi.testclient import TestClient

from app.config import settings
from app.main import app

client = TestClient(app)


def basic(user, password):
    return {"Authorization": "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()}


def test_healthz_is_always_open(monkeypatch):
    monkeypatch.setattr(settings, "auth_user", "admin")
    monkeypatch.setattr(settings, "auth_password", "secret")
    assert client.get("/healthz").json() == {"ok": True}


def test_basic_auth(monkeypatch):
    monkeypatch.setattr(settings, "auth_user", "admin")
    monkeypatch.setattr(settings, "auth_password", "secret")
    r = client.get("/api/state")
    assert r.status_code == 401 and "Basic" in r.headers["www-authenticate"]
    assert client.get("/api/state", headers=basic("admin", "wrong")).status_code == 401
    assert client.get("/api/state", headers=basic("root", "secret")).status_code == 401
    assert client.get("/api/state", headers=basic("admin", "secret")).status_code == 200


def test_no_auth_when_not_configured():
    assert client.get("/api/state").status_code == 200


def test_security_headers():
    r = client.get("/healthz")
    assert r.headers["x-frame-options"] == "DENY"
    assert r.headers["x-content-type-options"] == "nosniff"


def test_pages_are_served():
    assert "AmberVentory" in client.get("/").text
    assert client.get("/report/anything").status_code == 200
    assert client.get("/static/app.css").status_code == 200


def test_job_requires_key():
    r = client.post("/api/jobs", json={"hosts": [{"ip": "10.0.0.1"}]})
    assert r.status_code == 400 and "ключ" in r.json()["detail"]


@pytest.mark.parametrize("targets", ["10.0.0.0/8", "10.0.0.1 -oN /tmp/x", ""])
def test_scan_rejects_bad_targets(targets):
    assert client.post("/api/scan", json={"targets": targets}).status_code == 400


def test_report_ids_are_validated():
    assert client.get("/api/reports/does-not-exist").status_code == 404
    assert client.get("/api/reports/..%2f..%2fetc%2fpasswd").status_code in (400, 404)
    assert client.get("/api/reports/a.b").status_code == 400


def test_report_endpoints(data_dir):
    from tools import make_demo

    make_demo.main()
    reports = client.get("/api/reports").json()
    rid = next(r["id"] for r in reports if "demo" in r["id"])
    body = client.get(f"/api/reports/{rid}").json()
    assert body["fleet"]["hosts_total"] == 4
    csv_text = client.get(f"/api/reports/{rid}/vulns.csv").text
    assert csv_text.lstrip("﻿").startswith("host;ip;release;severity;cve")
    assert "CVE-2099-2001" in csv_text
    assert client.post(f"/api/reports/{rid}/reanalyze").json()["ok"] is True
    assert client.delete(f"/api/reports/{rid}").json() == {"ok": True}
    assert client.get(f"/api/reports/{rid}").status_code == 404


@pytest.mark.skipif(shutil.which("ansible-inventory") is None, reason="ansible is not installed")
def test_inventory_upload():
    ini = b"[web]\nweb1 ansible_host=10.0.0.5 ansible_port=2222 ansible_user=ops\n[db]\ndb1\n"
    r = client.post("/api/inventory", files={"file": ("hosts.ini", ini)})
    assert r.status_code == 200
    hosts = {h["name"]: h for h in r.json()["hosts"]}
    assert hosts["web1"]["ip"] == "10.0.0.5" and hosts["web1"]["port"] == 2222
    assert hosts["web1"]["user"] == "ops" and hosts["web1"]["groups"] == ["web"]
    assert hosts["db1"]["groups"] == ["db"]


def test_inventory_wrong_extension():
    r = client.post("/api/inventory", files={"file": ("evil.sh", b"echo hi")})
    assert r.status_code == 400
