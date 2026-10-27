"""AmberVentory — Debian fleet inventory & vulnerability report (FastAPI)."""
from __future__ import annotations

import base64
import csv
import io
import json
import logging
import os
import re
import secrets
import shutil
import tempfile
import time
from contextlib import asynccontextmanager

from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, JSONResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from .config import settings
from .jobs import REPORTS_DIR, build_report, list_reports, manager
from .scanner import UserError, inspect_key, nmap_scan, parse_inventory
from .vulndb import get_vulndb

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("amberventory")

STATIC = os.path.join(os.path.dirname(__file__), "static")
KEYS_DIR = os.path.join(settings.data_dir, "keys")
INV_DIR = os.path.join(settings.data_dir, "inventories")
for d in (KEYS_DIR, INV_DIR):
    os.makedirs(d, exist_ok=True)
    os.chmod(d, 0o700)
KEY_PATH = os.path.join(KEYS_DIR, "id_key")
KEY_META = os.path.join(KEYS_DIR, "key.json")



@asynccontextmanager
async def lifespan(_: FastAPI):
    vdb = get_vulndb()
    imported = int(vdb.meta().get("tracker_imported") or 0)
    if not imported or time.time() - imported > settings.feed_ttl:
        log.info("vulnerability DB missing or stale, updating in background")
        vdb.update_async()
    yield


app = FastAPI(title="AmberVentory", docs_url="/api/docs", redoc_url=None, lifespan=lifespan)
STATE = {"passphrase": "", "inventory": None}


# ------------------------------------------------------------------ auth
@app.middleware("http")
async def basic_auth(request: Request, call_next):
    if settings.auth_user and request.url.path != "/healthz":
        hdr = request.headers.get("authorization", "")
        ok = False
        if hdr.lower().startswith("basic "):
            try:
                user, _, pwd = base64.b64decode(hdr[6:]).decode().partition(":")
                ok = secrets.compare_digest(user, settings.auth_user) and \
                    secrets.compare_digest(pwd, settings.auth_password)
            except Exception:
                ok = False
        if not ok:
            return Response(status_code=401, headers={"WWW-Authenticate": 'Basic realm="AmberVentory"'})
    resp = await call_next(request)
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("Referrer-Policy", "no-referrer")
    return resp


@app.exception_handler(UserError)
async def user_error(_, exc: UserError):
    return JSONResponse({"detail": str(exc)}, status_code=400)


# ----------------------------------------------------------------- pages
@app.get("/")
def index():
    return FileResponse(os.path.join(STATIC, "index.html"))


@app.get("/report/{report_id}")
def report_page(report_id: str):
    return FileResponse(os.path.join(STATIC, "report.html"))


@app.get("/healthz")
def healthz():
    return {"ok": True}


app.mount("/static", StaticFiles(directory=STATIC), name="static")


# ------------------------------------------------------------------- api
def key_info():
    if not os.path.exists(KEY_PATH) or not os.path.exists(KEY_META):
        return None
    info = json.load(open(KEY_META))
    info["unlocked"] = not info.get("encrypted") or bool(STATE["passphrase"])
    return info


@app.get("/api/state")
def api_state():
    running = [j.progress() for j in manager.jobs.values() if j.state in ("queued", "running", "analyzing")]
    return {
        "key": key_info(),
        "inventory": STATE["inventory"],
        "vulndb": get_vulndb().meta(),
        "job": running[0] if running else None,
        "reports": list_reports(),
        "watchlist": settings.watchlist,
        "auth": bool(settings.auth_user),
    }


class ScanReq(BaseModel):
    targets: str
    port: int = Field(22, ge=1, le=65535)


@app.post("/api/scan")
def api_scan(req: ScanReq):
    t0 = time.time()
    hosts = nmap_scan(req.targets, req.port)
    return {"hosts": hosts, "elapsed": round(time.time() - t0, 1)}


@app.post("/api/inventory")
async def api_inventory(file: UploadFile = File(...)):
    name = os.path.basename(file.filename or "inventory")
    ext = os.path.splitext(name)[1].lower()
    if ext not in ("", ".ini", ".cfg", ".yml", ".yaml", ".txt", ".hosts", ".json"):
        raise UserError("Ожидается inventory в формате INI или YAML")
    data = await file.read()
    if len(data) > 2 * 1024 * 1024:
        raise UserError("Inventory больше 2 МБ")
    path = os.path.join(INV_DIR, f"{int(time.time())}{ext or '.ini'}")
    with open(path, "wb") as f:
        f.write(data)
    try:
        hosts = parse_inventory(path)
    except UserError:
        os.unlink(path)
        raise
    STATE["inventory"] = {"path": path, "name": name, "hosts": len(hosts)}
    return {"hosts": hosts, "name": name}


@app.post("/api/key")
async def api_key(file: UploadFile = File(...), passphrase: str = Form("")):
    data = await file.read()
    if len(data) > 64 * 1024:
        raise UserError("Слишком большой файл для SSH-ключа")
    if not data.endswith(b"\n"):
        data += b"\n"
    fd, tmp = tempfile.mkstemp(dir=KEYS_DIR)
    with os.fdopen(fd, "wb") as f:
        f.write(data.replace(b"\r\n", b"\n"))
    os.chmod(tmp, 0o600)
    try:
        info = inspect_key(tmp, passphrase)
    except UserError:
        os.unlink(tmp)
        raise
    os.replace(tmp, KEY_PATH)
    info.update(name=os.path.basename(file.filename or "key"), uploaded=time.time())
    with open(KEY_META, "w") as f:
        json.dump(info, f)
    STATE["passphrase"] = passphrase  # memory only, never written to disk
    return key_info()


@app.delete("/api/key")
def api_key_delete():
    for p in (KEY_PATH, KEY_META):
        if os.path.exists(p):
            os.unlink(p)
    STATE["passphrase"] = ""
    return {"ok": True}


class UnlockReq(BaseModel):
    passphrase: str


@app.post("/api/key/unlock")
def api_key_unlock(req: UnlockReq):
    if not key_info():
        raise UserError("Ключ не загружен")
    inspect_key(KEY_PATH, req.passphrase)
    STATE["passphrase"] = req.passphrase
    return key_info()


class HostIn(BaseModel):
    ip: str
    name: str = ""
    port: int = 22
    groups: list[str] = []


class JobReq(BaseModel):
    hosts: list[HostIn]
    source: str = "scan"  # scan | inventory
    source_label: str = ""
    user: str = "root"
    become: bool = False
    apt_refresh: bool = False
    strict_host_keys: bool = False


@app.post("/api/jobs")
def api_job_start(req: JobReq):
    info = key_info()
    if not info:
        raise UserError("Сначала загрузите SSH-ключ")
    if not info["unlocked"]:
        raise UserError("Ключ защищён паролем: введите passphrase")
    if not req.hosts:
        raise UserError("Не выбрано ни одного хоста")
    if req.user and not re.fullmatch(r"[a-z_][a-z0-9_.-]{0,31}", req.user):
        raise UserError("Недопустимое имя пользователя SSH")
    if not get_vulndb().meta().get("ready"):
        log.warning("starting job without vulnerability DB; report will have inventory only")
    params = req.model_dump()
    params["hosts"] = [h.model_dump() for h in req.hosts]
    params["key_path"] = KEY_PATH
    params["passphrase"] = STATE["passphrase"]
    if req.source == "inventory":
        if not STATE["inventory"]:
            raise UserError("Inventory не загружен")
        params["inventory_path"] = STATE["inventory"]["path"]
        params["source_label"] = params["source_label"] or STATE["inventory"]["name"]
    try:
        job = manager.start(params)
    except RuntimeError as e:
        raise UserError(str(e)) from e
    return job.progress()


@app.get("/api/jobs/{job_id}")
def api_job(job_id: str):
    j = manager.get(job_id)
    if not j:
        raise HTTPException(404)
    return j.progress()


@app.post("/api/jobs/{job_id}/cancel")
def api_job_cancel(job_id: str):
    return {"ok": manager.cancel(job_id)}


@app.get("/api/jobs/{job_id}/log")
def api_job_log(job_id: str):
    j = manager.get(job_id)
    if not j:
        raise HTTPException(404)
    p = os.path.join(j.dir, "ansible.log")
    txt = open(p, errors="replace").read()[-20000:] if os.path.exists(p) else ""
    return Response(txt, media_type="text/plain; charset=utf-8")


def _report_path(report_id: str) -> str:
    if not report_id.replace("-", "").isalnum():
        raise HTTPException(400)
    p = os.path.join(REPORTS_DIR, report_id + ".json")
    if not os.path.exists(p):
        raise HTTPException(404, "Отчёт не найден")
    return p


@app.get("/api/reports")
def api_reports():
    return list_reports()


@app.get("/api/reports/{report_id}")
def api_report(report_id: str):
    return FileResponse(_report_path(report_id), media_type="application/json")


@app.delete("/api/reports/{report_id}")
def api_report_delete(report_id: str):
    os.unlink(_report_path(report_id))
    shutil.rmtree(os.path.join(settings.data_dir, "jobs", report_id), ignore_errors=True)
    return {"ok": True}


@app.post("/api/reports/{report_id}/reanalyze")
def api_reanalyze(report_id: str):
    _report_path(report_id)
    job_dir = os.path.join(settings.data_dir, "jobs", report_id)
    if not os.path.exists(os.path.join(job_dir, "params.json")):
        raise UserError("Сырые данные этого отчёта не сохранились")
    r = build_report(report_id, job_dir)
    return {"ok": True, "severity": r["fleet"]["severity"]}


@app.get("/api/reports/{report_id}/vulns.csv")
def api_report_csv(report_id: str):
    r = json.load(open(_report_path(report_id)))
    buf = io.StringIO()
    w = csv.writer(buf, delimiter=";")
    w.writerow(["host", "ip", "release", "severity", "cve", "source_package", "binaries", "installed", "fixed",
                "status", "debian_urgency", "kev", "epss", "cvss", "apt_candidate", "fixed_by_apt", "description"])
    for h in r["hosts"]:
        for v in h.get("vulns", []):
            w.writerow([h["name"], h.get("ip", ""), h["os"].get("codename", ""), v["severity"], v["cve"], v["src"],
                        " ".join(v["binaries"]), v["installed"], v["fixed"], v["status"], v["urgency"],
                        "yes" if v["kev"] else "", v["epss"] if v["epss"] is not None else "",
                        v["cvss"] if v["cvss"] is not None else "", v["candidate"],
                        "yes" if v["fixed_by_apt"] else "", v["description"][:300]])
    return StreamingResponse(iter(["﻿" + buf.getvalue()]), media_type="text/csv; charset=utf-8",
                             headers={"Content-Disposition": f'attachment; filename="amberventory-{report_id}.csv"'})


@app.get("/api/vulndb")
def api_vulndb():
    return get_vulndb().meta()


@app.post("/api/vulndb/update")
def api_vulndb_update(force: bool = True):
    return {"started": get_vulndb().update_async(force=force)}


@app.post("/api/vulndb/upload")
async def api_vulndb_upload(file: UploadFile = File(...)):
    vdb = get_vulndb()
    fd, tmp = tempfile.mkstemp(dir=vdb.feeds_dir, suffix=".json")
    with os.fdopen(fd, "wb") as f:
        while chunk := await file.read(1024 * 1024):
            f.write(chunk)
    with open(tmp, "rb") as f:
        if f.read(1) != b"{":
            os.unlink(tmp)
            raise UserError("Ожидается JSON Debian Security Tracker (https://security-tracker.debian.org/tracker/data/json)")
    vdb.import_uploaded_tracker(tmp)
    return {"started": True}


class NvdReq(BaseModel):
    report_id: str


@app.post("/api/vulndb/nvd")
def api_vulndb_nvd(req: NvdReq):
    r = json.load(open(_report_path(req.report_id)))
    cves = [v["cve"] for h in r["hosts"] for v in h.get("vulns", [])
            if v["severity"] == "unrated" and v["status"] in ("fixable", "no_fix")]
    return {"started": get_vulndb().enrich_cvss_async(cves), "candidates": len(set(cves)),
            "limit": settings.nvd_max_per_run}
