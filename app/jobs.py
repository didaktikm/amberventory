"""Collection jobs: run Ansible in the background, then build and store the report."""
from __future__ import annotations

import json
import logging
import os
import re
import shutil
import signal
import subprocess
import threading
import time
import uuid

from .analyze import analyze_host, build_fleet
from .config import settings
from .parser import parse_collector_output
from .scanner import decrypt_key_copy
from .vulndb import get_vulndb

log = logging.getLogger("amberventory.jobs")

JOBS_DIR = os.path.join(settings.data_dir, "jobs")
REPORTS_DIR = os.path.join(settings.data_dir, "reports")
os.makedirs(JOBS_DIR, exist_ok=True)
os.makedirs(REPORTS_DIR, exist_ok=True)

SAFE = re.compile(r"^[A-Za-z0-9_.:\-\[\]]+$")


class Job:
    def __init__(self, params: dict):
        self.id = time.strftime("%Y%m%d-%H%M%S-") + uuid.uuid4().hex[:6]
        self.dir = os.path.join(JOBS_DIR, self.id)
        os.makedirs(os.path.join(self.dir, "results"), exist_ok=True)
        self.params = params
        self.state = "queued"
        self.message = ""
        self.started = time.time()
        self.finished = None
        self.proc: subprocess.Popen | None = None
        self.cancelled = False

    @property
    def total(self):
        return len(self.params["hosts"])

    def progress(self):
        events = []
        p = os.path.join(self.dir, "progress.jsonl")
        if os.path.exists(p):
            with open(p) as f:
                events = [json.loads(ln) for ln in f if ln.strip()]
        done = {e["host"]: e for e in events}
        return {
            "id": self.id, "state": self.state, "message": self.message, "total": self.total,
            "done": len(done), "ok": sum(1 for e in done.values() if e["status"] == "ok"),
            "failed": sum(1 for e in done.values() if e["status"] != "ok"),
            "events": events[-50:], "started": self.started, "finished": self.finished,
            "report": self.id if self.state == "done" else None,
        }


class JobManager:
    def __init__(self):
        self.jobs: dict[str, Job] = {}
        self.lock = threading.Lock()

    def start(self, params: dict) -> Job:
        with self.lock:
            if any(j.state in ("queued", "running", "analyzing") for j in self.jobs.values()):
                raise RuntimeError("Уже выполняется задание — дождитесь завершения или отмените его")
            job = Job(params)
            self.jobs[job.id] = job
        threading.Thread(target=self._run, args=(job,), daemon=True).start()
        return job

    def get(self, job_id) -> Job | None:
        return self.jobs.get(job_id)

    def cancel(self, job_id):
        j = self.jobs.get(job_id)
        if j and j.proc and j.proc.poll() is None:
            j.cancelled = True
            os.killpg(j.proc.pid, signal.SIGTERM)
            return True
        return False

    # ------------------------------------------------------------------
    def _write_inventory(self, job: Job) -> tuple[str, list[str]]:
        p = job.params
        if p.get("inventory_path"):
            inv = os.path.join(job.dir, "inventory" + os.path.splitext(p["inventory_path"])[1])
            shutil.copyfile(p["inventory_path"], inv)
            return inv, [h["name"] for h in p["hosts"]]
        lines = ["[amber]"]
        names = []
        for h in p["hosts"]:
            name, ip = h.get("name") or h["ip"], h["ip"]
            if not (SAFE.match(name) and SAFE.match(ip)):
                continue
            port = int(h.get("port") or 22)
            lines.append(f"{name} ansible_host={ip} ansible_port={port}")
            names.append(name)
        inv = os.path.join(job.dir, "inventory.ini")
        with open(inv, "w") as f:
            f.write("\n".join(lines) + "\n")
        return inv, names

    def _run(self, job: Job):
        key_copy = os.path.join(job.dir, "id_key")
        try:
            job.state = "running"
            job.message = "Подключение к хостам по SSH…"
            p = job.params
            with open(os.path.join(job.dir, "params.json"), "w") as f:
                json.dump({k: v for k, v in p.items() if k not in ("passphrase", "key_path")}, f, ensure_ascii=False)
            decrypt_key_copy(p["key_path"], p.get("passphrase", ""), key_copy)
            inv, names = self._write_inventory(job)
            limit_file = os.path.join(job.dir, "limit.txt")
            with open(limit_file, "w") as f:
                f.write("\n".join(names) + "\n")
            cmd = ["ansible-playbook", "-i", inv, os.path.join(settings.ansible_dir, "collect.yml"),
                   "--limit", "@" + limit_file, "--private-key", key_copy,
                   "-f", str(settings.forks), "-T", str(settings.ssh_timeout),
                   "-e", f"amber_apt_refresh={'1' if p.get('apt_refresh') else '0'}"]
            if p.get("user"):
                cmd += ["-u", p["user"]]
            if p.get("become"):
                cmd += ["--become"]
            env = {
                **os.environ,
                "ANSIBLE_CONFIG": os.path.join(settings.ansible_dir, "ansible.cfg"),
                "ANSIBLE_HOME": os.path.join(job.dir, ".ansible"),
                "ANSIBLE_LOCAL_TEMP": os.path.join(job.dir, ".ansible", "tmp"),
                "ANSIBLE_SSH_CONTROL_PATH_DIR": os.path.join("/tmp", "acp-" + job.id[-6:]),
                "ANSIBLE_HOST_KEY_CHECKING": "True" if p.get("strict_host_keys") else "False",
                "AMBER_JOB_DIR": job.dir,
                "ANSIBLE_NOCOLOR": "1",
            }
            with open(os.path.join(job.dir, "ansible.log"), "w") as logf:
                job.proc = subprocess.Popen(cmd, cwd=settings.ansible_dir, stdout=logf, stderr=subprocess.STDOUT,
                                            env=env, start_new_session=True)
                try:
                    job.proc.wait(timeout=settings.job_timeout)
                except subprocess.TimeoutExpired:
                    os.killpg(job.proc.pid, signal.SIGTERM)
                    job.message = "Таймаут задания — отчёт по уже опрошенным хостам"
            note = "Отменено — отчёт по уже опрошенным хостам" if job.cancelled else (
                job.message if job.message.startswith("Таймаут") else "")
            job.state = "analyzing"
            job.message = "Анализ пакетов и уязвимостей…"
            build_report(job.id, job.dir, p)
            job.state = "done"
            job.message = note or "Готово"
        except Exception as e:
            log.exception("job failed")
            job.state = "error"
            job.message = str(e)
        finally:
            job.finished = time.time()
            if os.path.exists(key_copy):
                os.unlink(key_copy)
            shutil.rmtree(os.path.join(job.dir, ".ansible"), ignore_errors=True)


def build_report(report_id: str, job_dir: str, params: dict | None = None) -> dict:
    """(Re)build report from raw per-host results. Used after a job and for 're-analyze'."""
    params = params or json.load(open(os.path.join(job_dir, "params.json")))
    vdb = get_vulndb()
    ctx = {"tracked": vdb.tracked_sources(), "releases": vdb.releases(), "cache": {}}
    hosts = []
    results_dir = os.path.join(job_dir, "results")
    seen = set()
    for fn in sorted(os.listdir(results_dir)):
        if not fn.endswith(".json"):
            continue
        r = json.load(open(os.path.join(results_dir, fn)))
        seen.add(r["host"])
        meta = next((h for h in params["hosts"] if (h.get("name") or h["ip"]) == r["host"]), {})
        base = {"name": r["host"], "ip": meta.get("ip", r["host"]), "groups": meta.get("groups", [])}
        if r["status"] != "ok":
            msg = r.get("msg") or r.get("stderr") or ""
            hosts.append({**base, "state": r["status"], "error": _humanize_error(msg)})
            continue
        h = parse_collector_output(r["stdout"])
        h.update(base)
        h["state"] = "ok" if h["complete"] else "partial"
        h = analyze_host(h, vdb, ctx)
        if h["state"] == "partial":
            h["state"] = "ok"
            h["findings"].insert(0, {"level": "warn", "area": "Сбор", "text": "Вывод сборщика неполный", "hint": ""})
        hosts.append(h)
    for hp in params["hosts"]:
        n = hp.get("name") or hp["ip"]
        if n not in seen:
            hosts.append({"name": n, "ip": hp["ip"], "groups": hp.get("groups", []), "state": "skipped",
                          "error": "Хост не опрошен (отмена, таймаут или исключён из inventory)"})
    hosts.sort(key=lambda h: (h["state"] != "ok", -h.get("risk", 0), h["name"]))
    meta = get_vulndb().meta()
    report = {
        "id": report_id,
        "created": time.time(),
        "source": params.get("source", ""),
        "source_label": params.get("source_label", ""),
        "user": params.get("user", ""),
        "become": bool(params.get("become")),
        "apt_refresh": bool(params.get("apt_refresh")),
        "watchlist": settings.watchlist,
        "db": {k: meta.get(k) for k in ("tracker_imported", "tracker_file_mtime", "kev_imported", "kev_version",
                                         "epss_imported", "epss_model", "releases")},
        "fleet": build_fleet(hosts),
        "hosts": hosts,
    }
    tmp = os.path.join(REPORTS_DIR, report_id + ".json.tmp")
    with open(tmp, "w") as f:
        json.dump(report, f, ensure_ascii=False, separators=(",", ":"))
    os.replace(tmp, os.path.join(REPORTS_DIR, report_id + ".json"))
    return report


def _humanize_error(msg: str) -> str:
    m = msg.lower()
    if "permission denied" in m:
        return "SSH: доступ запрещён (ключ не подходит или неверный пользователь). " + msg[-200:]
    if "timed out" in m or "timeout" in m:
        return "SSH: таймаут подключения. " + msg[-200:]
    if "connection refused" in m:
        return "SSH: соединение отклонено. " + msg[-200:]
    if "no route" in m or "unreachable" in m:
        return "Хост недоступен по сети. " + msg[-200:]
    if "host key" in m:
        return "SSH: проблема с host key. " + msg[-200:]
    if "sudo" in m or "become" in m:
        return "sudo/become не удался (нужен NOPASSWD или запуск без become). " + msg[-200:]
    return msg[-400:]


def list_reports() -> list[dict]:
    out = []
    for fn in sorted(os.listdir(REPORTS_DIR), reverse=True):
        if not fn.endswith(".json"):
            continue
        path = os.path.join(REPORTS_DIR, fn)
        try:
            with open(path) as f:
                r = json.load(f)
        except Exception:
            continue
        fl = r.get("fleet", {})
        out.append({"id": r["id"], "created": r["created"], "source_label": r.get("source_label", ""),
                    "hosts": fl.get("hosts_total", 0), "ok": fl.get("hosts_ok", 0), "severity": fl.get("severity", {}),
                    "kev": len(fl.get("kev_cves", []))})
    return out[:100]


manager = JobManager()
