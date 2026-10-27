"""Vulnerability database: Debian Security Tracker + CISA KEV + FIRST EPSS (+ optional NVD CVSS).

All feeds are downloaded into $AMBER_DATA/feeds and imported into a SQLite file so that
matching thousands of packages across many hosts stays fast and memory-light.
"""
from __future__ import annotations

import csv
import gzip
import io
import json
import logging
import os
import shutil
import sqlite3
import threading
import time
import urllib.request
from contextlib import closing

import ijson

from .config import settings

log = logging.getLogger("amberventory.vulndb")

TRACKER_URL = os.environ.get("AMBER_TRACKER_URL", "https://security-tracker.debian.org/tracker/data/json")
KEV_URL = os.environ.get(
    "AMBER_KEV_URL", "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")
EPSS_URLS = [u for u in os.environ.get(
    "AMBER_EPSS_URL",
    "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz,https://epss.cyentia.com/epss_scores-current.csv.gz",
).split(",") if u]
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
UA = "AmberVentory/1.0 (+self-hosted inventory)"

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS vuln(src TEXT, cve TEXT, release TEXT, status TEXT, fixed TEXT,
                                urgency TEXT, nodsa TEXT, nodsa_reason TEXT);
CREATE INDEX IF NOT EXISTS vuln_rel_src ON vuln(release, src);
CREATE TABLE IF NOT EXISTS cve(cve TEXT PRIMARY KEY, description TEXT, scope TEXT, debianbug INTEGER);
CREATE TABLE IF NOT EXISTS srcpkg(src TEXT PRIMARY KEY);
CREATE TABLE IF NOT EXISTS releases(release TEXT PRIMARY KEY);
CREATE TABLE IF NOT EXISTS kev(cve TEXT PRIMARY KEY, vendor TEXT, product TEXT, name TEXT,
                               date_added TEXT, due_date TEXT, ransomware TEXT, action TEXT);
CREATE TABLE IF NOT EXISTS epss(cve TEXT PRIMARY KEY, score REAL, pct REAL);
CREATE TABLE IF NOT EXISTS cvss(cve TEXT PRIMARY KEY, score REAL, severity TEXT, vector TEXT, fetched REAL);
"""



def verify_gzip_complete(path: str) -> None:
    """Read the whole gzip stream; raise if it is truncated or corrupt."""
    with gzip.open(path, "rb") as f:
        while f.read(1024 * 1024):
            pass


class VulnDB:
    def __init__(self):
        self.feeds_dir = os.path.join(settings.data_dir, "feeds")
        self.db_path = os.path.join(settings.data_dir, "vulndb.sqlite")
        os.makedirs(self.feeds_dir, exist_ok=True)
        self.lock = threading.Lock()
        self.status = {"state": "idle", "message": "", "progress": 0, "started": None}
        with closing(self.connect()) as c:
            c.executescript(SCHEMA)

    # ------------------------------------------------------------------ utils
    def connect(self):
        c = sqlite3.connect(self.db_path, timeout=60)
        c.execute("PRAGMA journal_mode=WAL")
        return c

    def meta(self) -> dict:
        with closing(self.connect()) as c:
            rows = dict(c.execute("SELECT key, value FROM meta").fetchall())
            rels = [r[0] for r in c.execute("SELECT release FROM releases ORDER BY release")]
        rows["releases"] = rels
        rows["status"] = self.status
        rows["ready"] = bool(rows.get("tracker_imported"))
        return rows

    def _set_meta(self, c, key, value):
        c.execute("INSERT OR REPLACE INTO meta(key, value) VALUES(?, ?)", (key, str(value)))

    def _download(self, url: str, dest: str, label: str):
        self.status.update(message=f"Загрузка {label}…")
        req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept-Encoding": "gzip"})
        tmp = dest + ".part"
        with urllib.request.urlopen(req, timeout=120) as r, open(tmp, "wb") as f:
            gz = r.headers.get("Content-Encoding") == "gzip"
            src = gzip.GzipFile(fileobj=r) if gz else r
            shutil.copyfileobj(src, f, 1024 * 1024)
        os.replace(tmp, dest)

    # ---------------------------------------------------------------- update
    def update_async(self, force=False):
        if self.status["state"] == "running":
            return False
        threading.Thread(target=self.update, kwargs={"force": force}, daemon=True).start()
        return True

    def update(self, force=False):
        if not self.lock.acquire(blocking=False):
            return
        self.status = {"state": "running", "message": "Старт", "progress": 0, "started": time.time(), "errors": []}
        try:
            tracker = os.path.join(self.feeds_dir, "debian-tracker.json")
            kev = os.path.join(self.feeds_dir, "kev.json")
            epss = os.path.join(self.feeds_dir, "epss.csv.gz")
            steps = [
                ("Debian Security Tracker", lambda: self._download(TRACKER_URL, tracker, "Debian Security Tracker")),
                ("CISA KEV", lambda: self._download(KEV_URL, kev, "CISA KEV")),
                ("EPSS", lambda: self._download_epss(epss)),
            ]
            for i, (label, fn) in enumerate(steps):
                path = {0: tracker, 1: kev, 2: epss}[i]
                fresh = os.path.exists(path) and time.time() - os.path.getmtime(path) < settings.feed_ttl
                if fresh and not force:
                    continue
                try:
                    fn()
                except Exception as e:  # keep going with cached copy (air-gapped / partial outage)
                    log.warning("download %s failed: %s", label, e)
                    self.status["errors"].append(f"{label}: {e}")
                self.status["progress"] = 10 + i * 10
            if os.path.exists(tracker):
                self.import_tracker(tracker)
            if os.path.exists(kev):
                self.import_kev(kev)
            if os.path.exists(epss):
                try:
                    self.import_epss(epss)
                except Exception as e:  # a bad EPSS file must not block the tracker and KEV data
                    log.warning("EPSS import failed, removing the file so the next run downloads it: %s", e)
                    self.status["errors"].append(f"EPSS: импорт не удался ({e})")
                    os.unlink(epss)
            if not os.path.exists(tracker):
                raise RuntimeError("Нет данных Debian Security Tracker: загрузка не удалась, "
                                   "а локальной копии нет. Загрузите JSON вручную в интерфейсе.")
            self.status.update(state="done", message="Базы обновлены", progress=100)
        except Exception as e:
            log.exception("vulndb update failed")
            self.status.update(state="error", message=str(e))
        finally:
            self.lock.release()

    def _download_epss(self, dest):
        """Download EPSS to a temp file and replace the cached copy only if the download is complete.

        A truncated transfer (proxy reset, network drop) still yields a readable HTTP body, so a
        Content-Length check and a full gzip read are needed before the file is trusted.
        """
        last = None
        for url in EPSS_URLS:
            tmp = dest + ".part"
            try:
                req = urllib.request.Request(url.strip(), headers={"User-Agent": UA})
                with urllib.request.urlopen(req, timeout=120) as r, open(tmp, "wb") as f:
                    expected = r.headers.get("Content-Length")
                    shutil.copyfileobj(r, f, 1024 * 1024)
                if expected is not None and os.path.getsize(tmp) != int(expected):
                    raise OSError(f"загрузка обрезана: получено {os.path.getsize(tmp)} из {expected} байт")
                verify_gzip_complete(tmp)
                os.replace(tmp, dest)
                return
            except Exception as e:
                last = e
                log.warning("EPSS from %s rejected: %s", url.strip(), e)
                if os.path.exists(tmp):
                    os.unlink(tmp)
        raise last or RuntimeError("EPSS unavailable")

    def import_tracker(self, path):
        self.status.update(message="Импорт Debian Security Tracker…", progress=40)
        t0 = time.time()
        with closing(self.connect()) as c, open(path, "rb") as f:
            c.execute("BEGIN")
            c.execute("DELETE FROM vuln")
            c.execute("DELETE FROM cve")
            c.execute("DELETE FROM srcpkg")
            c.execute("DELETE FROM releases")
            releases, rows, cve_rows, cves, n = set(), [], [], set(), 0
            for src, entries in ijson.kvitems(f, "", use_float=True):
                c.execute("INSERT OR IGNORE INTO srcpkg(src) VALUES(?)", (src,))
                for cve_id, info in entries.items():
                    if cve_id not in cves:
                        cves.add(cve_id)
                        cve_rows.append((cve_id, (info.get("description") or "")[:600],
                                         info.get("scope") or "", info.get("debianbug")))
                    for rel, r in (info.get("releases") or {}).items():
                        releases.add(rel)
                        rows.append((src, cve_id, rel, r.get("status", ""), r.get("fixed_version") or "",
                                     (r.get("urgency") or "").replace("*", "").strip(),
                                     r.get("nodsa") or "", r.get("nodsa_reason") or ""))
                n += 1
                if len(rows) > 50000:
                    c.executemany("INSERT INTO vuln VALUES(?,?,?,?,?,?,?,?)", rows)
                    c.executemany("INSERT OR REPLACE INTO cve VALUES(?,?,?,?)", cve_rows)
                    rows.clear()
                    cve_rows.clear()
                    self.status["message"] = f"Импорт трекера: {n} исходных пакетов…"
            c.executemany("INSERT INTO vuln VALUES(?,?,?,?,?,?,?,?)", rows)
            c.executemany("INSERT OR REPLACE INTO cve VALUES(?,?,?,?)", cve_rows)
            c.executemany("INSERT OR IGNORE INTO releases VALUES(?)", [(r,) for r in releases])
            self._set_meta(c, "tracker_imported", int(time.time()))
            self._set_meta(c, "tracker_file_mtime", int(os.path.getmtime(path)))
            self._set_meta(c, "tracker_sources", n)
            self._set_meta(c, "tracker_cves", len(cves))
            c.execute("COMMIT")
        log.info("tracker imported: %s sources, %s ids in %.1fs", n, len(cves), time.time() - t0)

    def import_kev(self, path):
        self.status.update(message="Импорт CISA KEV…", progress=80)
        with open(path, "rb") as f:
            data = json.load(f)
        vulns = data.get("vulnerabilities", [])
        with closing(self.connect()) as c:
            c.execute("BEGIN")
            c.execute("DELETE FROM kev")
            c.executemany("INSERT OR REPLACE INTO kev VALUES(?,?,?,?,?,?,?,?)", [
                (v.get("cveID"), v.get("vendorProject"), v.get("product"), v.get("vulnerabilityName"),
                 v.get("dateAdded"), v.get("dueDate"), v.get("knownRansomwareCampaignUse"),
                 v.get("requiredAction")) for v in vulns if v.get("cveID")])
            self._set_meta(c, "kev_imported", int(time.time()))
            self._set_meta(c, "kev_count", len(vulns))
            self._set_meta(c, "kev_version", data.get("catalogVersion", ""))
            c.execute("COMMIT")

    def import_epss(self, path):
        self.status.update(message="Импорт EPSS…", progress=90)
        rows, model = [], ""
        with gzip.open(path, "rt", encoding="utf-8", errors="replace") as f:
            first = f.readline()
            if first.startswith("#"):
                model = first.strip("#\n ")
            else:
                f = io.StringIO(first + f.read())
            for r in csv.DictReader(f):
                try:
                    rows.append((r["cve"], float(r["epss"]), float(r["percentile"])))
                except (KeyError, ValueError):
                    continue
        with closing(self.connect()) as c:
            c.execute("BEGIN")
            c.execute("DELETE FROM epss")
            c.executemany("INSERT OR REPLACE INTO epss VALUES(?,?,?)", rows)
            self._set_meta(c, "epss_imported", int(time.time()))
            self._set_meta(c, "epss_model", model)
            self._set_meta(c, "epss_count", len(rows))
            c.execute("COMMIT")

    def import_uploaded_tracker(self, tmp_path):
        """Air-gapped mode: user uploads tracker JSON manually."""
        dest = os.path.join(self.feeds_dir, "debian-tracker.json")
        shutil.move(tmp_path, dest)
        os.utime(dest)

        def run():
            with self.lock:
                self.status = {"state": "running", "message": "Импорт загруженного файла", "progress": 30,
                               "started": time.time(), "errors": []}
                try:
                    self.import_tracker(dest)
                    self.status.update(state="done", message="Трекер импортирован", progress=100)
                except Exception as e:
                    self.status.update(state="error", message=f"Ошибка импорта: {e}")
        threading.Thread(target=run, daemon=True).start()

    # --------------------------------------------------------------- queries
    def tracked_sources(self) -> set[str]:
        with closing(self.connect()) as c:
            return {r[0] for r in c.execute("SELECT src FROM srcpkg")}

    def releases(self) -> set[str]:
        with closing(self.connect()) as c:
            return {r[0] for r in c.execute("SELECT release FROM releases")}

    def rows_for(self, c, release: str, src: str):
        return c.execute(
            "SELECT v.cve, v.status, v.fixed, v.urgency, v.nodsa, v.nodsa_reason, "
            "       ci.description, ci.scope, k.cve IS NOT NULL, k.date_added, k.ransomware, k.name, "
            "       e.score, e.pct, s.score, s.severity "
            "FROM vuln v LEFT JOIN cve ci ON ci.cve = v.cve "
            "LEFT JOIN kev k ON k.cve = v.cve LEFT JOIN epss e ON e.cve = v.cve "
            "LEFT JOIN cvss s ON s.cve = v.cve "
            "WHERE v.release = ? AND v.src = ?", (release, src)).fetchall()

    # ------------------------------------------------------- NVD enrichment
    def enrich_cvss_async(self, cves: list[str]):
        if self.status["state"] == "running":
            return False
        threading.Thread(target=self.enrich_cvss, args=(cves,), daemon=True).start()
        return True

    def enrich_cvss(self, cves: list[str]):
        if not self.lock.acquire(blocking=False):
            return
        key = os.environ.get("NVD_API_KEY", "")
        delay = 0.7 if key else 6.2  # NVD public rate limits
        self.status = {"state": "running", "message": "NVD: получение CVSS…", "progress": 0,
                       "started": time.time(), "errors": []}
        try:
            with closing(self.connect()) as c:
                known = {r[0] for r in c.execute("SELECT cve FROM cvss")}
            todo = [x for x in dict.fromkeys(cves) if x.startswith("CVE-") and x not in known]
            todo = todo[: settings.nvd_max_per_run]
            for i, cve_id in enumerate(todo):
                self.status.update(message=f"NVD: {cve_id} ({i + 1}/{len(todo)})",
                                   progress=int(100 * i / max(1, len(todo))))
                try:
                    req = urllib.request.Request(f"{NVD_API}?cveId={cve_id}",
                                                 headers={"User-Agent": UA, **({"apiKey": key} if key else {})})
                    with urllib.request.urlopen(req, timeout=30) as r:
                        data = json.load(r)
                    score, sev, vec = _extract_cvss(data)
                    with closing(self.connect()) as c:
                        c.execute("INSERT OR REPLACE INTO cvss VALUES(?,?,?,?,?)",
                                  (cve_id, score, sev, vec, time.time()))
                        c.commit()
                except Exception as e:
                    self.status["errors"].append(f"{cve_id}: {e}")
                    if len(self.status["errors"]) > 5 and i < 6:
                        raise RuntimeError("NVD недоступен: " + str(e)) from e
                time.sleep(delay)
            self.status.update(state="done", message=f"CVSS получены для {len(todo)} CVE", progress=100)
        except Exception as e:
            self.status.update(state="error", message=str(e))
        finally:
            self.lock.release()


def _extract_cvss(data):
    try:
        metrics = data["vulnerabilities"][0]["cve"].get("metrics", {})
    except (KeyError, IndexError):
        return None, "", ""
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        items = metrics.get(key) or []
        items = sorted(items, key=lambda m: m.get("type") != "Primary")
        for m in items:
            d = m.get("cvssData", {})
            score = d.get("baseScore")
            if score is not None:
                sev = d.get("baseSeverity") or m.get("baseSeverity") or ""
                return float(score), sev.upper(), d.get("vectorString", "")
    return None, "", ""


vulndb: VulnDB | None = None


def get_vulndb() -> VulnDB:
    global vulndb
    if vulndb is None:
        vulndb = VulnDB()
    return vulndb
