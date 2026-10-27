"""Turn parsed host data + vulnerability DB into an annotated report."""
from __future__ import annotations

import fnmatch
import re
import time
from collections import defaultdict
from contextlib import closing
from datetime import date

from . import debver
from .config import DEBIAN_RELEASES, MAJOR_TO_CODENAME, settings

SEV_RANK = {"critical": 5, "high": 4, "medium": 3, "unrated": 2, "low": 1, "negligible": 0}
URGENCY_SEV = {"high": "high", "medium": "medium", "low": "low", "unimportant": "negligible"}
THIRD_PARTY_RE = re.compile(r"(\+0~\d{8}|sury|~debian\.\d+|\.el\d|ubuntu|\+deb\.|-dotdeb|~nginx|"
                            r"pgdg|\.mariadb|percona|~bookworm\d|~trixie\d|~bullseye\d)", re.I)
DB_PORTS = {5432: "PostgreSQL", 3306: "MySQL/MariaDB", 6379: "Redis", 27017: "MongoDB", 9200: "Elasticsearch",
            11211: "Memcached", 2379: "etcd", 5672: "RabbitMQ", 15672: "RabbitMQ UI", 9092: "Kafka",
            8086: "InfluxDB", 9000: "ClickHouse/MinIO", 8123: "ClickHouse HTTP", 2375: "Docker API (без TLS!)",
            10250: "kubelet", 6443: "Kubernetes API"}


def severity_of(urgency: str, kev: bool, epss: float | None, cvss: float | None) -> tuple[str, str]:
    """Return (severity, reason). Debian urgency first, CVSS as fallback, KEV/EPSS escalate."""
    sev, why = URGENCY_SEV.get(urgency), f"Debian urgency: {urgency}" if urgency else ""
    if sev is None:
        if cvss is not None:
            sev = "critical" if cvss >= 9 else "high" if cvss >= 7 else "medium" if cvss >= 4 else "low"
            why = f"CVSS {cvss:.1f} (NVD)"
        else:
            sev, why = "unrated", "Debian ещё не оценил, CVSS не загружен"
    if epss is not None and epss >= 0.5 and SEV_RANK[sev] < SEV_RANK["high"]:
        sev, why = "high", f"EPSS {epss:.0%}: высокая вероятность эксплуатации"
    if kev:
        sev, why = "critical", "CISA KEV: эксплуатируется в реальных атаках"
    return sev, why


def release_state(codename: str, os_id: str) -> dict:
    if os_id and os_id != "debian":
        return {"state": "non-debian", "label": "Не Debian", "level": "warn",
                "note": "Сопоставление с Debian Security Tracker не применяется"}
    info = DEBIAN_RELEASES.get(codename)
    if not info:
        return {"state": "unknown", "label": "Неизвестный релиз", "level": "warn", "note": ""}
    major, eol, lts = info
    today = date.today().isoformat()
    if codename in ("sid", "forky"):
        return {"state": "testing", "label": "testing/unstable", "level": "warn",
                "note": "Нет гарантированной поддержки безопасности"}
    if eol and today <= eol:
        return {"state": "supported", "label": "Поддерживается", "level": "ok",
                "note": f"Security-поддержка до {eol}, LTS до {lts}"}
    if lts and today <= lts:
        return {"state": "lts", "label": "Debian LTS", "level": "info",
                "note": f"Основная поддержка закончилась {eol}; LTS до {lts}. Проверьте, что подключён security-репозиторий"}
    return {"state": "eol", "label": "EOL", "level": "crit",
            "note": f"Поддержка (включая LTS) закончилась {lts}. Обновления безопасности не выходят — только ELTS (платно) или апгрейд релиза"}


def matches_watch(name: str, patterns) -> bool:
    return any(fnmatch.fnmatch(name, p) for p in patterns)


def analyze_host(host: dict, vdb, ctx: dict) -> dict:
    """ctx carries cached data shared across hosts: tracked sources, releases, query cache."""
    os_ = host["os"]
    codename = os_.get("codename") or ""
    if not codename and os_.get("debian_version", "")[:2].rstrip(".").isdigit():
        codename = MAJOR_TO_CODENAME.get(int(os_["debian_version"].split(".")[0]), "")
        os_["codename"] = codename
    rel = release_state(codename, os_.get("id", ""))
    host["release"] = rel
    tracker_ok = rel["state"] != "non-debian" and codename in ctx["releases"]
    host["tracker_available"] = tracker_ok

    # group binaries by source package
    by_src: dict[tuple[str, str], list[dict]] = defaultdict(list)
    for p in host["packages"]:
        if p["source"] == "linux":  # several kernels may be installed: assess once, by the running one
            by_src[("linux", "")].append(p)
        else:
            by_src[(p["source"], p["source_version"])].append(p)
    upg = {u["name"]: u for u in host["upgradable"]}
    for p in host["packages"]:
        u = upg.get(p["name"])
        p["candidate"] = u["new"] if u else ""
        p["security_update"] = bool(u and u["security"])
        p["watch"] = matches_watch(p["name"], settings.watchlist) or matches_watch(p["source"], settings.watchlist)
        p["third_party"] = bool(THIRD_PARTY_RE.search(p["version"]))
        p["tracked"] = p["source"] in ctx["tracked"] or p["source"].startswith("linux-signed")
        p["vulns"] = {k: 0 for k in SEV_RANK}
        p["max_sev"] = ""

    running_kernel = host["system"].get("kernel_pkg_version")
    vulns = []
    if tracker_ok:
        cache = ctx["cache"]
        with closing(vdb.connect()) as c:
            for (src, sver), bins in by_src.items():
                if src.startswith("linux-signed-"):
                    continue
                check_ver = sver
                note = ""
                if src == "linux":
                    if running_kernel:
                        check_ver, note = running_kernel, "версия запущенного ядра"
                    else:
                        check_ver = max((b["source_version"] for b in bins), key=_VerKey)
                        note = "версия самого нового установленного ядра (запущенное не определено)"
                key = (codename, src)
                if key not in cache:
                    cache[key] = vdb.rows_for(c, codename, src)
                for (cve, status, fixed, urgency, nodsa, nodsa_reason, desc, scope, kev, kev_added,
                     ransomware, kev_name, epss, epss_pct, cvss, _cvss_sev) in cache[key]:
                    if status == "resolved":
                        if not fixed or fixed == "0":
                            continue
                        if not debver.lt(check_ver, fixed):
                            continue
                        state = "fixable"
                    elif status == "open":
                        state = "postponed" if nodsa else "no_fix"
                    elif status == "undetermined":
                        state = "undetermined"
                    else:
                        continue
                    if urgency == "end-of-life":
                        state = "pkg_eol"
                    sev, why = severity_of(urgency, bool(kev), epss, cvss)
                    if urgency == "unimportant" and not kev:
                        sev, why = "negligible", "Debian: unimportant"
                    cand = max((upg[b["name"]]["new"] for b in bins if b["name"] in upg),
                               default="", key=lambda v: _VerKey(v))
                    fixed_by_apt = bool(cand and fixed and fixed != "0" and not debver.lt(cand, fixed))
                    fixed_by_reboot = False
                    if src == "linux" and state == "fixable":
                        newest = max((b["source_version"] for b in bins), key=_VerKey)
                        fixed_by_reboot = not debver.lt(newest, fixed)
                    v = {
                        "cve": cve, "src": src, "installed": check_ver, "fixed": fixed if fixed != "0" else "",
                        "status": state, "urgency": urgency or "not yet assigned", "severity": sev, "why": why,
                        "nodsa": nodsa, "nodsa_reason": nodsa_reason, "scope": scope or "",
                        "description": desc or "", "kev": bool(kev), "kev_added": kev_added,
                        "kev_ransomware": ransomware == "Known", "kev_name": kev_name,
                        "epss": epss, "epss_pct": epss_pct, "cvss": cvss, "candidate": cand,
                        "fixed_by_apt": fixed_by_apt, "fixed_by_reboot": fixed_by_reboot, "binaries": sorted(b["name"] for b in bins),
                        "watch": any(b["watch"] for b in bins), "note": note,
                    }
                    vulns.append(v)
                    for b in bins:
                        b["vulns"][sev] += 1
                        if not b["max_sev"] or SEV_RANK[sev] > SEV_RANK[b["max_sev"]]:
                            b["max_sev"] = sev
    vulns.sort(key=lambda v: (-SEV_RANK[v["severity"]], v["status"] != "fixable",
                              -(v["epss"] or 0), v["src"], v["cve"]))
    host["vulns"] = vulns

    active = [v for v in vulns if v["status"] in ("fixable", "no_fix") and v["severity"] != "negligible"]
    counts = {k: 0 for k in SEV_RANK}
    for v in active:
        counts[v["severity"]] += 1
    host["summary"] = {
        "vuln_counts": counts,
        "vuln_total": len(active),
        "fixable": sum(1 for v in active if v["status"] == "fixable"),
        "no_fix": sum(1 for v in active if v["status"] == "no_fix"),
        "postponed": sum(1 for v in vulns if v["status"] == "postponed"),
        "kev": len({v["cve"] for v in active if v["kev"]}),
        "packages": len(host["packages"]),
        "upgradable": len(host["upgradable"]),
        "security_updates": sum(1 for u in host["upgradable"] if u["security"]),
        "untracked": sum(1 for p in host["packages"] if not p["tracked"]),
        "third_party": sum(1 for p in host["packages"] if p["third_party"]),
        "services": sum(1 for s in host["services"] if not s["system"]),
    }
    host["findings"] = findings_for(host)
    host["risk"] = risk_score(host)
    return host


class _VerKey:
    def __init__(self, v):
        self.v = v

    def __lt__(self, other):
        if not self.v:
            return True
        if not other.v:
            return False
        return debver.lt(self.v, other.v)


def findings_for(h: dict) -> list[dict]:
    f = []

    def add(level, area, text, hint=""):
        f.append({"level": level, "area": area, "text": text, "hint": hint})

    rel = h["release"]
    if rel["state"] in ("eol", "unknown", "testing", "non-debian"):
        add("crit" if rel["state"] == "eol" else "warn", "ОС",
            f"{h['os'].get('pretty') or 'ОС'}: {rel['label']}", rel["note"])
    elif rel["state"] == "lts":
        add("info", "ОС", f"{h['os'].get('pretty')}: Debian LTS", rel["note"])
    if h["os"].get("id") == "debian" and not h.get("tracker_available"):
        add("warn", "Уязвимости", f"Релиза «{h['os'].get('codename')}» нет в базе Debian Security Tracker",
            "Сопоставление CVE для этого хоста не выполнено")
    s = h["summary"]
    if s["kev"]:
        add("crit", "Уязвимости", f"{s['kev']} CVE из каталога CISA KEV (эксплуатируются в атаках)",
            "Обновить затронутые пакеты в первую очередь")
    srcs = " ".join(h["apt_sources"])
    if h["os"].get("id") == "debian" and h["apt_sources"] and "security" not in srcs:
        add("crit", "APT", "Не подключён security-репозиторий",
            "Обновления безопасности не приходят через apt. Добавьте deb http://security.debian.org/debian-security <codename>-security main")
    last = h["system"].get("apt_last_update")
    if last and time.time() - last > 7 * 86400:
        days = int((time.time() - last) / 86400)
        add("warn", "APT", f"Списки пакетов apt не обновлялись {days} дн.",
            "Список доступных обновлений может быть неполным; включите «apt update» при запуске")
    if s["security_updates"]:
        add("warn", "APT", f"Доступно {s['security_updates']} обновлений безопасности", "apt-get upgrade")
    if not h["system"].get("unattended_upgrades"):
        add("info", "APT", "unattended-upgrades не установлен")
    if h["system"].get("reboot_required"):
        add("warn", "Ядро", "Требуется перезагрузка (/var/run/reboot-required)",
            " ".join(h["system"].get("reboot_required_pkgs", [])[:8]))
    kv = h["system"].get("kernel_pkg_version")
    imgs = [p for p in h["packages"] if p["name"].startswith("linux-image-") and re.match(r"linux-image-\d", p["name"])]
    if kv and imgs:
        newest = max((p["version"] for p in imgs), key=_VerKey)
        if debver.lt(kv, newest):
            add("warn", "Ядро", f"Запущено ядро {kv}, установлено более новое {newest}",
                "Исправления ядра не действуют до перезагрузки")
    for d in h["disks"]:
        if d["fstype"].startswith("fuse") or d["fstype"] in ("nfs", "nfs4", "cifs"):
            continue
        if d["pct"] >= 90:
            add("crit", "Диски", f"{d['mount']}: занято {d['pct']}%", f"свободно {fmt_kb(d['avail_kb'])}")
        elif d["pct"] >= 80:
            add("warn", "Диски", f"{d['mount']}: занято {d['pct']}%", f"свободно {fmt_kb(d['avail_kb'])}")
        if (d.get("inode_pct") or 0) >= 85:
            add("warn", "Диски", f"{d['mount']}: inode заняты на {d['inode_pct']}%")
    for u in h["users"]:
        if u["uid"] == 0 and u["name"] != "root":
            add("crit", "Пользователи", f"Пользователь {u['name']} имеет UID 0")
    if h["failed_units"]:
        add("warn", "Службы", f"Упавшие юниты: {', '.join(h['failed_units'][:6])}")
    sshd = h.get("sshd") or {}
    if sshd.get("permitrootlogin") == "yes":
        add("warn", "SSH", "PermitRootLogin yes", "Рекомендуется prohibit-password или no")
    if sshd.get("passwordauthentication") == "yes":
        add("warn", "SSH", "Разрешён вход по паролю (PasswordAuthentication yes)")
    if sshd.get("permitemptypasswords") == "yes":
        add("crit", "SSH", "Разрешены пустые пароли")
    for p in h["listening"]:
        if p["public"] and isinstance(p["port"], int) and p["port"] in DB_PORTS:
            add("warn", "Сеть", f"{DB_PORTS[p['port']]} слушает на всех интерфейсах ({p['proto']}/{p['port']})",
                "Ограничьте bind-адрес или закройте файрволом")
    for c in h["certs"]:
        if "expired" in c["issues"]:
            add("crit", "TLS", f"Сертификат просрочен: {c['path']}", c["subject"])
        elif "expires_soon" in c["issues"]:
            add("warn", "TLS", f"Сертификат истекает через {c['days_left']} дн.: {c['path']}", c["subject"])
        if "weak_signature" in c["issues"] or "weak_key" in c["issues"]:
            add("warn", "TLS", f"Слабая подпись/ключ: {c['path']}", f"{c['sig']} {c['bits'] or ''}")
    if s["untracked"]:
        add("info", "Уязвимости", f"{s['untracked']} пакетов вне Debian Security Tracker",
            "Сторонние репозитории (Docker, Sury PHP, PGDG и т.п.) или локальные сборки: CVE по ним не сопоставляются")
    order = {"crit": 0, "warn": 1, "info": 2}
    f.sort(key=lambda x: order[x["level"]])
    return f


def risk_score(h: dict) -> int:
    c = h["summary"]["vuln_counts"]
    score = c["critical"] * 25 + c["high"] * 6 + c["medium"] * 1.5 + c["unrated"] * 0.5 + c["low"] * 0.2
    score += sum(15 for f in h["findings"] if f["level"] == "crit") + sum(4 for f in h["findings"] if f["level"] == "warn")
    return int(min(100, score))


def fmt_kb(kb: int) -> str:
    n = float(kb) * 1024
    for unit in ("Б", "КБ", "МБ", "ГБ", "ТБ", "ПБ"):
        if n < 1024:
            return f"{n:.1f} {unit}" if unit not in ("Б", "КБ") else f"{n:.0f} {unit}"
        n /= 1024
    return f"{n:.1f} ЭБ"


def build_fleet(hosts: list[dict]) -> dict:
    sev = {k: 0 for k in SEV_RANK}
    cve_hosts: dict[str, dict] = {}
    for h in hosts:
        if h.get("state") != "ok":
            continue
        for k, v in h["summary"]["vuln_counts"].items():
            sev[k] += v
        for v in h["vulns"]:
            if v["status"] not in ("fixable", "no_fix") or v["severity"] == "negligible":
                continue
            e = cve_hosts.setdefault(v["cve"], {"cve": v["cve"], "src": v["src"], "severity": v["severity"],
                                                "kev": v["kev"], "epss": v["epss"], "hosts": [],
                                                "fixable": v["status"] == "fixable", "description": v["description"],
                                                "watch": v["watch"]})
            if h["name"] not in e["hosts"]:
                e["hosts"].append(h["name"])
            if SEV_RANK[v["severity"]] > SEV_RANK[e["severity"]]:
                e["severity"] = v["severity"]
    top = sorted(cve_hosts.values(), key=lambda e: (-SEV_RANK[e["severity"]], -len(e["hosts"]), -(e["epss"] or 0)))
    ok = [h for h in hosts if h.get("state") == "ok"]
    releases = defaultdict(int)
    for h in ok:
        releases[h["os"].get("pretty") or "?"] += 1
    services = defaultdict(list)
    for h in ok:
        for s in h["services"]:
            if not s["system"]:
                services[s["name"]].append(h["name"])
    return {
        "hosts_total": len(hosts),
        "hosts_ok": len(ok),
        "hosts_failed": len(hosts) - len(ok),
        "severity": sev,
        "kev_cves": sorted({e["cve"] for e in cve_hosts.values() if e["kev"]}),
        "unique_cves": len(cve_hosts),
        "top_cves": top[:150],
        "releases": dict(releases),
        "eol_hosts": [h["name"] for h in ok if h["release"]["state"] == "eol"],
        "reboot_hosts": [h["name"] for h in ok if h["system"].get("reboot_required")],
        "upgradable": sum(h["summary"]["upgradable"] for h in ok),
        "security_updates": sum(h["summary"]["security_updates"] for h in ok),
        "services": {k: sorted(v) for k, v in sorted(services.items())},
    }
