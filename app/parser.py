"""Parse collector.sh output into a structured host dict."""
from __future__ import annotations

import re
from datetime import UTC, datetime

# Services that belong to a stock Debian system; hidden by default in the UI.
SYSTEM_SERVICE_RE = re.compile(
    r"^(systemd-.*|dbus|dbus-broker|cron|anacron|atd|rsyslog|syslog-ng|getty@.*|serial-getty@.*|"
    r"ssh|sshd|networking|ifup@.*|NetworkManager|wpa_supplicant|polkit|udisks2|accounts-daemon|"
    r"user@.*|irqbalance|chrony|chronyd|ntp|ntpsec|ntpd|openntpd|unattended-upgrades|haveged|rngd|"
    r"lvm2-.*|multipathd|ModemManager|avahi-daemon|cups|cups-browsed|bluetooth|qemu-guest-agent|"
    r"open-vm-tools|vmtoolsd|vgauth|smartd|smartmontools|acpid|console-setup|keyboard-setup|kmod.*|"
    r"apparmor|auditd|packagekit|snapd|cloud-.*|google-.*|rc-local|upower|rtkit-daemon|mdmonitor|"
    r"iscsid|open-iscsi|rpcbind|nscd|unscd|sssd|ifupdown.*|resolvconf|hv-kvp-daemon|hv-vss-daemon|"
    r"hyperv-daemons.*|xe-daemon|xe-linux-distribution|lxcfs|blk-availability|mcelog|rasdaemon|"
    r"thermald|power-profiles-daemon|switcheroo-control|colord|gdm|lightdm|sddm|"
    r"wtmpdb.*|e2scrub.*|fstrim|logrotate|man-db|apt-daily.*|plymouth.*|dm-event|uuidd|"
    r"lm-sensors|fancontrol|iptables|netfilter-persistent|nftables|ufw|firewalld|tuned|"
    r"virtlogd|virtlockd|ssh@.*|sshd@.*|postfix@-?|exim4-base|containerd-shim.*)$"
)

CATEGORIES = [
    ("db", r"postgres|mysql|mariadb|mongod|redis|valkey|clickhouse|cassandra|elasticsearch|opensearch|"
           r"influx|memcached|etcd|couchdb|neo4j|keydb|scylla|pgbouncer|patroni|tarantool|questdb|solr"),
    ("web", r"nginx|apache2|httpd|caddy|haproxy|traefik|lighttpd|envoy|varnish|squid|php.*fpm|uwsgi|"
            r"gunicorn|tomcat|jetty|wildfly|pm2|unit$|openresty|angie|keepalived"),
    ("queue", r"rabbitmq|kafka|zookeeper|nats|mosquitto|activemq|artemis|redpanda|celery|emqx|beanstalkd"),
    ("containers", r"docker|containerd|podman|k3s|kubelet|rke2|crio|cri-o|lxc|lxd|incus|libvirtd|"
                   r"pve|proxmox|nomad|consul"),
    ("monitoring", r"prometheus|exporter|grafana|zabbix|telegraf|netdata|loki|promtail|alloy|vector|"
                   r"beat|fluent|victoria|vmagent|alertmanager|datadog|collectd|snmpd|icinga|nagios|"
                   r"nrpe|monit|uptime"),
    ("security", r"fail2ban|crowdsec|wazuh|ossec|clamav|openvpn|wireguard|wg-quick|strongswan|ipsec|"
                 r"vault|teleport|tailscale|zerotier|bind9|named|unbound|dnsmasq|pdns|freeradius|"
                 r"slapd|keycloak|samba-ad"),
    ("mail", r"postfix|exim4|dovecot|opendkim|rspamd|amavis|spamassassin|opendmarc"),
    ("devops", r"gitlab|gitea|forgejo|jenkins|runner|drone|harbor|nexus|artifactory|minio|ceph|"
               r"glusterd|nfs-server|nfs-kernel|smbd|nmbd|samba|syncthing|rsyncd|vsftpd|proftpd|"
               r"pure-ftpd|bacula|bareos|restic|borg|ansible|salt|puppet|chef"),
]
CATEGORY_RES = [(name, re.compile(rx, re.I)) for name, rx in CATEGORIES]


def _kv(lines):
    out = {}
    for ln in lines:
        if "=" in ln:
            k, v = ln.split("=", 1)
            out[k.strip()] = v.strip().strip('"')
    return out


def _int(v, default=None):
    try:
        return int(v)
    except (TypeError, ValueError):
        return default


def split_sections(text: str) -> dict[str, list[str]]:
    sections: dict[str, list[str]] = {}
    cur = None
    for ln in text.splitlines():
        if ln.startswith("@@ "):
            cur = ln[3:].strip()
            sections.setdefault(cur, [])
            continue
        if cur is not None:
            sections[cur].append(ln.rstrip("\n"))
    return sections


def classify_service(unit: str) -> tuple[str, bool]:
    base = unit[:-8] if unit.endswith(".service") else unit
    if SYSTEM_SERVICE_RE.match(base):
        return "system", True
    for name, rx in CATEGORY_RES:
        if rx.search(base):
            return name, False
    return "other", False


def parse_ss(lines):
    out = []
    for ln in lines:
        parts = ln.split()
        if len(parts) < 5 or parts[0] in ("Netid", "Proto"):
            continue
        if parts[0] in ("tcp", "udp", "tcp6", "udp6") and parts[1] in ("LISTEN", "UNCONN"):
            proto, local, rest = parts[0], parts[4], " ".join(parts[6:])
        elif parts[0].startswith(("tcp", "udp")):  # netstat
            proto, local, rest = parts[0], parts[3], parts[-1]
        else:
            continue
        addr, _, port = local.rpartition(":")
        procs = re.findall(r'"([^"]+)"', rest) or ([rest] if rest and "/" in rest else [])
        if procs and "/" in procs[0]:
            procs = [procs[0].split("/", 1)[1]]
        out.append({
            "proto": proto.replace("6", ""),
            "addr": addr.strip("[]") or "*",
            "port": _int(port, port),
            "process": ",".join(sorted(set(procs))),
            "public": addr.strip("[]") in ("0.0.0.0", "*", "::", ""),
        })
    seen, uniq = set(), []
    for p in sorted(out, key=lambda x: (x["proto"], x["port"] if isinstance(x["port"], int) else 0)):
        key = (p["proto"], p["addr"], p["port"])
        if key not in seen:
            seen.add(key)
            uniq.append(p)
    return uniq


UPG_RE = re.compile(r"^Inst (\S+)(?: \[([^\]]+)\])? \((\S+) (.+?) \[([^\]]+)\]\)")
UPG_RE2 = re.compile(r"^Inst (\S+)(?: \[([^\]]+)\])? \((\S+) (.+?)\)")


def parse_upgradable(lines):
    out = []
    for ln in lines:
        m = UPG_RE.match(ln) or UPG_RE2.match(ln)
        if not m:
            continue
        suite = m.group(4)
        out.append({
            "name": m.group(1),
            "old": m.group(2) or "",
            "new": m.group(3),
            "suite": suite,
            "security": "security" in suite.lower(),
            "new_install": not m.group(2),
        })
    return out


def _parse_cert_date(s):
    s = re.sub(r"\s+", " ", s.strip())
    for fmt in ("%b %d %H:%M:%S %Y %Z", "%b %d %H:%M:%S %Y"):
        try:
            return datetime.strptime(s, fmt).replace(tzinfo=UTC)
        except ValueError:
            pass
    return None


def parse_certs(lines, now=None):
    now = now or datetime.now(UTC)
    out = []
    for ln in lines:
        p = ln.split("|")
        if len(p) < 5:
            continue
        path, subj, iss, start, end = p[:5]
        sig = p[5] if len(p) > 5 else ""
        bits = _int(p[6]) if len(p) > 6 else None
        san = p[7] if len(p) > 7 else ""
        end_dt = _parse_cert_date(end)
        days = int((end_dt - now).total_seconds() // 86400) if end_dt else None
        issues = []
        if days is not None and days < 0:
            issues.append("expired")
        elif days is not None and days < 21:
            issues.append("expires_soon")
        if subj and subj == iss:
            issues.append("self_signed")
        if re.search(r"sha1|md5", sig, re.I):
            issues.append("weak_signature")
        if bits and "rsa" in sig.lower() and bits < 2048:
            issues.append("weak_key")
        out.append({"path": path, "subject": subj, "issuer": iss, "not_before": start,
                    "not_after": end, "days_left": days, "sig": sig, "bits": bits,
                    "san": san, "issues": issues})
    return out


def parse_debian_kernel_version(kernel_version: str) -> str | None:
    # uname -v: "#1 SMP PREEMPT_DYNAMIC Debian 6.1.112-1 (2024-09-30)"
    m = re.search(r"Debian (\d[\w.+~:-]*)", kernel_version or "")
    return m.group(1) if m else None


def parse_collector_output(text: str) -> dict:
    s = split_sections(text)
    meta = _kv(s.get("meta", []))
    osr = _kv(s.get("os_release", []))
    system = _kv(s.get("system", []))

    disks = []
    inodes = {}
    for ln in s.get("df_inodes", []):
        p = ln.split()
        if len(p) >= 6:
            inodes[p[-1]] = _int(p[-2].rstrip("%"), None)
    for ln in s.get("df", []):
        p = ln.split()
        if len(p) < 7:
            continue
        size, used, avail = _int(p[2], 0), _int(p[3], 0), _int(p[4], 0)
        mount = " ".join(p[6:])
        if p[1].startswith("fuse.") and size > 10**12:  # network/fuse mounts with fake sizes
            pass
        pct = _int(p[5].rstrip("%"), 0)
        disks.append({"device": p[0], "fstype": p[1], "size_kb": size, "used_kb": used,
                      "avail_kb": avail, "pct": pct, "mount": mount, "inode_pct": inodes.get(mount)})

    block = []
    for ln in s.get("lsblk", []):
        d = dict(re.findall(r'(\w+)="([^"]*)"', ln))
        if d:
            block.append({"name": d.get("NAME", ""), "kname": d.get("KNAME", ""), "type": d.get("TYPE", ""),
                          "size": _int(d.get("SIZE"), 0), "fstype": d.get("FSTYPE", ""),
                          "mount": d.get("MOUNTPOINT", ""), "model": d.get("MODEL", "").strip(),
                          "parent": d.get("PKNAME", "")})

    users = []
    for ln in s.get("users", []):
        p = ln.split("|")
        if len(p) < 7:
            continue
        uid = _int(p[1], -1)
        groups = [g for g in p[6].split(",") if g]
        shell = p[5]
        pw = p[8] if len(p) > 8 else ""
        users.append({
            "name": p[0], "uid": uid, "gid": _int(p[2], -1), "gecos": p[3], "home": p[4],
            "shell": shell, "groups": groups,
            "login": not re.search(r"(nologin|false|sync)$", shell or "nologin"),
            "sudo": uid == 0 or bool({"sudo", "wheel", "admin"} & set(groups)),
            "ssh_keys": _int(p[7], -1) if len(p) > 7 else -1,
            "password": {"": "unknown", "!": "locked", "*": "locked"}.get(pw, "set"),
        })
    users.sort(key=lambda u: (u["uid"] != 0, not u["login"], u["uid"]))

    services = []
    for ln in s.get("services", []):
        if "|" not in ln:
            continue
        unit, desc = ln.split("|", 1)
        if not unit.endswith(".service"):
            continue
        cat, is_sys = classify_service(unit)
        services.append({"unit": unit, "name": unit[:-8], "desc": desc.strip(),
                         "category": cat, "system": is_sys})

    docker = []
    for ln in s.get("docker", []):
        p = ln.split("|")
        if len(p) >= 3:
            docker.append({"name": p[0], "image": p[1], "status": p[2], "ports": p[3] if len(p) > 3 else ""})

    packages = []
    for ln in s.get("packages", []):
        p = ln.split("|")
        if len(p) < 6:
            continue
        status = p[5].strip()
        if not (status.startswith("ii") or status.startswith("hi") or "ok installed" in status):
            continue
        src = (p[3] or p[0]).split(" ")[0]
        src_ver = p[4] or p[1]
        if not p[4] and "(" in p[3]:  # old dpkg: "Source: foo (1.2-3)"
            m = re.search(r"\(([^)]+)\)", p[3])
            src_ver = m.group(1) if m else p[1]
        packages.append({"name": p[0], "version": p[1], "arch": p[2], "source": src,
                         "source_version": src_ver, "hold": status.startswith("hi")})

    sshd = _kv([ln.replace(" ", "=", 1) for ln in s.get("sshd", []) if not ln.startswith("ssh_version")])
    sshd["version"] = _kv([ln for ln in s.get("sshd", []) if ln.startswith("ssh_version")]).get("ssh_version", "")

    kernel_pkg_ver = parse_debian_kernel_version(system.get("kernel_version", ""))

    return {
        "meta": meta,
        "os": {
            "id": osr.get("ID", ""),
            "id_like": osr.get("ID_LIKE", ""),
            "name": osr.get("NAME", ""),
            "pretty": osr.get("PRETTY_NAME", ""),
            "version_id": osr.get("VERSION_ID", ""),
            "codename": osr.get("VERSION_CODENAME", "") or _codename_from_version(osr.get("VERSION", "")),
            "debian_version": system.get("debian_version", ""),
        },
        "system": {
            "hostname": system.get("hostname", ""),
            "fqdn": system.get("fqdn", ""),
            "kernel_release": system.get("kernel_release", ""),
            "kernel_version": system.get("kernel_version", ""),
            "kernel_pkg_version": kernel_pkg_ver,
            "arch": system.get("arch", ""),
            "dpkg_arch": system.get("dpkg_arch", ""),
            "virt": system.get("virt", ""),
            "uptime_s": _int(system.get("uptime_s"), 0),
            "loadavg": system.get("loadavg", ""),
            "cpu_count": _int(system.get("cpu_count"), 0),
            "cpu_model": system.get("cpu_model", ""),
            "mem_total_kb": _int(system.get("mem_total_kb"), 0),
            "mem_avail_kb": _int(system.get("mem_avail_kb"), 0),
            "swap_total_kb": _int(system.get("swap_total_kb"), 0),
            "swap_free_kb": _int(system.get("swap_free_kb"), 0),
            "reboot_required": system.get("reboot_required") == "1",
            "reboot_required_pkgs": system.get("reboot_required_pkgs", "").split(),
            "ips": system.get("ips", "").split(),
            "unattended_upgrades": system.get("unattended_upgrades") == "1",
            "apt_last_update": _int(system.get("apt_last_update"), None),
        },
        "disks": disks,
        "block": block,
        "users": users,
        "last_logins": [ln for ln in s.get("last_logins", []) if ln.strip()],
        "services": services,
        "failed_units": [ln.strip() for ln in s.get("failed_units", []) if ln.strip()],
        "listening": parse_ss(s.get("listening", [])),
        "docker": docker,
        "packages": packages,
        "apt_sources": [ln.strip() for ln in s.get("apt_sources", []) if ln.strip()],
        "apt_refresh": (s.get("apt_refresh") or ["skipped"])[0].strip(),
        "upgradable": parse_upgradable(s.get("upgradable", [])),
        "certs": parse_certs(s.get("certs", [])),
        "sshd": sshd,
        "complete": "end" in s,
    }


def _codename_from_version(v: str) -> str:
    m = re.search(r"\(([a-z]+)\)", v or "")
    return m.group(1) if m else ""
