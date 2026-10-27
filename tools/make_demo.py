#!/usr/bin/env python3
"""Generate a DEMO report with synthetic hosts and a tiny synthetic vulnerability feed.

All CVE IDs are fake (CVE-2099-*) and clearly marked [DEMO]. Purpose: preview the UI and
test the pipeline without a real fleet or internet access.

    docker compose exec amberventory python -m tools.make_demo
"""
import gzip
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.config import settings  # noqa: E402

DEMO_FEEDS = os.path.join(settings.data_dir, "demo-feeds")

TRACKER = {
    "openssl": {
        "CVE-2099-1001": {"description": "[DEMO] Certificate verification bypass allows forged certificate chains",
                          "scope": "remote", "releases": {
                              "bookworm": {"status": "resolved", "fixed_version": "3.0.15-1~deb12u1", "urgency": "high"},
                              "trixie": {"status": "resolved", "fixed_version": "3.5.1-1", "urgency": "high"},
                              "bullseye": {"status": "open", "fixed_version": "", "urgency": "high"}}},
        "CVE-2099-1002": {"description": "[DEMO] Timing side channel in RSA decryption", "scope": "remote",
                          "releases": {"bookworm": {"status": "open", "urgency": "low", "nodsa": "Minor issue",
                                                    "nodsa_reason": "postponed"}}},
    },
    "php8.2": {
        "CVE-2099-2001": {"description": "[DEMO] Remote code execution via crafted multipart request in PHP-FPM",
                          "scope": "remote", "releases": {
                              "bookworm": {"status": "resolved", "fixed_version": "8.2.29-1~deb12u1",
                                           "urgency": "not yet assigned"}}},
    },
    "php8.4": {
        "CVE-2099-2001": {"description": "[DEMO] Remote code execution via crafted multipart request in PHP-FPM",
                          "scope": "remote", "releases": {
                              "trixie": {"status": "resolved", "fixed_version": "8.4.12-1", "urgency": "not yet assigned"}}},
    },
    "sudo": {
        "CVE-2099-3001": {"description": "[DEMO] Local privilege escalation via chroot option", "scope": "local",
                          "releases": {"bookworm": {"status": "resolved", "fixed_version": "1.9.13p3-1+deb12u2",
                                                    "urgency": "medium"},
                                       "bullseye": {"status": "resolved", "fixed_version": "1.9.5p2-3+deb11u2",
                                                    "urgency": "medium"}}},
    },
    "linux": {
        "CVE-2099-4001": {"description": "[DEMO] Use-after-free in netfilter allows local root", "scope": "local",
                          "releases": {"bookworm": {"status": "resolved", "fixed_version": "6.1.140-1", "urgency": "high"},
                                       "trixie": {"status": "resolved", "fixed_version": "6.12.48-1", "urgency": "high"}}},
        "CVE-2099-4002": {"description": "[DEMO] Minor info leak in a rarely used driver", "scope": "local",
                          "releases": {"bookworm": {"status": "open", "urgency": "unimportant"}}},
    },
    "glibc": {
        "CVE-2099-5001": {"description": "[DEMO] Buffer overflow in iconv", "scope": "remote",
                          "releases": {"bookworm": {"status": "resolved", "fixed_version": "2.36-9+deb12u10",
                                                    "urgency": "medium"},
                                       "bullseye": {"status": "resolved", "fixed_version": "2.31-13+deb11u12",
                                                    "urgency": "medium"}}},
    },
    "postgresql-15": {
        "CVE-2099-6001": {"description": "[DEMO] SQL injection in psql meta-commands", "scope": "remote",
                          "releases": {"bookworm": {"status": "resolved", "fixed_version": "15.14-0+deb12u1",
                                                    "urgency": "not yet assigned"}}},
    },
    "nginx": {
        "CVE-2099-7001": {"description": "[DEMO] HTTP/2 resource exhaustion", "scope": "remote",
                          "releases": {"trixie": {"status": "open", "urgency": "medium"}}},
    },
    "curl": {"CVE-2099-8001": {"description": "[DEMO] Cookie leak on redirect", "scope": "remote",
                               "releases": {"bookworm": {"status": "resolved", "fixed_version": "0",
                                                         "urgency": "low"}}}},
    "bash": {}, "coreutils": {}, "openssh": {}, "systemd": {}, "redis": {},
}
KEV = {"catalogVersion": "demo", "vulnerabilities": [
    {"cveID": "CVE-2099-2001", "vendorProject": "PHP", "product": "PHP", "vulnerabilityName": "[DEMO] PHP-FPM RCE",
     "dateAdded": "2026-10-01", "dueDate": "2026-10-22", "knownRansomwareCampaignUse": "Known",
     "requiredAction": "Apply updates"}]}
EPSS = "#model_version:demo,score_date:2026-10-26\ncve,epss,percentile\nCVE-2099-1001,0.62,0.98\n" \
       "CVE-2099-2001,0.94,0.999\nCVE-2099-3001,0.02,0.6\nCVE-2099-4001,0.08,0.9\nCVE-2099-6001,0.003,0.2\n"


def host_output(hostname, os_release, debian_version, kernel_rel, kernel_v, packages, upgradable, services,
                listening, disks, users, certs="", sshd="permitrootlogin prohibit-password\npasswordauthentication no",
                sources="deb http://deb.debian.org/debian bookworm main\ndeb http://security.debian.org/debian-security bookworm-security main",
                reboot="0", docker="", failed=""):
    return "\n".join([
        "@@ meta", "collector=1.0", "whoami=root", "uid=0", "privileged=1",
        "@@ os_release", os_release,
        "@@ system", f"hostname={hostname}", f"fqdn={hostname}.corp.local", f"debian_version={debian_version}",
        f"kernel_release={kernel_rel}", f"kernel_version={kernel_v}", "arch=x86_64", "dpkg_arch=amd64", "virt=kvm",
        "uptime_s=1987654", "loadavg=0.42 0.38 0.30", "cpu_count=8", "cpu_model=Intel(R) Xeon(R) Gold 6226R",
        "mem_total_kb=32780000", "mem_avail_kb=12100000", "swap_total_kb=2097148", "swap_free_kb=2000000",
        f"reboot_required={reboot}", "reboot_required_pkgs=linux-image-6.1.0-41-amd64" if reboot == "1" else "reboot_required_pkgs=",
        "init=systemd", f"ips=10.20.0.{abs(hash(hostname)) % 200 + 10}", "unattended_upgrades=0",
        f"apt_last_update={int(time.time()) - 86400 * 12}",
        "@@ df", disks, "@@ df_inodes",
        "@@ lsblk", 'NAME="sda" KNAME="sda" TYPE="disk" SIZE="214748364800" FSTYPE="" MOUNTPOINT="" MODEL="QEMU HARDDISK" PKNAME=""',
        'NAME="sda1" KNAME="sda1" TYPE="part" SIZE="214747316224" FSTYPE="ext4" MOUNTPOINT="/" MODEL="" PKNAME="sda"',
        "@@ users", users, "@@ last_logins",
        "@@ services", services, "@@ failed_units", failed, "@@ listening", listening, "@@ docker", docker,
        "@@ packages", packages, "@@ apt_sources", sources, "@@ apt_refresh", "skipped",
        "@@ upgradable", upgradable, "@@ certs", certs, "@@ sshd", sshd, "ssh_version=OpenSSH_9.2p1 Debian-2+deb12u7",
        "@@ end", "ok"])


BOOKWORM = 'PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"\nNAME="Debian GNU/Linux"\nVERSION_ID="12"\nVERSION="12 (bookworm)"\nVERSION_CODENAME=bookworm\nID=debian'
TRIXIE = 'PRETTY_NAME="Debian GNU/Linux 13 (trixie)"\nNAME="Debian GNU/Linux"\nVERSION_ID="13"\nVERSION="13 (trixie)"\nVERSION_CODENAME=trixie\nID=debian'
BULLSEYE = 'PRETTY_NAME="Debian GNU/Linux 11 (bullseye)"\nNAME="Debian GNU/Linux"\nVERSION_ID="11"\nVERSION="11 (bullseye)"\nVERSION_CODENAME=bullseye\nID=debian'

USERS = "root|0|0|root|/root|/bin/bash|root|2|*\ndeploy|1000|1000|Deploy,,,|/home/deploy|/bin/bash|deploy,sudo,docker|3|!\n" \
        "postgres|105|111|PostgreSQL administrator|/var/lib/postgresql|/bin/bash|postgres,ssl-cert|0|!"
SVC_SYS = "\n".join(f"{u}|loaded active running {d}" for u, d in [
    ("cron.service", "Regular background program processing daemon"), ("dbus.service", "D-Bus System Message Bus"),
    ("ssh.service", "OpenBSD Secure Shell server"), ("systemd-journald.service", "Journal Service"),
    ("rsyslog.service", "System Logging Service"), ("getty@tty1.service", "Getty on tty1")])


def pk(rows):
    return "\n".join(f"{n}|{v}|amd64|{s}|{sv or v}|ii " for n, v, s, sv in rows)


def main():
    from app.jobs import JOBS_DIR, build_report
    from app.vulndb import get_vulndb

    os.makedirs(DEMO_FEEDS, exist_ok=True)
    tr = os.path.join(DEMO_FEEDS, "tracker.json")
    json.dump(TRACKER, open(tr, "w"))
    json.dump(KEV, open(os.path.join(DEMO_FEEDS, "kev.json"), "w"))
    with gzip.open(os.path.join(DEMO_FEEDS, "epss.csv.gz"), "wt") as f:
        f.write(EPSS)
    vdb = get_vulndb()
    if not vdb.meta().get("ready") or "--force-feeds" in sys.argv:
        print("Importing DEMO feeds into the vulnerability DB (replace with real ones via 'Обновить базы')")
        vdb.import_tracker(tr)
        vdb.import_kev(os.path.join(DEMO_FEEDS, "kev.json"))
        vdb.import_epss(os.path.join(DEMO_FEEDS, "epss.csv.gz"))

    db1 = host_output(
        "pg-main-01", BOOKWORM, "12.8", "6.1.0-37-amd64", "#1 SMP PREEMPT_DYNAMIC Debian 6.1.137-1 (2025-05-20)",
        pk([("openssl", "3.0.13-1~deb12u1", "openssl", ""), ("libssl3", "3.0.13-1~deb12u1", "openssl", ""),
            ("sudo", "1.9.13p3-1+deb12u1", "sudo", ""), ("libc6", "2.36-9+deb12u10", "glibc", ""),
            ("linux-image-6.1.0-37-amd64", "6.1.137-1", "linux", ""), ("linux-image-6.1.0-41-amd64", "6.1.153-1", "linux", ""),
            ("postgresql-15", "15.12-0+deb12u2", "postgresql-15", ""), ("curl", "7.88.1-10+deb12u12", "curl", ""),
            ("bash", "5.2.15-2+b8", "bash", "5.2.15-2"), ("redis-server", "5:7.0.15-1~deb12u4", "redis", "5:7.0.15-1~deb12u4"),
            ("pgbackrest", "2.55.0-1.pgdg120+1", "pgbackrest", "")]),
        "Inst openssl [3.0.13-1~deb12u1] (3.0.17-1~deb12u2 Debian-Security:12/stable-security [amd64])\n"
        "Inst libssl3 [3.0.13-1~deb12u1] (3.0.17-1~deb12u2 Debian-Security:12/stable-security [amd64])\n"
        "Inst postgresql-15 [15.12-0+deb12u2] (15.14-0+deb12u1 Debian:12.12/oldstable [amd64])",
        SVC_SYS + "\npostgresql@15-main.service|loaded active running PostgreSQL Cluster 15-main\n"
                  "redis-server.service|loaded active running Advanced key-value store\n"
                  "prometheus-node-exporter.service|loaded active running Prometheus exporter for machine metrics\n"
                  "pgbouncer.service|loaded active running connection pooler for PostgreSQL",
        'tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=611,fd=3))\n'
        'tcp LISTEN 0 244 0.0.0.0:5432 0.0.0.0:* users:(("postgres",pid=800,fd=6))\n'
        'tcp LISTEN 0 511 127.0.0.1:6379 0.0.0.0:* users:(("redis-server",pid=700,fd=6))\n'
        'tcp LISTEN 0 4096 *:9100 *:* users:(("prometheus-node",pid=650,fd=3))',
        "/dev/sda1 ext4 205375464 189500000 5409292 98% /\n/dev/sdb1 xfs 1073217536 412000000 661217536 39% /var/lib/postgresql",
        USERS, reboot="1")
    web1 = host_output(
        "web-front-02", TRIXIE, "13.1", "6.12.43+deb13-amd64", "#1 SMP PREEMPT_DYNAMIC Debian 6.12.43-1 (2025-08-27)",
        pk([("openssl", "3.5.1-1", "openssl", ""), ("libssl3t64", "3.5.1-1", "openssl", ""),
            ("nginx", "1.26.3-3", "nginx", ""), ("php8.4-fpm", "8.4.11-1", "php8.4", ""),
            ("php8.4-cli", "8.4.11-1", "php8.4", ""),
            ("php8.3-fpm", "8.3.25-1+0~20250904.71+debian13~1.gbp3e2b19", "php8.3", ""),
            ("docker-ce", "5:28.4.0-1~debian.13~trixie", "docker-ce", ""),
            ("linux-image-6.12.43+deb13-amd64", "6.12.43-1", "linux", "")]),
        "Inst php8.4-fpm [8.4.11-1] (8.4.12-1 Debian-Security:13/stable-security [amd64])\n"
        "Inst php8.4-cli [8.4.11-1] (8.4.12-1 Debian-Security:13/stable-security [amd64])",
        SVC_SYS + "\nnginx.service|loaded active running A high performance web server and a reverse proxy server\n"
                  "php8.4-fpm.service|loaded active running The PHP 8.4 FastCGI Process Manager\n"
                  "docker.service|loaded active running Docker Application Container Engine\n"
                  "containerd.service|loaded active running containerd container runtime\n"
                  "fail2ban.service|loaded active running Fail2Ban Service",
        'tcp LISTEN 0 511 0.0.0.0:80 0.0.0.0:* users:(("nginx",pid=1200,fd=6))\n'
        'tcp LISTEN 0 511 0.0.0.0:443 0.0.0.0:* users:(("nginx",pid=1200,fd=7))\n'
        'tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=611,fd=3))\n'
        'tcp LISTEN 0 4096 0.0.0.0:2375 0.0.0.0:* users:(("dockerd",pid=900,fd=8))',
        "/dev/sda1 ext4 102687672 84000000 13428712 87% /\n/dev/sda15 vfat 126678 6182 120496 5% /boot/efi",
        USERS.replace("postgres|105", "www-data|33").replace("PostgreSQL administrator|/var/lib/postgresql|/bin/bash|postgres,ssl-cert|0|!",
                                                           "www-data|/var/www|/usr/sbin/nologin|www-data|0|*")
        + "\nbackup|0|0|backup user|/root|/bin/bash|root|1|set",
        certs="/etc/letsencrypt/live/shop.example.com/cert.pem|CN = shop.example.com|C = US, O = Let's Encrypt, CN = R11|"
              "Aug  1 00:00:00 2026 GMT|Nov  3 23:59:59 2026 GMT|sha256WithRSAEncryption|2048|DNS:shop.example.com\n"
              "/etc/nginx/ssl/legacy.crt|CN = legacy.corp.local|CN = legacy.corp.local|Jan  1 00:00:00 2020 GMT|"
              "Jan  1 00:00:00 2025 GMT|sha1WithRSAEncryption|1024|DNS:legacy.corp.local",
        sshd="permitrootlogin yes\npasswordauthentication yes",
        sources="deb http://deb.debian.org/debian trixie main\ndeb http://security.debian.org/debian-security trixie-security main\n"
                "deb https://packages.sury.org/php/ trixie main\ndeb https://download.docker.com/linux/debian trixie stable",
        docker="shop-api|registry.corp.local/shop/api:1.42|Up 3 days|0.0.0.0:8080->8080/tcp\nshop-worker|registry.corp.local/shop/worker:1.42|Up 3 days|",
        failed="certbot.service")
    old1 = host_output(
        "legacy-crm", BULLSEYE, "11.11", "5.10.0-30-amd64", "#1 SMP Debian 5.10.218-1 (2024-06-01)",
        pk([("openssl", "1.1.1w-0+deb11u1", "openssl", ""), ("sudo", "1.9.5p2-3+deb11u1", "sudo", ""),
            ("libc6", "2.31-13+deb11u10", "glibc", ""), ("apache2", "2.4.62-1~deb11u1", "apache2", ""),
            ("mariadb-server", "1:10.5.26-0+deb11u2", "mariadb-10.5", "")]),
        "",
        SVC_SYS + "\napache2.service|loaded active running The Apache HTTP Server\nmariadb.service|loaded active running MariaDB 10.5.26 database server",
        'tcp LISTEN 0 80 0.0.0.0:3306 0.0.0.0:* users:(("mariadbd",pid=900,fd=21))\n'
        'tcp LISTEN 0 511 *:80 *:* users:(("apache2",pid=1000,fd=4))',
        "/dev/vda1 ext4 51290592 22000000 26654436 46% /",
        USERS.replace("postgres|105|111|PostgreSQL administrator|/var/lib/postgresql", "mysql|106|112|MySQL Server|/nonexistent")
             .replace("/bin/bash|postgres,ssl-cert", "/bin/false|mysql"),
        sources="deb http://deb.debian.org/debian bullseye main")

    job_id = time.strftime("%Y%m%d-%H%M%S-") + "demo00"
    job_dir = os.path.join(JOBS_DIR, job_id)
    os.makedirs(os.path.join(job_dir, "results"), exist_ok=True)
    hosts = [("pg-main-01", "10.20.0.11", db1), ("web-front-02", "10.20.0.21", web1), ("legacy-crm", "10.20.0.40", old1),
             ("mq-03", "10.20.0.31", None)]
    params = {"source": "scan", "source_label": "DEMO 10.20.0.0/24", "user": "root", "become": False,
              "apt_refresh": False, "hosts": [{"name": n, "ip": ip, "port": 22, "groups": []} for n, ip, _ in hosts]}
    json.dump(params, open(os.path.join(job_dir, "params.json"), "w"))
    for n, _ip, out in hosts:
        r = {"host": n, "status": "ok" if out else "unreachable", "stdout": out or "",
             "msg": "" if out else "Failed to connect to the host via ssh: ssh: connect to host 10.20.0.31 port 22: Connection timed out"}
        json.dump(r, open(os.path.join(job_dir, "results", n + ".json"), "w"))
    rep = build_report(job_id, job_dir, params)
    print("DEMO report:", job_id, json.dumps(rep["fleet"]["severity"]))


if __name__ == "__main__":
    main()
