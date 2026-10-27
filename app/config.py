"""Runtime settings (all via environment variables)."""
from __future__ import annotations

import os
from dataclasses import dataclass, field


def _list(name, default):
    return [x.strip() for x in os.environ.get(name, default).split(",") if x.strip()]


@dataclass
class Settings:
    data_dir: str = os.environ.get("AMBER_DATA", "/data")
    ansible_dir: str = os.environ.get("AMBER_ANSIBLE_DIR",
                                      os.path.join(os.path.dirname(os.path.dirname(__file__)), "ansible"))
    auth_user: str = os.environ.get("AMBER_USER", "")
    auth_password: str = os.environ.get("AMBER_PASSWORD", "")
    feed_ttl: int = int(os.environ.get("AMBER_FEED_TTL", str(6 * 3600)))
    forks: int = int(os.environ.get("AMBER_FORKS", "25"))
    ssh_timeout: int = int(os.environ.get("AMBER_SSH_TIMEOUT", "15"))
    job_timeout: int = int(os.environ.get("AMBER_JOB_TIMEOUT", "1800"))
    max_scan_hosts: int = int(os.environ.get("AMBER_MAX_SCAN_HOSTS", "4096"))
    nvd_max_per_run: int = int(os.environ.get("AMBER_NVD_MAX", "300"))
    # Packages always highlighted in reports ("hot list"): exposed, frequently exploited components.
    watchlist: list = field(default_factory=lambda: _list(
        "AMBER_WATCHLIST",
        "openssl,openssh,php*,sudo,glibc,linux,nginx,apache2,ca-certificates,gnutls28,nss,"
        "libxml2,curl,systemd,polkit*,xz-utils,exim4,postfix,dovecot,bind9,samba,"
        "postgresql*,mariadb*,mysql*,redis,python3*,nodejs,git,libssh*,openjdk*,tomcat*,haproxy,squid"))


settings = Settings()

# Debian releases: codename -> (major, end of regular security support, end of LTS).
# Dates as published by Debian; trixie dates are approximate (≈ 3 years + LTS).
DEBIAN_RELEASES = {
    "jessie":   (8,  "2018-06-17", "2020-06-30"),
    "stretch":  (9,  "2020-07-18", "2022-06-30"),
    "buster":   (10, "2022-09-10", "2024-06-30"),
    "bullseye": (11, "2024-08-14", "2026-08-31"),
    "bookworm": (12, "2026-06-10", "2028-06-30"),
    "trixie":   (13, "2028-08-09", "2030-06-30"),
    "forky":    (14, None, None),
    "sid":      (None, None, None),
}
MAJOR_TO_CODENAME = {v[0]: k for k, v in DEBIAN_RELEASES.items() if v[0]}
