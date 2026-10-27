"""Parsing of the collector output and of nmap XML."""
from app.parser import classify_service, parse_collector_output, parse_ss, parse_upgradable
from app.scanner import UserError, _debian_from_openssh, parse_nmap_xml, validate_targets

SAMPLE = """\
@@ meta
collector=1.0
uid=0
@@ os_release
PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"
ID=debian
VERSION_ID="12"
VERSION_CODENAME=bookworm
@@ system
hostname=db1
debian_version=12.8
kernel_release=6.1.0-37-amd64
kernel_version=#1 SMP PREEMPT_DYNAMIC Debian 6.1.140-1 (2025-05-22)
mem_total_kb=1000
mem_avail_kb=400
reboot_required=1
reboot_required_pkgs=linux-image-6.1.0-37-amd64
ips=10.0.0.5 fd00::5
@@ df
/dev/sda1 ext4 1000 900 100 90% /
@@ df_inodes
/dev/sda1 100 10 90 10% /
@@ users
root|0|0|root|/root|/bin/bash|root|2|*
deploy|1000|1000|Deploy|/home/deploy|/bin/bash|deploy,sudo|1|!
www-data|33|33|www-data|/var/www|/usr/sbin/nologin|www-data|0|*
@@ services
ssh.service|loaded active running OpenBSD Secure Shell server
postgresql@15-main.service|loaded active running PostgreSQL Cluster 15-main
@@ listening
tcp   LISTEN 0 4096 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=1,fd=3))
tcp   LISTEN 0 244 127.0.0.1:5432 0.0.0.0:* users:(("postgres",pid=2,fd=6))
@@ packages
openssl|3.0.13-1~deb12u1|amd64|openssl|3.0.13-1~deb12u1|ii
libssl3|3.0.13-1~deb12u1|amd64|openssl|3.0.13-1~deb12u1|ii
bash|5.2.15-2+b8|amd64|bash|5.2.15-2|ii
oldpkg|1.0|amd64|oldpkg|1.0|rc
@@ upgradable
Inst openssl [3.0.13-1~deb12u1] (3.0.17-1~deb12u2 Debian-Security:12/stable-security [amd64])
@@ end
ok
"""


def test_collector_output_is_parsed():
    host = parse_collector_output(SAMPLE)
    assert host["complete"] is True
    assert host["os"]["codename"] == "bookworm"
    assert host["system"]["kernel_pkg_version"] == "6.1.140-1"
    assert host["system"]["reboot_required"] is True
    assert host["system"]["ips"] == ["10.0.0.5", "fd00::5"]
    assert host["disks"][0]["pct"] == 90 and host["disks"][0]["inode_pct"] == 10

    names = [u["name"] for u in host["users"]]
    assert names[0] == "root"
    deploy = next(u for u in host["users"] if u["name"] == "deploy")
    assert deploy["sudo"] and deploy["login"] and deploy["ssh_keys"] == 1 and deploy["password"] == "locked"
    assert not next(u for u in host["users"] if u["name"] == "www-data")["login"]

    # not-installed packages (status "rc") are skipped, source package versions are kept
    assert {p["name"] for p in host["packages"]} == {"openssl", "libssl3", "bash"}
    bash = next(p for p in host["packages"] if p["name"] == "bash")
    assert bash["version"] == "5.2.15-2+b8" and bash["source_version"] == "5.2.15-2"

    assert host["upgradable"][0]["security"] is True
    ports = {(p["port"], p["public"]) for p in host["listening"]}
    assert ports == {(22, True), (5432, False)}


def test_truncated_output_is_flagged():
    assert parse_collector_output(SAMPLE.split("@@ end")[0])["complete"] is False


def test_service_classification():
    assert classify_service("ssh.service") == ("system", True)
    assert classify_service("getty@tty1.service") == ("system", True)
    assert classify_service("postgresql@15-main.service") == ("db", False)
    assert classify_service("php8.2-fpm.service") == ("web", False)
    assert classify_service("rabbitmq-server.service") == ("queue", False)
    assert classify_service("docker.service") == ("containers", False)
    assert classify_service("myapp.service") == ("other", False)


def test_ss_handles_ipv6_and_multiple_processes():
    rows = parse_ss(['tcp LISTEN 0 511 [::]:80 [::]:* users:(("nginx",pid=1,fd=7),("nginx",pid=2,fd=7))'])
    assert rows == [{"proto": "tcp", "addr": "::", "port": 80, "process": "nginx", "public": True}]


def test_upgradable_without_old_version_is_new_install():
    rows = parse_upgradable(["Inst linux-image-6.1.0-28-amd64 (6.1.119-1 Debian:12.8/stable [amd64])"])
    assert rows[0]["new_install"] is True and rows[0]["security"] is False


NMAP_XML = """<nmaprun><host><address addr="10.0.0.5" addrtype="ipv4"/>
<address addr="AA:BB:CC:DD:EE:FF" addrtype="mac" vendor="Dell"/><hostnames><hostname name="db1.lan"/></hostnames>
<ports><port protocol="tcp" portid="22"><state state="open"/>
<service name="ssh" product="OpenSSH" version="9.2p1 Debian 2+deb12u3" extrainfo="protocol 2.0"/></port>
<port protocol="tcp" portid="2222"><state state="closed"/></port></ports></host></nmaprun>"""


def test_nmap_xml():
    hosts = parse_nmap_xml(NMAP_XML)
    assert len(hosts) == 1
    h = hosts[0]
    assert (h["ip"], h["port"], h["hostname"], h["vendor"]) == ("10.0.0.5", 22, "db1.lan", "Dell")
    assert h["os_guess"] == "Debian" and h["release_hint"] == "bookworm"


def test_openssh_banner_release_hints():
    assert _debian_from_openssh("OpenSSH 9.2p1 Debian 2+deb12u3") == "bookworm"
    assert _debian_from_openssh("OpenSSH 7.4p1 Debian 10+deb9u7") == "stretch"
    assert _debian_from_openssh("OpenSSH 8.9p1 Ubuntu 3ubuntu0.6") == ""


def test_target_validation():
    assert validate_targets("10.0.0.0/24, 10.0.1.10-40 host.example.com") == [
        "10.0.0.0/24", "10.0.1.10-40", "host.example.com"]
    for bad in ("", "10.0.0.1 -oN /tmp/x", "10.0.0.1; rm -rf /", "$(id)", "10.0.0.0/8"):
        try:
            validate_targets(bad)
        except UserError:
            continue
        raise AssertionError(f"{bad!r} must be rejected")
