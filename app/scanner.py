"""Subnet discovery (nmap), inventory parsing (ansible-inventory) and SSH key handling."""
from __future__ import annotations

import ipaddress
import json
import os
import re
import shutil
import subprocess
import tempfile
import xml.etree.ElementTree as ET

from .config import settings


class UserError(Exception):
    pass


def validate_targets(spec: str) -> list[str]:
    targets = [t for t in re.split(r"[\s,;]+", spec.strip()) if t]
    if not targets:
        raise UserError("Укажите подсеть, например 10.0.0.0/24")
    total = 0
    for t in targets:
        if not re.fullmatch(r"[0-9A-Za-z][0-9A-Za-z.:/\-]*", t):
            raise UserError(f"Недопустимая цель: {t}")
        try:
            net = ipaddress.ip_network(t, strict=False)
            total += net.num_addresses
        except ValueError:
            total += 1  # hostname or nmap range (10.0.0.1-20)
    if total > settings.max_scan_hosts:
        raise UserError(f"Слишком большой диапазон ({total} адресов), лимит {settings.max_scan_hosts}")
    return targets


def nmap_scan(spec: str, port: int = 22) -> list[dict]:
    targets = validate_targets(spec)
    if not shutil.which("nmap"):
        raise UserError("nmap не найден в контейнере")
    cmd = ["nmap", "-n", "-Pn", "-T4", "--open", "-p", str(int(port)), "-sV", "--version-light",
           "--max-retries", "1", "--host-timeout", "30s", "-oX", "-", "--", *targets]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=900)
    except subprocess.TimeoutExpired:
        raise UserError("nmap: превышено время сканирования") from None
    if out.returncode != 0 and not out.stdout:
        raise UserError("nmap: " + (out.stderr.strip()[:400] or "ошибка"))
    return parse_nmap_xml(out.stdout)


def parse_nmap_xml(xml: str) -> list[dict]:
    hosts = []
    root = ET.fromstring(xml)
    for h in root.findall("host"):
        addr = h.find("address[@addrtype='ipv4']")
        if addr is None:
            addr = h.find("address[@addrtype='ipv6']")
        if addr is None:
            continue
        mac = h.find("address[@addrtype='mac']")
        names = [n.get("name") for n in h.findall("hostnames/hostname") if n.get("name")]
        for p in h.findall("ports/port"):
            st = p.find("state")
            if st is None or st.get("state") != "open":
                continue
            svc = p.find("service")
            product = (svc.get("product", "") if svc is not None else "")
            version = (svc.get("version", "") if svc is not None else "")
            extra = (svc.get("extrainfo", "") if svc is not None else "")
            banner = " ".join(x for x in (product, version, extra) if x)
            os_guess = "Debian" if re.search(r"debian", banner, re.I) else \
                "Ubuntu" if re.search(r"ubuntu", banner, re.I) else ""
            deb_hint = _debian_from_openssh(banner)
            hosts.append({
                "ip": addr.get("addr"), "port": int(p.get("portid")), "hostname": names[0] if names else "",
                "mac": mac.get("addr") if mac is not None else "",
                "vendor": mac.get("vendor", "") if mac is not None else "",
                "banner": banner, "os_guess": os_guess, "release_hint": deb_hint,
            })
    return hosts


# OpenSSH package suffix → Debian release hint (banner like "OpenSSH 9.2p1 Debian 2+deb12u3")
def _debian_from_openssh(banner: str) -> str:
    m = re.search(r"deb(\d+)u\d+", banner)
    if m:
        return {"8": "jessie", "9": "stretch", "10": "buster", "11": "bullseye", "12": "bookworm",
                "13": "trixie"}.get(m.group(1), "")
    m = re.search(r"OpenSSH[_ ](\d+\.\d+)", banner)
    if m and "Debian" in banner:
        return {"6.7": "jessie", "7.4": "stretch", "7.9": "buster", "8.4": "bullseye", "9.2": "bookworm",
                "10.0": "trixie"}.get(m.group(1), "")
    return ""


def parse_inventory(path: str) -> list[dict]:
    """Use ansible-inventory itself so INI, YAML, and group_vars semantics are respected."""
    try:
        out = subprocess.run(["ansible-inventory", "-i", path, "--list"], capture_output=True, text=True,
                             timeout=60, env={**os.environ, "ANSIBLE_INVENTORY_UNPARSED_WARNING": "False"})
    except subprocess.TimeoutExpired:
        raise UserError("ansible-inventory: таймаут") from None
    if out.returncode != 0:
        raise UserError("Inventory не разобран: " + out.stderr.strip()[-500:])
    data = json.loads(out.stdout or "{}")
    hostvars = data.get("_meta", {}).get("hostvars", {})
    groups_of: dict[str, list[str]] = {}

    def walk(group, seen=()):
        g = data.get(group, {})
        for host in g.get("hosts", []):
            if group not in ("all", "ungrouped"):
                groups_of.setdefault(host, []).append(group)
            else:
                groups_of.setdefault(host, [])
        for child in g.get("children", []):
            if child not in seen:
                walk(child, seen + (child,))
    walk("all")
    hosts = []
    for name in sorted(groups_of):
        hv = hostvars.get(name, {})
        hosts.append({
            "name": name, "ip": hv.get("ansible_host", name),
            "port": int(hv.get("ansible_port", hv.get("ansible_ssh_port", 22)) or 22),
            "user": hv.get("ansible_user", hv.get("ansible_ssh_user", "")),
            "groups": sorted(set(groups_of[name])),
        })
    if not hosts:
        raise UserError("В inventory не найдено ни одного хоста")
    return hosts


def inspect_key(path: str, passphrase: str = "") -> dict:
    """Validate the private key; returns fingerprint and type. Raises UserError on bad key/passphrase."""
    out = subprocess.run(["ssh-keygen", "-y", "-P", passphrase, "-f", path], capture_output=True, text=True)
    if out.returncode != 0:
        err = out.stderr.strip()
        if "passphrase" in err.lower() or "incorrect" in err.lower():
            raise UserError("Ключ защищён паролем: укажите passphrase" if not passphrase else "Неверный passphrase")
        raise UserError("Это не приватный SSH-ключ: " + err[:200])
    pub = out.stdout.strip()
    with tempfile.NamedTemporaryFile("w", suffix=".pub", delete=False) as f:
        f.write(pub + "\n")
        tmp = f.name
    try:
        fp = subprocess.run(["ssh-keygen", "-l", "-f", tmp], capture_output=True, text=True).stdout.strip()
    finally:
        os.unlink(tmp)
    parts = fp.split()
    return {"fingerprint": parts[1] if len(parts) > 1 else fp, "bits": parts[0] if parts else "",
            "type": parts[-1].strip("()") if parts else "", "comment": " ".join(pub.split()[2:]),
            "encrypted": bool(passphrase)}


def decrypt_key_copy(src: str, passphrase: str, dest: str):
    """Write a passphrase-less copy for the duration of a job (deleted afterwards)."""
    shutil.copyfile(src, dest)
    os.chmod(dest, 0o600)
    if passphrase:
        r = subprocess.run(["ssh-keygen", "-p", "-P", passphrase, "-N", "", "-f", dest], capture_output=True, text=True)
        if r.returncode != 0:
            os.unlink(dest)
            raise UserError("Не удалось расшифровать ключ: " + r.stderr.strip()[:200])
