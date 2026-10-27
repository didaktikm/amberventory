#!/bin/bash
# AmberVentory host collector.
# Runs on the target via Ansible `script` module: needs only bash + coreutils,
# no Python on the target (works on old Debian 8/9 as well as 12/13).
# Output: plain-text sections delimited by "@@ <name>" lines, parsed server-side.
# Usage: collector.sh [APT_REFRESH=0|1]

APT_REFRESH="${1:-0}"
export LC_ALL=C LANG=C
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH"

sec() { echo "@@ $1"; }
have() { command -v "$1" >/dev/null 2>&1; }
SUDO=""
if [ "$(id -u)" != "0" ] && have sudo && sudo -n true 2>/dev/null; then SUDO="sudo -n"; fi

sec meta
echo "collector=1.0"
echo "whoami=$(id -un)"
echo "uid=$(id -u)"
echo "privileged=$([ "$(id -u)" = 0 ] || [ -n "$SUDO" ] && echo 1 || echo 0)"
echo "date=$(date -u +%Y-%m-%dT%H:%M:%SZ)"

sec os_release
cat /etc/os-release 2>/dev/null

sec system
echo "hostname=$(hostname 2>/dev/null)"
echo "fqdn=$(hostname -f 2>/dev/null)"
echo "debian_version=$(cat /etc/debian_version 2>/dev/null)"
echo "kernel_release=$(uname -r)"
echo "kernel_version=$(uname -v)"
echo "arch=$(uname -m)"
echo "dpkg_arch=$(dpkg --print-architecture 2>/dev/null)"
echo "virt=$(systemd-detect-virt 2>/dev/null || echo unknown)"
echo "uptime_s=$(cut -d. -f1 /proc/uptime 2>/dev/null)"
echo "loadavg=$(cut -d' ' -f1-3 /proc/loadavg 2>/dev/null)"
echo "cpu_count=$(grep -c ^processor /proc/cpuinfo 2>/dev/null)"
echo "cpu_model=$(grep -m1 'model name' /proc/cpuinfo 2>/dev/null | cut -d: -f2- | sed 's/^ *//')"
echo "mem_total_kb=$(awk '/^MemTotal:/{print $2}' /proc/meminfo 2>/dev/null)"
echo "mem_avail_kb=$(awk '/^MemAvailable:/{print $2}' /proc/meminfo 2>/dev/null)"
echo "swap_total_kb=$(awk '/^SwapTotal:/{print $2}' /proc/meminfo 2>/dev/null)"
echo "swap_free_kb=$(awk '/^SwapFree:/{print $2}' /proc/meminfo 2>/dev/null)"
echo "reboot_required=$([ -f /var/run/reboot-required ] && echo 1 || echo 0)"
echo "reboot_required_pkgs=$(cat /var/run/reboot-required.pkgs 2>/dev/null | tr '\n' ' ')"
echo "init=$(ps -p 1 -o comm= 2>/dev/null)"
echo "ips=$(hostname -I 2>/dev/null)"
echo "unattended_upgrades=$(dpkg-query -W -f='${Status}' unattended-upgrades 2>/dev/null | grep -q 'ok installed' && echo 1 || echo 0)"
if [ -f /var/lib/apt/periodic/update-success-stamp ]; then
  echo "apt_last_update=$(stat -c %Y /var/lib/apt/periodic/update-success-stamp)"
else
  echo "apt_last_update=$(stat -c %Y /var/lib/apt/lists 2>/dev/null)"
fi

sec df
# fstype, size, used, avail, use%, mount (1K blocks, POSIX format)
df -PT -k -x tmpfs -x devtmpfs -x squashfs -x overlay -x efivarfs 2>/dev/null | tail -n +2

sec df_inodes
df -P -i -x tmpfs -x devtmpfs -x squashfs -x overlay -x efivarfs 2>/dev/null | tail -n +2

sec lsblk
lsblk -P -b -o NAME,KNAME,TYPE,SIZE,FSTYPE,MOUNTPOINT,MODEL,PKNAME 2>/dev/null \
  || lsblk -P -b -o NAME,KNAME,TYPE,SIZE,FSTYPE,MOUNTPOINT,MODEL 2>/dev/null

sec users
# name:uid:gid:gecos:home:shell + groups + authorized_keys count
getent passwd 2>/dev/null | while IFS=: read -r name _ uid gid gecos home shell; do
  case "$shell" in */nologin|*/false|/bin/sync|"") login=0 ;; *) login=1 ;; esac
  if [ "$uid" = 0 ] || { [ "$uid" -ge 1000 ] && [ "$uid" != 65534 ]; } || [ "$login" = 1 ]; then
    groups="$(id -nG "$name" 2>/dev/null | tr ' ' ',')"
    keys=-1
    if [ -r "$home/.ssh/authorized_keys" ]; then
      keys=$(grep -cE '^(ssh-|ecdsa-|sk-)' "$home/.ssh/authorized_keys" 2>/dev/null)
    elif [ -n "$SUDO" ] && $SUDO test -f "$home/.ssh/authorized_keys" 2>/dev/null; then
      keys=$($SUDO grep -cE '^(ssh-|ecdsa-|sk-)' "$home/.ssh/authorized_keys" 2>/dev/null)
    elif [ -n "$SUDO" ] || [ "$(id -u)" = 0 ]; then
      keys=0
    fi
    pwstate=""
    if [ "$(id -u)" = 0 ]; then pwstate=$(getent shadow "$name" | cut -d: -f2 | cut -c1-1)
    elif [ -n "$SUDO" ]; then pwstate=$($SUDO getent shadow "$name" 2>/dev/null | cut -d: -f2 | cut -c1-1); fi
    printf '%s|%s|%s|%s|%s|%s|%s|%s|%s\n' "$name" "$uid" "$gid" "$gecos" "$home" "$shell" "$groups" "$keys" "$pwstate"
  fi
done

sec last_logins
if have lastlog; then lastlog 2>/dev/null | tail -n +2 | grep -v 'Never logged in' | head -50; fi

sec services
if have systemctl; then
  systemctl list-units --type=service --state=running --no-legend --no-pager --plain 2>/dev/null \
    | awk '{u=$1; $1=$2=$3=$4=""; sub(/^ +/,""); print u "|" $0}'
fi

sec failed_units
if have systemctl; then
  systemctl list-units --state=failed --no-legend --no-pager --plain 2>/dev/null | awk '{print $1}'
fi

sec listening
if have ss; then
  $SUDO ss -H -lntup 2>/dev/null || $SUDO ss -lntup 2>/dev/null | tail -n +2
elif have netstat; then
  $SUDO netstat -lntup 2>/dev/null | tail -n +3
fi

sec docker
if have docker; then
  $SUDO docker ps --format '{{.Names}}|{{.Image}}|{{.Status}}|{{.Ports}}' 2>/dev/null
fi

sec packages
# binary|version|arch|source|source_version|status
dpkg-query -W -f='${Package}|${Version}|${Architecture}|${source:Package}|${source:Version}|${db:Status-Abbrev}\n' 2>/dev/null \
  || dpkg-query -W -f='${Package}|${Version}|${Architecture}|${Source}||${Status}\n' 2>/dev/null

sec apt_sources
grep -hsE '^[[:space:]]*deb[[:space:]]' /etc/apt/sources.list /etc/apt/sources.list.d/*.list 2>/dev/null
grep -hsE '^(URIs|Suites|Components):' /etc/apt/sources.list.d/*.sources 2>/dev/null

sec apt_refresh
if [ "$APT_REFRESH" = "1" ]; then
  if [ "$(id -u)" = 0 ]; then apt-get update -qq >/dev/null 2>&1 && echo ok || echo failed
  elif [ -n "$SUDO" ]; then $SUDO apt-get update -qq >/dev/null 2>&1 && echo ok || echo failed
  else echo no-privileges; fi
else
  echo skipped
fi

sec upgradable
# Simulation only, nothing is installed. Format: Inst pkg [old] (new suite [arch])
apt-get -s -o Debug::NoLocking=1 dist-upgrade 2>/dev/null | grep '^Inst '

sec certs
# TLS certificates on disk used by typical services (not the CA bundle)
if have openssl; then
  for f in $( { ls /etc/letsencrypt/live/*/cert.pem 2>/dev/null;
               find /etc/nginx /etc/apache2 /etc/haproxy /etc/ssl/private /etc/ssl/localcerts /etc/postfix /etc/dovecot /etc/caddy /var/lib/caddy \
                    -maxdepth 6 \( -name '*.crt' -o -name '*.pem' -o -name '*.cer' \) -type f 2>/dev/null; } | sort -u | head -200 ); do
    case "$f" in *privkey*|*.key|*chain*|*/ca-certificates*|*-ca.pem) continue ;; esac
    out=$($SUDO openssl x509 -in "$f" -noout -subject -issuer -enddate -startdate 2>/dev/null) || continue
    subj=$(echo "$out" | sed -n 's/^subject= *//p')
    iss=$(echo "$out" | sed -n 's/^issuer= *//p')
    end=$(echo "$out" | sed -n 's/^notAfter=//p')
    st=$(echo "$out" | sed -n 's/^notBefore=//p')
    sig=$($SUDO openssl x509 -in "$f" -noout -text 2>/dev/null | grep -m1 'Signature Algorithm' | sed 's/.*: //')
    bits=$($SUDO openssl x509 -in "$f" -noout -text 2>/dev/null | grep -m1 -E 'Public-Key:|Public Key:' | grep -oE '[0-9]+')
    san=$($SUDO openssl x509 -in "$f" -noout -text 2>/dev/null | grep -A1 'Subject Alternative Name' | tail -1 | sed 's/^ *//' | cut -c1-300)
    printf '%s|%s|%s|%s|%s|%s|%s|%s\n' "$f" "$subj" "$iss" "$st" "$end" "$sig" "$bits" "$san"
  done
fi

sec sshd
if have sshd; then
  $SUDO sshd -T 2>/dev/null | grep -E '^(permitrootlogin|passwordauthentication|pubkeyauthentication|port|permitemptypasswords|x11forwarding|kbdinteractiveauthentication|challengeresponseauthentication) '
fi
have ssh && echo "ssh_version=$(ssh -V 2>&1 | head -1)"

sec end
echo ok
