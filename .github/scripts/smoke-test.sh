#!/usr/bin/env bash
# Smoke test for a running AmberVentory instance.
#
#   BASE_URL=http://127.0.0.1:8080 AMBER_USER=admin AMBER_PASSWORD=... .github/scripts/smoke-test.sh
#
# SMOKE_SKIP_SCAN=1 skips the nmap check (for hosts without nmap); SCAN_PORT is the port the
# application listens on inside the instance (default 8080).
# It exercises the code paths that write to the filesystem (inventory parsing runs ansible-inventory,
# the scan runs nmap), so it also proves the container works with a read-only root filesystem.
set -euo pipefail

BASE_URL="${BASE_URL:-http://127.0.0.1:8080}"
AUTH=()
if [[ -n "${AMBER_USER:-}" ]]; then
  AUTH=(-u "${AMBER_USER}:${AMBER_PASSWORD:-}")
fi

fail() { echo "FAIL: $*" >&2; exit 1; }
ok() { echo "ok: $*"; }

req() { curl -sS --max-time 60 "${AUTH[@]}" "$@"; }

# 1. liveness works without credentials
[[ "$(curl -sS --max-time 10 "${BASE_URL}/healthz")" == *'"ok":true'* ]] || fail "/healthz"
ok "/healthz"

# 2. authentication is enforced when configured
if [[ -n "${AMBER_USER:-}" ]]; then
  code="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 10 "${BASE_URL}/api/state")"
  [[ "${code}" == "401" ]] || fail "unauthenticated /api/state returned ${code}, expected 401"
  ok "authentication is enforced"
fi

# 3. the API answers and the page is served
req "${BASE_URL}/api/state" | python3 -c 'import json,sys; d=json.load(sys.stdin); assert "vulndb" in d and "reports" in d' \
  || fail "/api/state"
ok "/api/state"
req "${BASE_URL}/" | grep -q "AmberVentory" || fail "index page"
ok "index page"

# 4. inventory upload (runs ansible-inventory)
inv="$(mktemp --suffix=.ini)"
trap 'rm -f "${inv}"' EXIT
printf '[web]\nweb1 ansible_host=10.0.0.5 ansible_port=2222\n[db]\ndb1\n' >"${inv}"
req -F "file=@${inv}" "${BASE_URL}/api/inventory" \
  | python3 -c 'import json,sys; d=json.load(sys.stdin); h={x["name"]:x for x in d["hosts"]}; assert h["web1"]["port"]==2222 and h["db1"]["groups"]==["db"], d' \
  || fail "inventory upload"
ok "inventory upload"

# 5. nmap discovery. The scan runs inside the instance, so it targets the instance's own loopback
#    and the port the application listens on (SCAN_PORT), not the port you reached it through.
if [[ "${SMOKE_SKIP_SCAN:-0}" != "1" ]]; then
  req -H 'Content-Type: application/json' -d "{\"targets\":\"127.0.0.1\",\"port\":${SCAN_PORT:-8080}}" "${BASE_URL}/api/scan" \
    | python3 -c 'import json,sys; d=json.load(sys.stdin); assert any(h["ip"]=="127.0.0.1" for h in d["hosts"]), d' \
    || fail "nmap scan"
  ok "nmap scan"
fi

echo "smoke test passed"
