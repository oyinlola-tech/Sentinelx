#!/usr/bin/env bash
# Live attack demo: SentinelX in Docker, attacked by real tools, on this machine only.
#
# What it does
#   up          Build and start the Compose stack with live capture and real nftables
#               control granted to the API container, create the first administrator
#               and start capturing.
#   attack      Three attacker containers on the stack's private network run nmap
#               (SYN, Xmas and UDP scans), hping3 (SYN and ICMP floods), dig
#               (tunnelling-shaped DNS) and an HTTP flood against the API container.
#   report      Print what SentinelX detected, per source, and the incidents.
#   prevention  Enable automatic prevention (typed confirmation), attack from a fourth
#               container, and show the block in the kernel and its effect.
#   unblock     Remove that block, show traffic flowing again, and return to
#               detection only with dry run.
#   lab         Generate two synthetic captures and replay them in the PCAP Lab.
#   all         up, attack, report, prevention, unblock, lab.
#   down        Stop the stack and delete its volumes and the demo state.
#
# Safety
#   * Every packet stays on the stack's private Docker bridge network. Nothing is sent
#     to your LAN or the internet.
#   * Firewall rules change inside the API container's own network namespace. The
#     host firewall is never touched.
#   * The stack runs on ports 3300 (dashboard), 8800 (API), 5533 and 6481, all bound
#     to 127.0.0.1, so it does not collide with a stack on the default ports.
#
# State: .demo/ (git-ignored) holds the generated secrets and the administrator
# password, readable only by you. Sign in at http://127.0.0.1:3300 as "admin" with the
# password in .demo/admin-password.
#
# Requirements: Linux, Docker with Compose v2, python3, curl.
set -euo pipefail

REPO=$(cd "$(dirname "$0")/.." && pwd)
STATE="$REPO/.demo"
API=http://127.0.0.1:8800/api/v1
NET=sentinelx_backend
ATTACKER_IMAGE=sentinelx-demo-attacker

cd "$REPO"
mkdir -p "$STATE"
chmod 700 "$STATE"

say() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
json() { python3 -c "import sys, json; d = json.load(sys.stdin); $1"; }
compose() {
  docker compose --env-file "$STATE/stack.env" -f docker-compose.yml -f "$STATE/live.override.yml" "$@"
}
api_ip() { docker inspect -f '{{with index .NetworkSettings.Networks "sentinelx_backend"}}{{.IPAddress}}{{end}}' sentinelx-api-1; }

# Authenticated API call: call METHOD PATH [JSON]. The token is cached for 10 minutes.
call() {
  local token_file="$STATE/token"
  if [ ! -s "$token_file" ] || [ $(( $(date +%s) - $(stat -c %Y "$token_file") )) -gt 600 ]; then
    STATE="$STATE" API="$API" python3 - > "$token_file.tmp" <<'PY'
import json, os, urllib.request
body = json.dumps({"username": "admin", "password": open(os.environ["STATE"] + "/admin-password").read()})
request = urllib.request.Request(os.environ["API"] + "/auth/login", body.encode(), {"content-type": "application/json"})
print(json.load(urllib.request.urlopen(request))["access_token"])
PY
    chmod 600 "$token_file.tmp" && mv "$token_file.tmp" "$token_file"
  fi
  local args=(-s -X "$1" "$API$2" -H "Authorization: Bearer $(cat "$token_file")")
  [ $# -ge 3 ] && args+=(-H 'content-type: application/json' -d "$3")
  curl "${args[@]}"
}

write_config() {
  if [ ! -s "$STATE/stack.env" ]; then
    (umask 077; python3 - > "$STATE/stack.env" <<'PY'
import secrets
print(f"POSTGRES_PASSWORD={secrets.token_urlsafe(24)}")
print(f"REDIS_PASSWORD={secrets.token_urlsafe(24)}")
print(f"JWT_SECRET={secrets.token_urlsafe(48)}")
print("POSTGRES_HOST_PORT=5533\nREDIS_HOST_PORT=6481\nAPI_PORT=8800\nDASHBOARD_PORT=3300")
print("CORS_ORIGINS=http://127.0.0.1:3300,http://localhost:3300")
PY
    )
  fi
  cat > "$STATE/live.override.yml" <<'YML'
# Demo only: the API captures and changes nftables inside its own network namespace.
services:
  api:
    command: ["python3-sensor", "-m", "sentinelx", "start"]
    cap_add: [NET_RAW, NET_ADMIN]
    security_opt: ["no-new-privileges:false"]
    environment:
      FIREWALL_BACKEND: nftables
YML
}

build_attacker() {
  docker image inspect "$ATTACKER_IMAGE" >/dev/null 2>&1 && return
  say "Build the attacker image (nmap, hping3, dig, curl)"
  docker build -q -t "$ATTACKER_IMAGE" - <<'DOCKERFILE'
FROM python:3.12-slim
RUN apt-get update -qq \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends nmap hping3 dnsutils curl >/dev/null \
 && rm -rf /var/lib/apt/lists/*
DOCKERFILE
}

up() {
  write_config
  build_attacker
  say "Start the stack"
  compose up -d --build --wait >"$STATE/up.log" 2>&1 || { tail -20 "$STATE/up.log"; exit 1; }
  compose ps --format '  {{.Service}}: {{.Status}}'

  if [ ! -s "$STATE/admin-password" ]; then
    say "First administrator: read the one-time password from its file, then choose a new one"
    local first new token
    first=$(compose exec -T api cat /tmp/sentinelx/initial-admin-password)
    new="Demo-$(python3 -c 'import secrets; print(secrets.token_urlsafe(15))')"
    token=$(curl -s -X POST "$API/auth/login" -H 'content-type: application/json' \
      -d "{\"username\":\"admin\",\"password\":\"$first\"}" | json 'print(d["access_token"])')
    curl -s -o /dev/null -w '  change password: HTTP %{http_code}\n' -X POST "$API/auth/change-password" \
      -H "Authorization: Bearer $token" -H 'content-type: application/json' \
      -d "{\"current_password\":\"$first\",\"new_password\":\"$new\"}"
    (umask 077; printf '%s' "$new" > "$STATE/admin-password")
    compose exec -T api sh -c 'test -e /tmp/sentinelx/initial-admin-password && echo "  one-time password file: still present" || echo "  one-time password file: deleted"'
  fi

  say "Start live capture on every interface of the API container ($(api_ip))"
  call POST /sensors/start '{"interface":"any","bpf_filter":null}' | json 'print("  capture:", d["state"], "via", d["backend"])'
  echo "  dashboard: http://127.0.0.1:3300  (admin / password in .demo/admin-password)"
}

reach() {  # reach LABEL: can attacker 172.22.0.204 reach the API?
  local code
  code=$(docker exec sentinelx-demo-d curl -s -o /dev/null -m 4 -w '%{http_code}' "http://$(api_ip):8000/api/v1/system/health" || true)
  if [ "$code" = 000 ] || [ -z "$code" ]; then echo "  $1: no response (packets dropped)"; else echo "  $1: HTTP $code"; fi
}

attacker() {  # attacker IP COMMANDS
  docker run --rm --network "$NET" --ip "$1" "$ATTACKER_IMAGE" sh -c "$2"
}

attack() {
  local target; target=$(api_ip)
  say "Attacker 172.22.0.201: SYN scan, Xmas scan, UDP scan, then a SYN flood on the open API port"
  attacker 172.22.0.201 "
    nmap -sS -Pn -n -p 1-1000 --max-rate 1500 $target | tail -1
    nmap -sX -Pn -n -p 1-120 --max-rate 800 $target | tail -1
    nmap -sU -Pn -n -p 1-150 --max-retries 0 --min-rate 300 $target | tail -1
    hping3 -S -p 8000 -i u200 -c 4000 -q $target 2>&1 | grep 'packets transmitted'"
  say "Attacker 172.22.0.202: 80 DNS TXT queries with encoded-looking labels"
  attacker 172.22.0.202 "
    i=0; while [ \$i -lt 80 ]; do
      label=\$(head -c 30 /dev/urandom | base32 | tr -d '=' | tr 'A-Z' 'a-z')
      dig @$target \$label.\$i.exfil.example.test TXT +tries=1 +time=0 >/dev/null 2>&1; i=\$((i+1))
    done; echo 'sent 80 queries'"
  say "Attacker 172.22.0.203: ICMP flood, then 1,500 HTTP requests from 32 threads"
  attacker 172.22.0.203 "
    hping3 --icmp -i u400 -c 3000 -q $target 2>&1 | grep 'packets transmitted'
    python3 -c \"
import concurrent.futures, urllib.request, urllib.error
url = 'http://$target:8000/api/v1/system/health'
def hit(_):
    try: return urllib.request.urlopen(url, timeout=3).status
    except urllib.error.HTTPError as error: return error.code
    except Exception: return 'no response'
with concurrent.futures.ThreadPoolExecutor(32) as pool: codes = list(pool.map(hit, range(1500)))
print('HTTP responses:', {code: codes.count(code) for code in set(codes)})\""
  sleep 6
}

report() {
  say "Detections by source"
  call GET "/detections?limit=500" | json '
import collections
counts = collections.Counter((x["source_ip"], x["detector"]) for x in d["items"])
for (source, detector), n in sorted(counts.items()): print(f"  {source:15} {detector:26} x{n}")
print("  total:", len(d["items"]))'
  say "Incidents"
  call GET "/incidents?limit=50" | json '
for i in d["items"]: print("  %-6s %s" % (i["status"], i["title"]))'
}

prevention() {
  local target; target=$(api_ip)
  say "Enable automatic prevention with dry run off (requires the typed confirmation)"
  call PATCH /config/response '{"changes":{"mode":"automatic","dry_run":false},"confirmation":"ENABLE PREVENTION"}' >/dev/null
  call GET /firewall | json 's = d["status"]; print("  mode:", s["mode"], "| dry run:", s["dry_run"], "| prevention active:", s["prevention_active"])'

  say "Attacker 172.22.0.204: reachable first, then a port scan"
  docker rm -f sentinelx-demo-d >/dev/null 2>&1 || true
  docker run -d --name sentinelx-demo-d --network "$NET" --ip 172.22.0.204 "$ATTACKER_IMAGE" sleep 900 >/dev/null
  reach "before the attack"
  docker exec sentinelx-demo-d nmap -sS -Pn -n -p 1-1000 --max-rate 1500 "$target" | tail -1
  say "Wait for SentinelX to act on 172.22.0.204"
  local waited=0 active=""
  while [ $waited -lt 45 ]; do
    active=$(call GET /firewall | json '
hits = [b for b in d["active"] if b["network"].startswith("172.22.0.204")]
print(("rate limit" if hits[0]["rate_limited"] else "block") if hits else "")')
    [ -n "$active" ] && break
    sleep 1; waited=$((waited + 1))
  done
  echo "  after ${waited}s: ${active:-no action}"
  # The firewall applies the block at once; its decision record reaches the database
  # a moment later, through the event persister's buffer.
  local decision="" tries=0
  while [ -z "$decision" ] && [ $tries -lt 10 ]; do
    decision=$(call GET /firewall | json '
hits = [a for a in d["actions"] if a["target"] == "172.22.0.204" and a["action"] != "unblock_ip"]
print("%s %s - %s" % (hits[0]["action"], hits[0]["outcome"], hits[0]["reason"]) if hits else "")')
    [ -z "$decision" ] && sleep 1
    tries=$((tries + 1))
  done
  echo "  decision: ${decision:-not recorded yet}"
  say "The same attacker now floods the API port"
  docker exec sentinelx-demo-d hping3 -S -p 8000 -i u200 -c 3000 -q "$target" 2>&1 | grep 'packets transmitted' || true
  reach "after the block"
  say "The block in the kernel (nftables inside the API container)"
  compose exec -T -u root api nft list table inet sentinelx | tee "$STATE/nftables-blocked.txt" | sed -n '1,6p;/chain input/,/}/p' | sed 's/^/  /'
}

unblock() {
  local target; target=$(api_ip)
  say "Unblock 172.22.0.204"
  call POST /firewall/unblock '{"target":"172.22.0.204","reason":"live demo: restore"}' | json 'print("  unblock:", d.get("outcome"))'
  sleep 2
  compose exec -T -u root api nft list set inet sentinelx blocklist_v4 | sed 's/^/  /'
  reach "after unblock"
  docker rm -f sentinelx-demo-d >/dev/null
  say "Back to the safe default"
  call PATCH /config/response '{"changes":{"mode":"detect_only","dry_run":true}}' >/dev/null
  call GET /firewall | json 's = d["status"]; print("  mode:", s["mode"], "| dry run:", s["dry_run"])'
}

lab() {
  say "PCAP Lab: generate and replay two synthetic captures"
  local scenario id status
  for scenario in mixed_intrusion dns_tunneling; do
    call POST "/replay/scenarios/$scenario" '{}' | json 'print("  generated", d["path"], "-", d["packets"], "packets")'
    id=$(call POST /replay "{\"path\":\"fixtures/$scenario.pcap\"}" | json 'print(d["replay_id"])')
    for _ in $(seq 1 60); do
      status=$(call GET "/replay/$id" | json 'print(d["status"])')
      [ "$status" = completed ] && break
      sleep 1
    done
    call GET "/replay/$id" | json 'p = d["progress"]; print("  replayed %s: %d detections, %d incident(s), %s packets/s" % (d["filename"], p["detections"], p["incidents"], format(p["packets_per_second"], ",.0f")))'
  done
}

down() {
  write_config
  compose down -v
  docker rm -f sentinelx-demo-d >/dev/null 2>&1 || true
  rm -rf "$STATE"
}

all() { up; attack; report; prevention; unblock; lab; }

case "${1:-}" in
  up|attack|report|prevention|unblock|lab|all|down) "$1" ;;
  *) sed -n '2,32p' "$0" | sed 's/^# \{0,1\}//'; exit 2 ;;
esac
