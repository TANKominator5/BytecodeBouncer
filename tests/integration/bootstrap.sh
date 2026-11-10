#!/usr/bin/env bash
# Dedicated namespace; never attaches to a real host network interface.
set -euo pipefail
cd "$(dirname "$0")/../.."
[[ $EUID -eq 0 ]] || { echo 'run with sudo' >&2; exit 1; }
[[ ! -S /run/trafficcop/control.sock ]] || { echo 'trafficcop already running; refusing smoke test' >&2; exit 1; }
ns="tc-smoke-$$"
started=0
cleanup() {
  if [[ $started == 1 ]]; then nsenter --net="/run/netns/$ns" ./trafficcop stop >/dev/null 2>&1 || true; fi
  ip netns del "$ns" 2>/dev/null || true
}
trap cleanup EXIT
ip netns add "$ns"
ip -n "$ns" link add eth0 type veth peer name players
ip -n "$ns" link set eth0 up
ip -n "$ns" link set players up
ip -n "$ns" link set lo up
run() { nsenter --net="/run/netns/$ns" "$@"; }
# A missing honeypot interface must not attach anything.
echo 'EXPECTED FAILURE: missing honeypot interface (the following error is intentional)'
if run ./trafficcop start eth0 /dev/null extra; then echo 'unexpected unsupported-argument success' >&2; exit 1; fi
[[ ! -S /run/trafficcop/control.sock ]]
# Attachment failure must release the socket, lock and HTTP listener.
echo 'EXPECTED FAILURE: nonexistent interface (the following error is intentional)'
if run ./trafficcop start nonexistent0 tests/fixtures/bootstrap.rules; then echo 'unexpected attachment success' >&2; exit 1; fi
[[ ! -S /run/trafficcop/control.sock ]]
SECONDS=0
run ./trafficcop start eth0 tests/fixtures/bootstrap.rules
started=1
(( SECONDS < 5 ))
run python3 - <<'PY'
import json,socket,subprocess,time,urllib.request
binary='./trafficcop'
def call(*args): return subprocess.run([binary,*args],capture_output=True,text=True,timeout=1)
assert call('start','eth0','tests/fixtures/bootstrap.rules').returncode==1
before=json.loads(call('stats').stdout)
# Broadcast ARP-shaped Ethernet frames bypass filtering and count as other.
s=socket.socket(socket.AF_PACKET,socket.SOCK_RAW);s.bind(('players',0))
frame=b'\xff'*6+b'\x02\x00\x00\x00\x00\x02'+b'\x08\x06'+b'\x00'*46
for _ in range(32): s.send(frame)
s.close();time.sleep(.1)
after=json.loads(call('stats').stdout)
assert after['passed']>=before['passed']+32,(before,after)
assert after['other']>=before['other']+32,(before,after)
assert after['passed']+after['dropped']+after['bounced']+after['honeypotted']>=32
with urllib.request.urlopen('http://127.0.0.1:8088/stats.json',timeout=1) as r: web=json.load(r)
assert set(web)==set(after)
assert web['passed']>=after['passed']
with urllib.request.urlopen('http://127.0.0.1:8088/',timeout=1) as r: assert b'Bootstrap' in r.read()
assert call('reload','/nonexistent/trafficcop.rules').returncode==1
assert call('reload','tests/fixtures/bootstrap.rules').returncode==0
assert call('stats').returncode==0
print('PASS: real XDP counters, singleton, HTTP, failed/successful reload')
PY
SECONDS=0
run ./trafficcop stop
started=0
(( SECONDS < 5 ))
[[ ! -S /run/trafficcop/control.sock ]]
run python3 - <<'PY'
import socket,subprocess,json
s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind(('127.0.0.1',8088));s.close()
r=subprocess.run(['./trafficcop','stats'],capture_output=True);assert r.returncode==1
links=json.loads(subprocess.check_output(['ip','-j','link','show','eth0']))
assert not links[0].get('xdp',{}).get('attached'),links
print('PASS: detach, stopped commands, socket removal and port release')
PY
# Restart checks release of singleton lock and attachment resources.
run ./trafficcop start eth0 tests/fixtures/bootstrap.rules
started=1
run ./trafficcop stop
started=0
echo 'Bootstrap integration checks passed'
