#!/usr/bin/env bash
# Disposable interfaces only. Never stop another session's daemon.
set -euo pipefail
cd "$(dirname "$0")/../.."
[[ $EUID == 0 ]] || { echo 'run with sudo' >&2; exit 1; }
[[ ! -S /run/trafficcop/control.sock ]] || { echo 'trafficcop already running; refusing test' >&2; exit 1; }
tmp=$(mktemp -d)
ns="tc-firewall-$$"
created=0
started=0
cleanup() {
    if [[ $started == 1 ]]; then nsenter --net="/run/netns/$ns" ./trafficcop stop >/dev/null 2>&1 || true; fi
    if [[ $created == 1 ]]; then ip netns del "$ns" || true; fi
    rm -f "$tmp/policy.rules" "$tmp/reload.rules" "$tmp/invalid.rules" "$tmp/honeypot.rules" "$tmp/pass.o"
    rmdir "$tmp"
}
trap cleanup EXIT
ip netns add "$ns"
created=1
ip -n "$ns" link add eth0 type veth peer name players
ip -n "$ns" link add hp0 type veth peer name trap
# Disable only this bench's background IPv6 traffic to get exact frame counts.
nsenter --net="/run/netns/$ns" sysctl -q -w net.ipv6.conf.all.disable_ipv6=1
for name in lo eth0 players hp0 trap; do ip -n "$ns" link set "$name" up; done
clang -O2 -g -target bpfel -I"/usr/include/$(gcc -dumpmachine)" -c tests/bench/pass.bpf.c -o "$tmp/pass.o"
for name in players trap; do ip -n "$ns" link set "$name" xdpdrv obj "$tmp/pass.o" sec xdp; done
cat > "$tmp/policy.rules" <<'RULES'
# exact integration policy
default pass
fragments drop
set blocked 10.0.0.9 2001:db8::9
drop src @blocked log
jail 2 proto udp dport 9000 log
bounce proto udp dport 6666 log
honeypot proto udp dport 7777 log
limit 3/s burst 3 proto udp dport 9001 log
drop proto udp dport 6000-6099 vlan 100 log
drop proto icmp icmp-type 8 log
drop proto icmp6 icmp-type 128 log
drop proto udp dport 5000-5999 log
RULES
printf 'drop proto typo\n' > "$tmp/invalid.rules"
printf 'honeypot\n' > "$tmp/honeypot.rules"
run() { nsenter --net="/run/netns/$ns" "$@"; }
if run ./trafficcop start eth0 "$tmp/invalid.rules"; then echo 'invalid start accepted' >&2; exit 1; fi
if run ./trafficcop start eth0 "$tmp/honeypot.rules"; then echo 'missing honeypot accepted' >&2; exit 1; fi
SECONDS=0
run ./trafficcop start eth0 "$tmp/policy.rules" hp0
started=1
(( SECONDS < 5 ))
run python3 tests/bench/firewall.py "$tmp"
SECONDS=0
run ./trafficcop stop
started=0
(( SECONDS < 5 ))
[[ ! -S /run/trafficcop/control.sock ]]
run python3 - <<'PY'
import json,socket,subprocess
for command in [('stats',),('jail',),('log',),('stop',),('reload','/dev/null'),('set','add','x','::/0'),('unjail','::1')]:
    r=subprocess.run(['./trafficcop',*command],capture_output=True,text=True,timeout=1)
    assert r.returncode==1 and not r.stdout and len(r.stderr.splitlines())==1,(command,r)
sock=socket.socket();sock.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);sock.bind(('127.0.0.1',8088));sock.close()
links=json.loads(subprocess.check_output(['ip','-j','link','show','eth0']))
assert not links[0].get('xdp',{}).get('attached'),links
print('PASS: stopped commands, detached XDP, released port/socket')
PY
# A fresh daemon must have an empty history and start at generation one.
run ./trafficcop start eth0 "$tmp/policy.rules" hp0
started=1
run python3 - <<'PY'
import json,subprocess
assert json.loads(subprocess.check_output(['./trafficcop','log']))==[]
s=json.loads(subprocess.check_output(['./trafficcop','stats']))
assert s['rules_version']==1 and all(r['hits']==0 for r in s['rules'])
print('PASS: restart resets history and rule generation')
PY
run ./trafficcop stop
started=0
echo 'Firewall integration passed'
