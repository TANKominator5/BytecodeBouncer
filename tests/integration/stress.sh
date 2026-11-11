#!/usr/bin/env bash
# Separate consequential-load checks; no host interfaces or unrelated daemon.
set -euo pipefail
cd "$(dirname "$0")/../.."
[[ $EUID == 0 ]] || { echo 'run with sudo' >&2; exit 1; }
[[ ! -S /run/trafficcop/control.sock ]] || { echo 'trafficcop already running; refusing stress test' >&2; exit 1; }
tmp=$(mktemp -d)
ns="tc-stress-$$"
created=0
started=0
cleanup() {
    if [[ $started == 1 ]]; then nsenter --net="/run/netns/$ns" ./trafficcop stop >/dev/null 2>&1 || true; fi
    if [[ $created == 1 ]]; then ip netns del "$ns" || true; fi
    rm -f "$tmp/policy.rules" "$tmp/other.rules" "$tmp/invalid.rules" "$tmp/daemon.pid"
    rmdir "$tmp"
}
trap cleanup EXIT
ip netns add "$ns"
created=1
ip -n "$ns" link add eth0 type veth peer name players
nsenter --net="/run/netns/$ns" sysctl -q -w net.ipv6.conf.all.disable_ipv6=1
for name in lo eth0 players; do ip -n "$ns" link set "$name" up; done
printf 'drop proto udp dport 5000-65535 log\ndefault pass\n' > "$tmp/policy.rules"
nsenter --net="/run/netns/$ns" ./trafficcop start eth0 "$tmp/policy.rules"
started=1
nsenter --net="/run/netns/$ns" python3 - <<'PY' > "$tmp/daemon.pid"
import socket,struct
s=socket.socket(socket.AF_UNIX);s.connect('/run/trafficcop/control.sock')
print(struct.unpack('3i',s.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))[0])
s.close()
PY
nsenter --net="/run/netns/$ns" python3 tests/bench/stress.py "$tmp"
nsenter --net="/run/netns/$ns" ./trafficcop stop
started=0
nsenter --net="/run/netns/$ns" python3 - "$tmp/daemon.pid" <<'PY'
import json,pathlib,socket,subprocess,sys,time
pid=pathlib.Path(sys.argv[1]).read_text().strip()
deadline=time.monotonic()+4
while time.monotonic()<deadline:
    fds=pathlib.Path('/proc')/pid/'fd'
    if not fds.exists() or not list(fds.iterdir()):break
    time.sleep(.01)
else:raise AssertionError('daemon retained descriptors after stop')
assert not pathlib.Path('/run/trafficcop/control.sock').exists()
s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind(('127.0.0.1',8088));s.close()
assert not json.loads(subprocess.check_output(['ip','-j','link','show','eth0']))[0].get('xdp',{}).get('attached')
print('PASS: daemon descriptors, socket, HTTP port and XDP attachment released')
PY
echo 'Daemon logging/reload stress passed'
