#!/usr/bin/env bash
# Consequential memory/output test of the actual daemon, not a fake provider.
set -euo pipefail
cd "$(dirname "$0")/../.."
[[ $EUID == 0 ]] || { echo 'run with sudo' >&2; exit 1; }
[[ ! -S /run/trafficcop/control.sock ]] || { echo 'trafficcop running; refusing capacity test' >&2; exit 1; }
awk '/MemAvailable:/{if ($2 < 1572864) exit 1}' /proc/meminfo || { echo 'requires 1.5 GiB available; refusing host OOM pressure' >&2; exit 1; }
tmp=$(mktemp -d)
ns="tc-commands-$$"
created=0
started=0
cleanup() {
    if [[ $started == 1 ]]; then nsenter --net="/run/netns/$ns" ./trafficcop stop >/dev/null 2>&1 || true; fi
    if [[ $created == 1 ]]; then ip netns del "$ns" || true; fi
    rm -f "$tmp/populate" "$tmp/policy.rules" "$tmp/limits.rules"
    rmdir "$tmp"
}
trap cleanup EXIT
env GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=safe.directory "GIT_CONFIG_VALUE_0=$PWD" go build -o "$tmp/populate" ./tests/bench/populate
ip netns add "$ns"
created=1
ip -n "$ns" link add eth0 type veth peer name players
nsenter --net="/run/netns/$ns" sysctl -q -w net.ipv6.conf.all.disable_ipv6=1
for name in lo eth0 players; do ip -n "$ns" link set "$name" up; done
printf 'default pass\nset live\n' > "$tmp/policy.rules"
for _ in {1..64}; do printf 'pass\n' >> "$tmp/policy.rules"; done
nsenter --net="/run/netns/$ns" ./trafficcop start eth0 "$tmp/policy.rules"
started=1
pid=$(python3 - <<'PY'
import socket,struct
s=socket.socket(socket.AF_UNIX);s.connect('/run/trafficcop/control.sock')
print(struct.unpack('3i',s.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))[0]);s.close()
PY
)
nsenter --net="/run/netns/$ns" "$tmp/populate" "$pid"
nsenter --net="/run/netns/$ns" python3 tests/bench/command_capacity.py "$tmp"
nsenter --net="/run/netns/$ns" ./trafficcop stop
started=0
