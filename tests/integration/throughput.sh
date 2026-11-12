#!/usr/bin/env bash
# Disposable native-XDP veth flood only; never targets a real host interface.
set -euo pipefail
cd "$(dirname "$0")/../.."
[[ $EUID == 0 ]] || { echo 'run with sudo' >&2; exit 1; }
[[ ! -S /run/trafficcop/control.sock ]] || { echo 'trafficcop running; refusing benchmark' >&2; exit 1; }
seconds=${1:-15}
[[ $seconds =~ ^[0-9]+$ ]] && (( seconds >= 1 && seconds <= 600 )) || { echo 'seconds must be 1-600' >&2; exit 1; }
tmp=$(mktemp -d)
ns="tc-throughput-$$"
created=0
started=0
cleanup() {
    if [[ $started == 1 ]]; then nsenter --net="/run/netns/$ns" ./trafficcop stop >/dev/null 2>&1 || true; fi
    if [[ $created == 1 ]]; then ip netns del "$ns" || true; fi
    rm -f "$tmp/flood" "$tmp/policy.rules"
    rmdir "$tmp"
}
trap cleanup EXIT
gcc -O2 -Wall -Werror -pthread tests/bench/flood.c -o "$tmp/flood"
ip netns add "$ns"
created=1
ip -n "$ns" link add eth0 type veth peer name players
nsenter --net="/run/netns/$ns" sysctl -q -w net.ipv6.conf.all.disable_ipv6=1
for name in lo eth0 players; do ip -n "$ns" link set "$name" up; done
printf 'default pass\n' > "$tmp/policy.rules"
nsenter --net="/run/netns/$ns" ./trafficcop start eth0 "$tmp/policy.rules"
started=1
nsenter --net="/run/netns/$ns" python3 tests/bench/throughput.py "$tmp" "$seconds"
nsenter --net="/run/netns/$ns" ./trafficcop stop
started=0
echo 'Private-veth ingress benchmark passed; not a physical-NIC throughput claim'
