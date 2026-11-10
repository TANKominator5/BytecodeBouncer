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
    rm -f "$tmp/policy.rules" "$tmp/other.rules" "$tmp/invalid.rules"
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
nsenter --net="/run/netns/$ns" python3 tests/bench/stress.py "$tmp"
nsenter --net="/run/netns/$ns" ./trafficcop stop
started=0
echo 'Daemon logging/reload stress passed'
