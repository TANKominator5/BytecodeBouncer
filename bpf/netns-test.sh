#!/usr/bin/env bash
# Native XDP wire checks and program replacement only on private veth interfaces.
set -euo pipefail
cd "$(dirname "$0")/.."
[[ $EUID == 0 ]] || { echo 'run with sudo' >&2; exit 1; }
tmp=$(mktemp -d)
ns="tc-policy-$$"
created=0
cleanup() {
    if [[ $created == 1 ]]; then ip netns del "$ns" || true; fi
    rm -f "$tmp/dataplane.test"
    rmdir "$tmp"
}
trap cleanup EXIT
go test -c -o "$tmp/dataplane.test" ./internal/dataplane
ip netns add "$ns"
created=1
ip -n "$ns" link add eth0 type veth peer name players
ip -n "$ns" link add hp0 type veth peer name trap
for name in lo eth0 players hp0 trap; do ip -n "$ns" link set "$name" up; done
nsenter --net="/run/netns/$ns" env TC_BPF_TEST=1 TC_BPF_NETNS_TEST=1 \
    "$tmp/dataplane.test" -test.run '^TestKernelWireAndReplacement$' -test.v -test.count=1
