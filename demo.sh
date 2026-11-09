#!/usr/bin/env bash
# Persistent, isolated demo; never attaches to a host interface.
set -euo pipefail
cd "$(dirname "$0")"
usage() { echo 'usage: sudo ./demo.sh start|stats|dashboard|stop' >&2; exit 1; }
[[ $# == 1 ]] || usage
case "$1" in start|stats|dashboard|stop) ;; *) usage ;; esac
[[ $EUID == 0 ]] || { echo 'run with sudo: sudo ./demo.sh '"$1" >&2; exit 1; }
ns=trafficcop-demo
state=/run/trafficcop-demo
netns="/run/netns/$ns"
socket=/run/trafficcop/control.sock
exec 9>/run/trafficcop-demo.lock
flock -n 9 || { echo 'another demo command is running' >&2; exit 1; }
owned_namespace() {
  [[ -f $state/namespace && -e $netns ]] &&
    [[ $(cat "$state/namespace") == "$(stat -Lc %i "$netns")" ]]
}
owned_daemon() {
  [[ -f $state/socket && -S $socket ]] &&
    [[ $(cat "$state/socket") == "$(stat -Lc %i "$socket")" ]]
}
run() { nsenter --net="$netns" "$@" 9>&-; }
case "$1" in
 start)
  [[ -x ./trafficcop ]] || { echo 'build first: ./build.sh' >&2; exit 1; }
  [[ ! -e $state && ! -e $netns && ! -S $socket ]] || {
    echo 'demo resources or another trafficcop instance already exist; use demo.sh stop for an owned demo' >&2; exit 1;
  }
  mkdir -m 700 "$state"
  created=0; started=0
  rollback() {
    result=$?
    if (( result != 0 )); then
      if (( started )); then run ./trafficcop stop >&2 || true; fi
      if (( created )); then ip netns del "$ns" || true; fi
      rm -f "$state/namespace" "$state/socket"
      rmdir "$state" || true
    fi
  }
  trap rollback EXIT
  ip netns add "$ns"; created=1
  stat -Lc %i "$netns" > "$state/namespace"
  ip -n "$ns" link add eth0 type veth peer name players
  ip -n "$ns" link set eth0 up
  ip -n "$ns" link set players up
  ip -n "$ns" link set lo up
  run ./trafficcop start eth0 tests/fixtures/bootstrap.rules
  started=1
  stat -Lc %i "$socket" > "$state/socket"
  echo 'Demo started (pass-through only).'
  echo 'Stats: sudo ./demo.sh stats'
  echo 'Browser dashboard: sudo ./demo.sh dashboard, then open http://127.0.0.1:8088/'
  echo 'Stop and clean up: sudo ./demo.sh stop'
  ;;
 stats|dashboard)
  owned_namespace && owned_daemon || { echo 'demo is not running; use sudo ./demo.sh start' >&2; exit 1; }
  if [[ $1 == stats ]]; then run ./trafficcop stats
  else
    # Foreground proxy must not retain the demo lock: stop can run in another terminal.
    flock -u 9
    exec 9>&-
    exec python3 tests/bench/dashboard_proxy.py "$netns"
  fi
  ;;
 stop)
  if [[ ! -e $state && ! -e $netns ]]; then echo 'Demo is already stopped.'; exit 0; fi
  owned_namespace || { echo 'namespace ownership cannot be verified; refusing to remove it' >&2; exit 1; }
  if [[ -S $socket ]]; then
    owned_daemon || { echo 'another trafficcop instance owns the socket; refusing to stop it' >&2; exit 1; }
    run ./trafficcop stop
  fi
  ip netns del "$ns"
  rm -f "$state/namespace" "$state/socket"
  rmdir "$state"
  echo 'Demo stopped; namespace removed. Stop any foreground dashboard proxy with Ctrl+C.'
  ;;
esac
