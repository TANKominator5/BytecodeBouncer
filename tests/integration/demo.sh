#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
[[ $EUID == 0 ]] || { echo 'run with sudo' >&2; exit 1; }
[[ ! -e /run/trafficcop-demo && ! -e /run/netns/trafficcop-demo && ! -S /run/trafficcop/control.sock ]] || {
  echo 'existing demo/trafficcop resources; refusing test' >&2; exit 1;
}
started=0; proxy=''
cleanup() {
  if [[ -n $proxy ]]; then kill "$proxy" 2>/dev/null || true; wait "$proxy" 2>/dev/null || true; fi
  if (( started )); then ./demo.sh stop || true; fi
}
trap cleanup EXIT
./demo.sh start
started=1
./demo.sh stats | python3 -c 'import json,sys; assert json.load(sys.stdin)["rules_version"] == 1'
if ./demo.sh start; then echo 'duplicate start unexpectedly succeeded' >&2; exit 1; fi
./demo.sh dashboard &
proxy=$!
python3 - <<'PY'
import json,time,urllib.request
for attempt in range(30):
    try:
        with urllib.request.urlopen('http://127.0.0.1:8088/',timeout=1) as r:
            assert b'Bytecode Bouncer' in r.read()
        break
    except OSError:
        time.sleep(.1)
else:
    raise AssertionError('dashboard proxy did not become ready')
with urllib.request.urlopen('http://127.0.0.1:8088/stats.json',timeout=2) as r:
    assert json.load(r)['rules_version']==1
for path in ('app.js','app.css','jail.json','log.json','health.json'):
    with urllib.request.urlopen('http://127.0.0.1:8088/'+path,timeout=2) as r:
        assert r.status==200
print('PASS: host browser proxy reaches demo page and stats')
PY
# Stop must work while the foreground proxy is still running (no inherited lock).
./demo.sh stop
started=0
./demo.sh stop
[[ ! -e /run/netns/trafficcop-demo && ! -e /run/trafficcop-demo && ! -S /run/trafficcop/control.sock ]]
if ./demo.sh stats; then echo 'stats unexpectedly succeeded after stop' >&2; exit 1; fi
echo 'Demo integration checks passed'
