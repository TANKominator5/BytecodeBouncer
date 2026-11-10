#!/usr/bin/env bash
# Readiness and rollback tests, never attach/replace a host-interface program.
set -euo pipefail
cd "$(dirname "$0")/../.."
[[ $EUID == 0 ]] || { echo 'run with sudo' >&2; exit 1; }
[[ ! -S /run/trafficcop/control.sock ]] || { echo 'trafficcop running; refusing lifecycle test' >&2; exit 1; }
tmp=$(mktemp -d)
ns="tc-lifecycle-$$"
created=0
started=0
cleanup() {
    if [[ $started == 1 ]]; then nsenter --net="/run/netns/$ns" ./trafficcop stop >/dev/null 2>&1 || true; fi
    if [[ $created == 1 ]]; then ip netns del "$ns" || true; fi
    rm -f "$tmp/pass.c" "$tmp/pass.o" "$tmp/limits.rules"
    rmdir "$tmp"
}
trap cleanup EXIT
ip netns add "$ns"
created=1
ip -n "$ns" link add eth0 type veth peer name players
for name in lo eth0 players; do ip -n "$ns" link set "$name" up; done
run() { nsenter --net="/run/netns/$ns" "$@"; }
run python3 - <<'PY'
import json,socket,subprocess
listener=socket.socket();listener.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);listener.bind(('127.0.0.1',8088));listener.listen()
r=subprocess.run(['./trafficcop','start','eth0','tests/fixtures/bootstrap.rules'],capture_output=True,text=True,timeout=5)
assert r.returncode==1 and not r.stdout and len(r.stderr.splitlines())==1,r
assert not __import__('os').path.exists('/run/trafficcop/control.sock')
links=json.loads(subprocess.check_output(['ip','-j','link','show','eth0']))
assert not links[0].get('xdp',{}).get('attached'),links
listener.close()
print('PASS: occupied HTTP port rolls back socket/lock and leaves interface untouched')
PY
cat > "$tmp/pass.c" <<'C'
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
SEC("xdp") int owned_peer(struct xdp_md *ctx) { return XDP_PASS; }
char LICENSE[] SEC("license") = "GPL";
C
clang -O2 -g -target bpfel -I"/usr/include/$(gcc -dumpmachine)" -c "$tmp/pass.c" -o "$tmp/pass.o"
ip -n "$ns" link set dev eth0 xdpdrv obj "$tmp/pass.o" sec xdp
run python3 - <<'PY'
import json,subprocess
def attachment():
    return json.loads(subprocess.check_output(['ip','-j','link','show','eth0']))[0]['xdp']
before=attachment()
r=subprocess.run(['./trafficcop','start','eth0','tests/fixtures/bootstrap.rules'],capture_output=True,text=True,timeout=5)
assert r.returncode==1 and not r.stdout and len(r.stderr.splitlines())==1,r
assert attachment()==before,(before,attachment())
assert not __import__('os').path.exists('/run/trafficcop/control.sock')
print('PASS: refuses existing native attachment; program identity preserved and startup resources rolled back')
PY
# This is our own test program on our own disposable interface.
ip -n "$ns" link set dev eth0 xdp off
run ./trafficcop start eth0 tests/fixtures/demo.rules
started=1
run python3 - <<'PY'
import json,os,signal,socket,subprocess,time
control=socket.socket(socket.AF_UNIX);control.connect('/run/trafficcop/control.sock')
# Linux peer credentials identify the exact daemon; no broad pkill patterns.
import struct
pid,uid,gid=struct.unpack('3i',control.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
control.close();os.kill(pid,signal.SIGTERM)
deadline=time.monotonic()+4
while time.monotonic()<deadline:
    links=json.loads(subprocess.check_output(['ip','-j','link','show','eth0']))
    if not os.path.exists('/run/trafficcop/control.sock') and not links[0].get('xdp',{}).get('attached'):break
    time.sleep(.02)
else:raise AssertionError('signal cleanup did not remove socket')
links=json.loads(subprocess.check_output(['ip','-j','link','show','eth0']))
assert not links[0].get('xdp',{}).get('attached'),links
s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind(('127.0.0.1',8088));s.close()
print('PASS: SIGTERM releases XDP, socket, HTTP and event workers')
PY
started=0
# Maximum rule-count start must report readiness before five seconds.
python3 - "$tmp/limits.rules" <<'PY'
from pathlib import Path
import sys
Path(sys.argv[1]).write_text('default pass\n'+''.join(f'limit 1000000/s burst 1000000 proto udp dport {10000+i}\n' for i in range(64)))
PY
SECONDS=0
run ./trafficcop start eth0 "$tmp/limits.rules"
started=1
(( SECONDS < 5 ))
run ./trafficcop stop
started=0
echo 'Lifecycle checks passed, including 64-limit-rule readiness and clean stop'
