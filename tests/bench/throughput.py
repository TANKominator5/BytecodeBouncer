"""Actual private-veth/XDP ingress throughput; never label these NIC line rate."""
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import time
import urllib.request

root = Path(sys.argv[1])
seconds = int(sys.argv[2])
assert 1 <= seconds <= 600

def cli(*args):
    start = time.monotonic()
    result = subprocess.run(['./trafficcop', *map(str, args)], capture_output=True, text=True, timeout=1)
    assert result.returncode == 0 and not result.stderr, (args, result.stderr)
    assert time.monotonic() - start < 1
    return json.loads(result.stdout) if result.stdout else None

print(json.dumps(dict(benchmark='private-veth-XDP-ingress', kernel=platform.release(), machine=platform.machine(),
                      allowed_cpus=sorted(os.sched_getaffinity(0)), nic_line_rate=False)), flush=True)
worst = 'default drop\n' + ''.join(
    f'limit 1000000/s burst 1000000 family ipv6 proto udp src fd00::/8 dst fd00::/64 sport 40000 dport {10000+i} vlan none\n'
    for i in range(63)) + 'pass family ipv6 proto udp src fd00::/8 dst fd00::/64 sport 40000 dport 60000-60003 vlan none\n'
for name, rules, extensions, verdict in [
    ('default-pass', 'default pass\n', 0, 'passed'),
    ('logged-off-drop', 'drop\n', 0, 'dropped'),
    ('64-rule-last-match', worst, 0, 'passed'),
    ('64-rule-eight-extensions', worst, 8, 'passed'),
]:
    policy = root / 'policy.rules'
    policy.write_text(rules)
    cli('reload', policy)
    before = cli('stats')
    result = subprocess.run([str(root/'flood'), str(seconds), str(extensions)], capture_output=True, text=True, timeout=seconds+5)
    assert result.returncode == 0, result.stderr
    measurement = json.loads(result.stdout)
    deadline = time.monotonic() + 2
    while True:
        after = cli('stats')
        delta = {k: after[k] - before[k] for k in ('passed', 'dropped', 'bounced', 'honeypotted')}
        if sum(delta.values()) >= measurement['frames'] or time.monotonic() >= deadline:
            break
        time.sleep(.01)
    assert delta[verdict] == measurement['frames'] and sum(delta.values()) == measurement['frames'], (measurement, delta)
    assert after['other'] == before['other'] and after['malformed'] == before['malformed']
    with urllib.request.urlopen('http://127.0.0.1:8088/health.json',timeout=1) as response:
        health=json.load(response)
    assert not any(value for key,value in health.items() if key!='events_read'),health
    if name.startswith('64-rule'):
        assert after['rules'][-1]['hits'] == measurement['frames']
        assert all(r['hits'] == 0 for r in after['rules'][:-1])
    measurement.update(scenario=name, verdict=verdict, exact_kernel_frames=delta[verdict])
    print(json.dumps(measurement), flush=True)
