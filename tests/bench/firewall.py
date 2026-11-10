"""CLI/HTTP integration fixtures, run only in firewall.sh's disposable netns.

No Scapy dependency; all lengths/checksums intentionally exercise XDP's contract.
"""
import collections
import fcntl
import ipaddress
import json
from pathlib import Path
import socket
import struct
import subprocess
import sys
import time
import urllib.request

root = Path(sys.argv[1])
rules = root / 'policy.rules'
replacement = root / 'reload.rules'


def cli(*args, ok=True):
    start = time.monotonic()
    r = subprocess.run(['./trafficcop', *map(str, args)], capture_output=True, text=True, timeout=1)
    elapsed = time.monotonic() - start
    assert elapsed < 1, (args, elapsed)
    if ok:
        assert r.returncode == 0 and not r.stderr, (args, r.returncode, r.stderr)
        return json.loads(r.stdout) if r.stdout else None
    assert r.returncode == 1 and not r.stdout and len(r.stderr.splitlines()) == 1, (args, r)
    return r.stderr


def web(path):
    with urllib.request.urlopen('http://127.0.0.1:8088/' + path, timeout=1) as r:
        return json.load(r)


def hardware_address(name):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as control:
        return fcntl.ioctl(control.fileno(), 0x8927, struct.pack('256s', name.encode()))[18:24]


mac = hardware_address('eth0')
source_mac = hardware_address('players')
sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
sock.bind(('players', 0))
trap = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
trap.bind(('trap', 0))


def frame(src, port=1234, proto=17, fragment=0, ihl=5, vlan=None, payload=None):
    ip = ipaddress.ip_address(src)
    if payload is None:
        payload = struct.pack('!HHHH', 40000, port, 0, 0)
    if ip.version == 4:
        header = bytearray(ihl * 4)
        header[0] = 0x40 | ihl
        header[9] = proto
        header[6:8] = struct.pack('!H', fragment)
        header[12:16] = ip.packed
        header[16:20] = ipaddress.ip_address('10.0.0.1').packed
        ether = 0x0800
    else:
        header = bytearray(40)
        header[0] = 0x60
        header[6] = proto
        header[8:24] = ip.packed
        header[24:40] = ipaddress.ip_address('2001:db8::1').packed
        ether = 0x86dd
    ethernet = mac + source_mac
    if vlan is None:
        ethernet += struct.pack('!H', ether)
    else:
        ethernet += struct.pack('!HHH', 0x8100, vlan, ether)
    return ethernet + header + payload


def send(f):
    for attempt in range(100):
        try:
            sock.send(f)
            return
        except OSError as err:
            if err.errno not in (11, 105):
                raise
            time.sleep(.001)
    raise AssertionError('generator remained backpressured')


expected = collections.Counter()
rule_expected = collections.defaultdict(collections.Counter)
sources = collections.Counter()
last = []
baseline = cli('stats')


def decide(src, port, verdict, line=None, **kwargs):
    f = frame(src, port, **kwargs)
    send(f)
    expected[verdict] += 1
    sources[src] += 1
    if line is not None:
        rule_expected[line]['hits'] += 1
        rule_expected[line][verdict] += 1
        proto = kwargs.get('proto', 17)
        has_ports = proto in (6, 17) and not kwargs.get('fragment', 0) & 0x1fff
        last.append(dict(line=line, verdict={'passed': 'PASS', 'dropped': 'DROP', 'bounced': 'BOUNCE', 'honeypotted': 'HONEYPOT'}[verdict],
                         src=src, dst='10.0.0.1' if ':' not in src else '2001:db8::1',
                         proto={17: 'udp', 6: 'tcp', 1: 'icmp', 58: 'icmp6'}.get(proto, str(proto)),
                         sport=40000 if has_ports else None, dport=port if has_ports else None))
    return f


def settled(total):
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline:
        s = cli('stats')
        count = sum(s[k] - baseline[k] for k in ('passed', 'dropped', 'bounced', 'honeypotted'))
        if count >= total:
            assert count == total, (count, total, s)
            return s
        time.sleep(.005)
    raise AssertionError(('packets did not settle', total, s))


def check_state():
    s = settled(sum(expected.values()))
    for key in ('passed', 'dropped', 'bounced', 'honeypotted'):
        assert s[key] - baseline[key] == expected[key], (key, s[key], expected)
    assert list(s) == ['passed', 'dropped', 'bounced', 'honeypotted', 'malformed', 'other', 'jailed', 'jailed_sources', 'rules_version', 'default_hits', 'rules', 'sets', 'top_sources']
    for r in s['rules']:
        want = rule_expected[r['line']]
        for key in ('hits', 'passed', 'dropped', 'bounced', 'honeypotted'):
            assert r[key] == want[key], (r, want)
    assert cli('log') == last[-1000:], 'event order/contents mismatch'
    assert web('stats.json') == s, 'CLI/HTTP snapshots differ on quiescent traffic'
    assert web('log.json') == cli('log')
    health = web('health.json')
    assert health['events_read'] == len(last), health
    assert not any(value for key, value in health.items() if key != 'events_read'), health
    return s


# All policy features through public CLI, without manipulating BPF maps.
for src in ('10.0.0.9', '2001:db8::9'):
    decide(src, 1234, 'dropped', 5)
for src in ('10.0.0.5', '2001:db8::5'):
    for port in (6666, 7777):
        sent = decide(src, port, 'bounced' if port == 6666 else 'honeypotted', 7 if port == 6666 else 8)
        want = sent[6:12] + sent[:6] + sent[12:] if port == 6666 else sent
        receiver = sock if port == 6666 else trap
        receiver.settimeout(.5)
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            try:
                got = receiver.recv(4096)
            except socket.timeout:
                continue
            if got == want:
                break
        else:
            raise AssertionError(('wire frame not received unchanged/MAC-only', src, port))
for src in ('10.0.0.2', '10.1.0.2', '2001:db8::2', '2001:db8:1::2', '192.0.2.9', '::ffff:c000:209'):
    for _ in range(3):
        decide(src, 9001, 'passed', 9)
    decide(src, 9001, 'dropped', 9)
decide('10.0.0.3', 6000, 'dropped', 10, ihl=15, vlan=100)
decide('10.0.0.3', 6099, 'dropped', 10, vlan=100)
decide('10.0.0.3', 6100, 'passed', vlan=100)
decide('10.0.0.3', 6000, 'passed')
decide('10.0.0.3', 0, 'dropped', 11, proto=1, payload=bytes([8]) + bytes(7))
decide('2001:db8::3', 0, 'dropped', 12, proto=58, payload=bytes([128]) + bytes(7))
decide('10.0.0.3', 0, 'dropped', fragment=1, payload=b'')
send(mac + source_mac + b'\x08\x06' + bytes(46))
expected['passed'] += 1
send(frame('10.0.0.4', payload=b''))
expected['dropped'] += 1

# Live prefix normalization, idempotence, missing errors, no file modification.
original = rules.read_bytes()
cli('set', 'del', 'blocked', '10.0.0.9')
decide('10.0.0.9', 1234, 'passed')
cli('set', 'add', 'blocked', '10.0.0.123/24')
cli('set', 'add', 'blocked', '10.0.0.0/24')
decide('10.0.0.255', 1234, 'dropped', 5)
cli('set', 'del', 'blocked', '10.0.0.222/24')
cli('set', 'del', 'blocked', '10.0.0.0/24', ok=False)
cli('set', 'add', 'missing', '::/0', ok=False)
assert rules.read_bytes() == original

for src in ('10.0.0.8', '2001:db8::8'):
    decide(src, 9000, 'dropped', 6)
    decide(src, 1234, 'dropped')
j = cli('jail')
assert [v['src'] for v in j] == ['10.0.0.8', '2001:db8::8'], j
assert all(v['seconds_left'] in (1, 2) for v in j)
assert web('jail.json') == j
cli('unjail', '2001:0db8::8')
cli('unjail', '2001:db8::8', ok=False)
decide('2001:db8::8', 1234, 'passed')

# More than 1,000 decisions verifies exact bounded history and oldest-first order.
for i in range(1205):
    decide('10.9.0.7', 5000 + i % 1000, 'dropped', 13)
s = check_state()
assert s['malformed'] - baseline['malformed'] == 1
assert s['other'] - baseline['other'] == 1
assert s['jailed'] - baseline['jailed'] == 2
top = sorted(sources.items(), key=lambda item: (-item[1], ipaddress.ip_address(item[0]).version, int(ipaddress.ip_address(item[0]))))[:5]
assert s['top_sources'] == [dict(src=src, packets=count) for src, count in top], s['top_sources']

# Bad reload leaves enforcement, version, counters and active sets untouched.
before = cli('stats')
assert 'line 1' in cli('reload', root / 'invalid.rules', ok=False)
assert cli('stats') == before
decide('2001:db8::9', 1, 'dropped', 5)
check_state()

# Successful reload preserves jail/global/log state, replaces sets and counters.
replacement.write_text('# generation two\ndefault drop\nset fresh\npass proto udp dport 1234 log\n')
oldlog = cli('log')
oldstats = cli('stats')
cli('reload', replacement)
s = cli('stats')
assert s['rules_version'] == 2 and s['rules'] == [dict(line=4, hits=0, passed=0, dropped=0, bounced=0, honeypotted=0)], s
assert s['sets'] == [dict(name='fresh', prefixes=0)]
for key in ('passed', 'dropped', 'bounced', 'honeypotted', 'malformed', 'other', 'jailed', 'default_hits', 'top_sources'):
    assert s[key] == oldstats[key], (key, s, oldstats)
assert cli('log') == oldlog
cli('set', 'add', 'blocked', '::/0', ok=False)
time.sleep(2.1)
assert cli('jail') == []
f = frame('2001:db8::9', 1234)
send(f)
time.sleep(.02)
log = cli('log')
assert len(log) == 1000 and log[-1]['line'] == 4 and log[-1]['verdict'] == 'PASS' and log[-1]['src'] == '2001:db8::9'
assert log[:-1] == oldlog[1:]

# Fixed-window scans: distinct ports, cross-protocol identity and threshold frame.
replacement.write_text('default pass\nportscan 3 ports in 1s jail 2\npass log\n')
cli('reload', replacement)
for src in ('10.88.0.1', '2001:db8:88::1'):
    for port in (10, 10, 11, 12, 10):
        send(frame(src, port))
time.sleep(.02)
s = cli('stats')
assert s['rules_version'] == 3 and s['rules'][0]['hits'] == 6 and s['jailed_sources'] == 2, s
assert [v['src'] for v in cli('jail')] == ['10.88.0.1', '2001:db8:88::1']
for src in ('10.88.0.1', '2001:db8:88::1'):
    cli('unjail', src)
send(frame('10.88.0.2', 1))
time.sleep(1.1)
send(frame('10.88.0.2', 2))
send(frame('10.88.0.2', 3))
time.sleep(.02)
assert cli('jail') == []
assert web('stats.json') == cli('stats')
health = web('health.json')
assert not any(value for key, value in health.items() if key != 'events_read'), health
sock.close()
trap.close()
print('PASS: exact policy counters, IPv4/IPv6 wire bounce/honeypot, full-address limits, sets, jail/release/expiry, scans, CLI/HTTP equivalence, last-1000 events and reload persistence')
