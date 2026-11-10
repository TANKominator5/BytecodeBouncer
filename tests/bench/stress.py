"""Measured daemon-level logging and reload checks. No claimed NIC benchmark."""
import concurrent.futures
import fcntl
import ipaddress
import json
from pathlib import Path
import socket
import struct
import subprocess
import sys
import threading
import time
import urllib.request

root = Path(sys.argv[1])


def cli(*args, ok=True):
    start = time.monotonic()
    r = subprocess.run(['./trafficcop', *map(str, args)], capture_output=True, text=True, timeout=1)
    elapsed = time.monotonic() - start
    assert elapsed < 1, (args, elapsed)
    if ok:
        assert r.returncode == 0, (args, elapsed, r.stderr)
        return json.loads(r.stdout) if r.stdout else None
    assert r.returncode == 1 and len(r.stderr.splitlines()) == 1 and not r.stdout, r


def web(path):
    with urllib.request.urlopen('http://127.0.0.1:8088/' + path, timeout=1) as r:
        return json.load(r)


def hardware_address(name):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as control:
        return fcntl.ioctl(control.fileno(), 0x8927, struct.pack('256s', name.encode()))[18:24]


ethernet = hardware_address('eth0') + hardware_address('players') + b'\x86\xdd'
header = bytearray(40)
header[0] = 0x60
header[6] = 17
header[8:24] = ipaddress.ip_address('2001:db8::7').packed
header[24:40] = ipaddress.ip_address('2001:db8::1').packed


def frame(seq, port=None, worker=None):
    h = bytearray(header)
    if worker is not None:
        h[8:24] = ipaddress.ip_address(f'2001:db8:{worker}::7').packed
    sport = seq >> 16
    dport = 5000 + seq % 60000 if port is None else port
    return ethernet + h + struct.pack('!HHHH', sport, dport, 0, 0)


def sender():
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
    s.bind(('players', 0))
    return s


def send(s, f):
    for _ in range(100):
        try:
            s.send(f)
            return
        except OSError as err:
            if err.errno not in (11, 105):
                raise
            time.sleep(.001)
    raise AssertionError('persistent generator backpressure')


# Slow HTTP clients and regular snapshots must not be dependencies of the drain.
slow = []
for _ in range(4):
    s = socket.create_connection(('127.0.0.1', 8088))
    s.sendall(b'GET /log.json HTTP/1.1\r\nHost: localhost\r\n')
    slow.append(s)
stop_http = threading.Event()
http_errors = []


def poll_http():
    while not stop_http.is_set():
        try:
            web('stats.json')
            web('log.json')
        except Exception as err:
            http_errors.append(repr(err))
        stop_http.wait(.08)


poller = threading.Thread(target=poll_http, daemon=True)
poller.start()
sock = sender()
before = cli('stats')
read_before = web('health.json')['events_read']
packets = 90000
rate = 25000
batch = 250
start = time.perf_counter()
for seq in range(packets):
    send(sock, frame(seq))
    if (seq + 1) % batch == 0:
        remaining = start + (seq + 1) / rate - time.perf_counter()
        if remaining > 0:
            time.sleep(remaining)
elapsed = time.perf_counter() - start
stop_http.set()
poller.join(timeout=2)
for s in slow:
    s.close()
assert not poller.is_alive() and not http_errors, http_errors
assert packets / elapsed >= 20000, ('generator did not meet 20k/s', packets / elapsed)

# Barrier includes all pending events and proves exact newest-1000 history.
log = cli('log')
assert len(log) == 1000
for index, event in enumerate(log):
    seq = packets - 1000 + index
    assert event == dict(line=1, verdict='DROP', src='2001:db8::7', dst='2001:db8::1', proto='udp', sport=seq >> 16, dport=5000 + seq % 60000), (seq, event)
health = web('health.json')
assert health['events_read'] - read_before == packets, health
assert not any(v for k, v in health.items() if k != 'events_read'), health
after = cli('stats')
assert after['dropped'] - before['dropped'] == packets
assert after['rules'][0]['hits'] == packets and after['rules'][0]['dropped'] == packets
print(f'PASS: {packets} logged IPv6 decisions in {elapsed:.3f}s ({packets / elapsed:.0f}/s), exact events_read and newest 1000; zero ring/stream losses with slow HTTP clients')

# Four CPU-affined worker threads, each a distinct full IPv6 source. Four
# ports each must pass both adversarial files; marker policy differs per reload.
cpus = sorted(__import__('os').sched_getaffinity(0))[:4]
assert len(cpus) == 4, cpus
old = root / 'policy.rules'
new = root / 'other.rules'
invalid = root / 'invalid.rules'
old.write_text('default drop\nset old 2001:db8:ffff::/48\npass proto udp dport 1234\ndrop proto udp dport 4321 log\n')
new.write_text('default drop\nset new 2001:db8:eeee::/48\npass proto udp dport 4321 log\npass proto udp dport 1234\n')
invalid.write_text('drop proto invalid\n')
cli('reload', old)
with socket.socket(socket.AF_UNIX) as control:
    control.connect('/run/trafficcop/control.sock')
    daemon_pid = struct.unpack('3i', control.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))[0]
fd_baseline = len(list(Path(f'/proc/{daemon_pid}/fd').iterdir()))
workers_stop = threading.Event()


def flood(worker, cpu):
    import os
    native = threading.get_native_id()
    previous = os.sched_getaffinity(native)
    os.sched_setaffinity(native, {cpu})
    local = sender()
    count = 0
    try:
        while not workers_stop.is_set():
            for _ in range(32):
                send(local, frame(count, 1234, worker))
                count += 1
            time.sleep(.002)
        return count
    finally:
        local.close()
        os.sched_setaffinity(native, previous)


before = cli('stats')
baseline_sources = {v['src']: v['packets'] for v in before['top_sources']}
start = time.monotonic()
durations = []
expected_marker_drops = 0
with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
    futures = [pool.submit(flood, i + 1, cpu) for i, cpu in enumerate(cpus)]
    try:
        for iteration in range(12):
            target = new if iteration % 2 == 0 else old
            t = time.monotonic()
            cli('reload', target)
            durations.append(time.monotonic() - t)
            if iteration % 3 == 0:
                cli('reload', invalid, ok=False)
            send(sock, frame(iteration, 4321))
            event = cli('log')[-1]
            verdict = 'PASS' if target == new else 'DROP'
            expected_marker_drops += verdict == 'DROP'
            assert event['verdict'] == verdict and event['dport'] == 4321, (iteration, event)
            s = cli('stats')
            assert s['rules_version'] == 3 + iteration, s['rules_version']
            assert s['sets'][0]['name'] == ('new' if target == new else 'old')
            assert len(list(Path(f'/proc/{daemon_pid}/fd').iterdir())) <= fd_baseline + 2, 'retired generation descriptors retained'
    finally:
        workers_stop.set()
    sent = sum(f.result() for f in futures)
time.sleep(.05)
after = cli('stats')
assert after['dropped'] - before['dropped'] == expected_marker_drops, (before, after)
assert after['passed'] - before['passed'] == sent + 12 - expected_marker_drops, (sent, before, after)
health = web('health.json')
assert not any(v for k, v in health.items() if k != 'events_read'), health
assert web('stats.json') == after
print(f'PASS: 12 adversarial CLI reloads with {sent} stable-pass frames across CPUs {cpus}; exact total accounting, no unexpected drop, new policy/version/sets after return; reload max={max(durations):.3f}s')

# Measure largest rule count and isolated bucket allocation on real CLI reload.
old.write_text('default pass\n' + ''.join(f'limit 1000000/s burst 1000000 proto udp dport {10000 + i}\n' for i in range(64)))
start = time.monotonic()
cli('reload', old)
elapsed = time.monotonic() - start
assert len(cli('stats')['rules']) == 64
print(f'PASS: 64-limit-rule production CLI reload completed in {elapsed:.3f}s')

# Maximum declared set population is also part of the one-second reload path.
old.write_text('default pass\nset all ' + ' '.join(f'10.0.{i >> 8}.{i & 255}' for i in range(10000)) + '\ndrop src @all\n')
start = time.monotonic()
cli('reload', old)
elapsed = time.monotonic() - start
assert cli('stats')['sets'] == [dict(name='all', prefixes=10000)]
cli('set', 'add', 'all', '192.0.2.1', ok=False)
cli('set', 'del', 'all', '10.0.0.0')
cli('set', 'add', 'all', '192.0.2.1')
assert cli('stats')['sets'] == [dict(name='all', prefixes=10000)]
print(f'PASS: 10000-prefix production CLI reload completed in {elapsed:.3f}s; live capacity rejection/deletion/addition exact')
sock.close()
