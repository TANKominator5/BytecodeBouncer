# Follow-up acceptance evidence — 11 November 2026

Tracks the maintainer's remaining-work comments on issues #1, #2 and #3. Results
below are measured, not a claim that the open issues can all be closed.

## A: exact-accounting CI regression

Main run [42926807664](https://github.com/TANKominator5/BytecodeBouncer/actions/runs/42926807664)
reported 100,001 honeypot decisions for a requested 100,000-repetition test run.
`BPF_PROG_TEST_RUN` can return EINTR after executing part of a burst. cilium/ebpf
v0.17.3 retries the entire count and provides `RunOptions.Reset` specifically for
undoing those partial test side effects. The old fixture omitted that callback.

The accounting-only, unattached fixture now snapshots/restores per-CPU global and
rule counters plus its source count before replay. Production counters/verdicts
are unchanged and assertions still require exact totals. A directed SIGUSR1 test
forces an interrupted syscall and verifies exactly 1,000,000 rule/source decisions
after replay. Both accounting tests passed five consecutive runs; each signal
fixture actually observed a replay. No assertion tolerance or retry-until-green
test policy was added.

## A: full production map capacity and exhaustion recovery

```sh
sudo env TC_BPF_TEST=1 TC_BPF_CAPACITY=1 go test -count=1 -v \
  ./internal/dataplane -run TestKernelFullStateCapacity
```

This opt-in test refuses less than 1.5 GiB available host memory. It fills actual
production capacities in bounded batches, checks active-state preservation and
health diagnostics at exhaustion, creates one free/expired slot, then verifies
successful kernel insertion/reclamation and no further health failures. It uses
test-run only, never a host interface.

Measured on Ubuntu 24.04 / WSL x86-64 Linux 6.18.58.1:

| Map | Entries | Kernel fdinfo memlock bytes | Fill | Full-active packet | Recovery packet |
| --- | ---: | ---: | ---: | ---: | ---: |
| sources | 1,048,576 | 109,053,056 | 1.752 s | 0.234 ms | 0.014 ms |
| jail | 1,048,576 | 125,830,272 | 1.519 s | 678.700 ms | 99.401 ms |
| scans | 65,536 | 545,784,960 | 1.761 s | 18.631 ms | 9.297 ms |

`fdinfo` is the kernel's map memory accounting, not isolated resident memory.
The test also reports host MemAvailable deltas, explicitly labeled non-isolated;
allocator caches and unrelated host activity make them unsuitable for attributing
exact RSS to a map. In particular the full-active jail collector is expensive;
these results do not establish a wire-rate guarantee under exhausted state.

## B/C: full snapshots, maximum reloads and object reclamation

The A fix has a green [follow-up CI run](https://github.com/TANKominator5/BytecodeBouncer/actions/runs/43029915302).
The B follow-up includes that fix as an explicit dependency, plus cross-owner C
stats aggregation and shared Makefile/bench changes. No kernel ABI change.

`TestKernelFullSnapshotLatency` populates 1,048,576 sources **and** 1,048,576 active
jails with 64 rule records. The initial stats path exceeded one second. Independent
source/jail map reads now run concurrently while the parent holds the generation
read lock; error paths wait for both before releasing it. Larger batch reads and
geometric record-buffer growth reduce syscall/allocation overhead. Stats counts
active distinct jail identities without building/sorting a million formatted jail
rows; the jail-list command still uses the canonical formatter.

Two complete measured runs (three snapshots each) ranged **720.99–844.10 ms** and
**791.49–832.07 ms**, with exact top-five and jail counts. These are direct stats
snapshots, not a guarantee for serializing/writing a million-row `jail` CLI response.

```sh
sudo env TC_BPF_TEST=1 TC_BPF_CAPACITY=1 go test -count=1 -v \
  ./internal/dataplane -run TestKernelFullSnapshotLatency
sudo env TC_BPF_TEST=1 TC_BPF_ENDURANCE=1 go test -count=1 -v \
  ./internal/dataplane -run TestKernelRetiredGenerationObjects
make endurance  # five minutes, >=100 reload/live-set cycles, 10 changed 64-limit reloads
```

Thirty separately prepared policies changed all 64 rate/burst settings and used
IPv6 source/destination prefixes, ports, VLAN and an eight-extension test frame.
Maximum preparation was **457.24 ms**. After closing candidate collections, all
retired program/private-map IDs (including every inner limit map) were unreachable
within **25.55 ms** of the final check. This checks kernel object lifetime, not
only the number of process descriptors.

The extended namespace stress alternates adversarial policies under four-CPU
traffic, exercises effective live set add/delete on every generation, checks
fresh counters/new metadata/failed reloads, exact global totals, bounded daemon
descriptors and RSS, then changes all 64 limit rules repeatedly under traffic.
Stop must release the daemon's descriptors, XDP, socket and HTTP port. Fast default
smoke passed: 12 cycles, maximum reload **178 ms**, maximum-policy reload **347 ms**,
10,000-prefix reload **124 ms**, with all sent stable-pass frames accounted for.

The first five-minute run completed 1,099 adversarial reload/live-set cycles and
4,388,576 exact stable-pass frames, max reload 929 ms, RSS 45,036/45,776/45,320 KiB
(start/peak/end). Its subsequent maximum-limit phase exceeded one second, so the
whole suite was **not** accepted as passing. Candidate construction now overlaps
verification with independent private inner-map allocation rather than adding
their costs serially. Every worker is joined on success/failure before publication
or return; a forced-invalid-program test verifies no descriptor leaks and active
policy preservation while 63 allocation jobs are outstanding. A subsequent
ten-changed-64-limit test under four-CPU traffic passed, max **854 ms**. The command
assertions remain strictly below one second.

## Still requires external/native validation

- Native Ubuntu 24.04 / Linux 6.8 x86-64 with four CPUs. This workspace is WSL
  Linux 6.18; a CPU-emulated 6.8 loader test is not native target acceptance.
- Physical NIC/flood throughput on the target. Private-veth measurements must be
  labeled as such, not promoted to NIC line rate.
- A green follow-up branch does not change main until the maintainer reviews and
  merges it. No direct main push or automatic issue closure is appropriate.
- Resource exhaustion tests above concern map capacity, not arbitrary system-wide
  OOM. They deliberately do not exhaust the developer's host memory.
