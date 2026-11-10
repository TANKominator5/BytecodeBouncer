# Person A validation — 10 November 2026

Environment: Ubuntu 24.04.3 under WSL2, x86-64, Linux
`6.18.54.1-microsoft-standard-WSL2`, Clang 18.1.3, Go 1.22.2. This is **not**
the judges' Linux 6.8 kernel. Dependencies were installed with the packages in
`build.sh`. Windows checkout CRLFs in existing shell scripts were normalized
locally to run them; no semantic script changes were needed.

## Checks actually run

- `bash ./build.sh`: BPF and embedded Go binary build successfully.
- `make test`: Go race tests, ELF/BTF ABI tests and `go vet` pass. The target also
  runs native parser fixtures with AddressSanitizer/UndefinedBehaviorSanitizer.
- Root `bash tests/integration/bootstrap.sh`: native XDP attachment in its own
  namespace, counters/HTTP, validation/attachment failure rollback, unsupported
  reload preservation, stop/detach/restart and timing assertions pass.
- Root `bash bpf/test.sh --kernel`: real XDP `BPF_PROG_TEST_RUN` fixtures pass:
  - Ethernet, single/short/double VLAN, non-IP, IPv4 version/IHL/options and
    first/non-first fragments, required transport truncation, unknown protocols;
  - IPv6 base/version, all supported extension types, eight/nine-header boundary,
    variable extension lengths and first/non-first fragments. Following the PDF's
    header-walk contract, non-first fragments skip transport validation but still
    receive extension-header bounds and eight-header-limit checks;
  - first match, full-address/prefix family separation, partial-byte prefixes,
    /0, /32, /65, /127, /128 edges, sets/overlap/live map edits, port ranges,
    ICMP type, VLAN and fragment/default semantics;
  - 64-rule traversal with source/destination prefix and set checks, ports, VLAN
    and an eight-extension IPv6 frame;
  - per-source/per-rule bursts/refill, jail expiration/locked release and exact
    distinct-port scan thresholds/windows;
  - 160,000 frames with exact shared-source and rule/global counts on four pinned
    CPUs (0–3), one shared source rate allowance rather than four allowances,
    and every concurrent logged event decoded;
  - 100,000 frames for each of PASS/DROP/BOUNCE/HONEYPOT plus 1,000 other and
    1,000 malformed frames: exact counters and source totals;
  - all 64 independent 65,536-entry limit maps loaded; two populated with exactly
    65,536 distinct source states each; rule 0 insertion does not evict rule 1;
  - 20,000 logged IPv6 drops produced and every event read/decoded, original line,
    generation, full source, protocol, ports and verdict preserved. The final
    parallel regression produced the burst in 30.91 ms (~647,000 decisions/s), with
    `health.event_lost=0`. This is a **kernel ring burst**, not an end-to-end
    continuous 20k/s daemon/history guarantee or a NIC throughput benchmark.
- Root `bash bpf/netns-test.sh`: real native XDP on disposable namespace veths:
  byte-exact IPv4/IPv6 bounce (only MACs swapped), unchanged honeypot delivery,
  and ordinary PASS delivery. Five link program updates during concurrent
  stable-pass traffic preserve global maps/jail and reset rule counters. The
  final run saw 38,656 stable-pass frames and no unexpected policy drops;
  logged marker frames after each update used the new generation/verdict.
  The generator uses bounded retries for send-side ENOBUFS/EAGAIN and reports
  their count separately (zero in that final run).

Native parser tests cover exact sub-14-byte input, which kernel test-run rejects
at its syscall boundary. All BPF fixtures either use test-run without attachment
or attach only inside a newly created private network namespace. No real host
interface or existing attachment was replaced.

## Verifier and memory evidence

The program is checked with a writable config map, not specialized to a small
test rule count. Successful verifier output (including the 64-rule fixture):

```text
processed 136594 insns (limit 1000000) max_states_per_insn 24 total_states 5180 peak_states 1095 mark_read 0
```

Observed verification time varies with load (~137–886 ms with stats-only logging
in the final parallel regression). Branch-level logs are retried on a failed load
so the actual rejection/register state is available without slowing every success.

Kernel `/proc/self/fdinfo/<fd>` reports a total **402,722,816 bytes** for the 64
allocated limit maps, including the template reused for the first rule. This
excludes other maps/programs and is not a process-RSS or total-system measurement.
The capacity fixture with bulk outer-map publication took 2.29 seconds during
the parallel regression, including population/inspection of two full maps. It
does not establish CLI startup/reload timing under all target workloads.
Source/jail/scan hash maps allocate values on demand. Their full-capacity memory
and resource-exhaustion recovery have not been measured.

## Failures found and fixed

- Large scan bitmap clearing initially became an unsupported BPF `memset`;
  bounded volatile 64-bit stores avoid that compiler transformation.
- An inner map type without a concrete map instance emitted only forward BTF;
  `bucket_template` retains the full layout and can serve the first limit rule.
- Kernel rejected a spinlock in an LRU value (`operation not supported`). Linux
  6.8 permits spinlocks in HASH/ARRAY, not LRU_HASH. Buckets now use a single
  atomic virtual finish time; jail and scan values retain supported HASH locks.
- Verifier rejected an unbounded rule pointer after clang checked a different
  zero-extended register. Explicitly bounding the actual indexing register fixes
  the rejection without skipping any rule.
- XDP test-run does not support `BPF_F_TEST_RUN_ON_CPU`; four locked OS threads
  with restored CPU affinity provide actual four-CPU execution instead.
- Concurrent regression exposed send-side ENOBUFS in the test generator. Bounded
  retries and a paced flood distinguish unsent/backpressured frames from XDP
  verdicts; persistent send failure still fails the test, rather than being hidden.

## Still required before Issue #1 acceptance / final submission

- B/C integration and review of ABI v4, production map publication, strict config
  validation, CLI operations, continuous event draining/history and snapshots.
- Ubuntu 24.04 **Linux 6.8** verification/runtime, sustained flood speed, a
  long-running repeated reload/reclamation test on all CPUs and worst-case
  one-second CLI reload timing (including 64 changed limit rules).
- Continuous daemon 20k/s logging with exactly the newest 1,000 events, including
  reloads; source ranking/JSON formatting is still C's work.
- Explicit handling/reporting of finite map capacity and event-ring saturation.
  Expired jail/scan entries now have on-pressure reclamation; cumulative source
  identities are not garbage-collected online. The bootstrap
  stats schema does not expose `health` yet; B/C must not hide these diagnostics.
- Hidden-harness testing, full-capacity source/jail/scan memory measurements and
  complete dashboard/README screenshot remain unverified.

No production CLI filtering/reload or complete-firewall acceptance is claimed.

## PR review correction — expired-state saturation

On the ARM64 Linux 7.0 host, real BPF test-run regression checks passed with
four-entry jail/scan maps and more than twelve historical sources. Expired entries
were reclaimed, new scan sources still reached jail thresholds, and active state
was preserved. A full active scan map dropped the new source without miscounting
it as jailed. ABI v4 adds retirement markers and a maintenance map that must be
shared with persistent jail state on reload. Native parser tests use the system
Clang by default (override CLANG explicitly), avoiding an unrelated Android NDK
clang earlier in PATH. CI now runs the opt-in kernel suite as root rather than
silently skipping its policy tests. Linux 6.8 runtime acceptance remains open.

Terra review follow-up: deterministic kernel regressions hold the jail collector
flag during a threshold crossing, verify repeated ports remain blocked, then
release the flag and verify jail installation recovers. Atomic-unjail tests
verify retired records cannot be revived, absent/active results are correct and
later kernel jail decisions still take effect. These tests pass on the ARM64
Linux 7.0 host; they are not a Linux 6.8 concurrency-stress claim.
