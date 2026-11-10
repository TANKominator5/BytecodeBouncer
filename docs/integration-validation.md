# Issues B/C integration evidence — 10 November 2026

## CI reload regression — 11 November 2026

Both attempts of [run 42865136788](https://github.com/TANKominator5/BytecodeBouncer/actions/runs/42865136788)
failed in `firewall.py` on the first successful reload: the CLI exceeded its
970 ms IPC deadline. The same fixture passed on WSL, so rerunning alone was not
a fix. The command deadline and sub-one-second bench assertions are unchanged.

The production loader now rewrites two frozen ELF constants with the union of
actions/matches in the validated candidate. Variable rule indices previously
hid individual config values from the verifier, leaving unused branches to be
analyzed. Masks only prune absent features; XDP still evaluates every configured
condition and makes every verdict. The generic kernel fixtures leave all features
enabled. Kernel ABI v5, rule capacity, map capacities and reload persistence are
unchanged. These are coordinated A/B loader/BPF changes, not a pipeline bypass.

A standalone QEMU/TCG boot of Ubuntu `6.8.0-149-generic` reproduced the excessive
verification work: 212,296 instructions for the default-drop/one-pass-rule
candidate before specialization, 61,867 after. Timing under CPU emulation is
**not** a native deadline benchmark. The new `TestKernelProductionReloadPreparation`
loads the two integration reload policies, exercises their verdicts/scan threshold
and reports preparation/close time and verified instruction counts.

This also revealed a Linux 6.8 scan-policy rejection (`tail_call abusing map_ptr`):
the address-taken reclamation selector was reloaded after a map helper, keeping
both jail/scan branches alive and merging their iterator call sites. A separate
lookup key preserves the constant selector. The same loader regression then
passed on the emulated Linux 6.8 kernel. This narrow loader/test-run validation
does not replace full Linux 6.8 namespace/wire/performance acceptance.

Additional production tests exercise specialized IPv4/IPv6 prefix, source/dest
set, source/destination port, ICMP and VLAN matches with matching/nonmatching
frames. Local build, race/vet, full kernel suite and namespace integration pass;
the hour-old cancellation subfixture still skips on short-uptime WSL.
The separate daemon stress rerun passed at 24,999 logged decisions/s, max
adversarial reload 0.147 s, 64-limit reload 0.270 s and 10,000-prefix reload
0.134 s. An earlier run in this session exceeded one second at the 64-limit
allocation step; worst-case allocation latency therefore remains open, not fixed
by this verifier optimization.

Environment: Ubuntu 24.04.3 in WSL2, x86-64 Linux
`6.18.54.1-microsoft-standard-WSL2`, Go 1.22.2, Clang 18.1.3. Linux 6.8 target
runtime, fresh-machine build and a final flood speed benchmark remain unverified.

## Branches and coordination

- `feat/control-plane`: local foundation commit `649407e` (Refs #2): strict grammar,
  policy construction/publication, live sets/unjail and concrete map/event APIs.
- `feat/observability-bench`: starts from current main and integrates that B commit
  as a dependency, then adds the complete telemetry/HTTP/dashboard, daemon command
  wiring and public-CLI namespace bench (Refs #2/#3).
- C/B integration changes include daemon wiring, private bucket allocation workers,
  parser long-line handling, the shared Go StateReader/Flush contract, build/test
  targets, CI steps and an LF shell-checkout rule. Kernel ABI v5 is unchanged.
  No separate Go/BPF JSON schemas, frontend services or userspace packet verdicts.

This work is published for review in PR #6.
Shared API/build/pipeline changes need normal teammate review before merge.

## Checks exercised

| Command | Coverage |
| --- | --- |
| `bash ./build.sh` | native BPF object and single embedded Go executable |
| `make test` | parser/CLI tests, ELF/BTF layouts, ASan/UBSan native parsing, Go race tests/vet |
| root `bash tests/integration/bootstrap.sh` | startup/stop timings, singleton, rollback, HTTP, native attachment, failed/successful reload, restart |
| root `bash tests/integration/firewall.sh` | complete running CLI/HTTP behavior on disposable veths; details below |
| root `bash tests/integration/lifecycle.sh` | occupied HTTP port, existing XDP identity preservation, SIGTERM and 64-limit-rule readiness |
| root `bash tests/integration/demo.sh` | owned persistent demo, safe duplicate refusal/stop, localhost proxy including all CSS/JS/JSON assets |
| root `bash tests/integration/stress.sh` | consequential sustained logging, adversarial reload traffic and 64-limit-rule reload; separate from fast checks |
| root `TC_BPF_TEST=1 go test -count=1 -v ./internal/dataplane -run TestKernelProduction` | production map loader, live control, flush/Close semantics and exact 100k-source batch snapshot |

The public firewall test checks original line numbers, first-match/drop rules,
MAC-only bounce and unchanged honeypot delivery for IPv4/IPv6 through **production
configuration**, source/rule-independent limits, VLAN+IPv4 options, malformed/
other/fragment accounting, canonical IPv6/nullable ports, source ranking, normalized
and idempotent set edits without modifying the file, jail/list/release/expiry,
fixed-window scan thresholds, exact newest-1,000 logs, successful/invalid reloads,
set replacement, zero new rule counters, persistent totals/history and empty
history/version 1 after restart. Stats JSON fields and CLI/HTTP equivalence are
checked on quiescent traffic. All commands use sub-one-second assertions except
the specified five-second start/stop paths.

IPv4-mapped IPv6 remains a separate full-family identity and prints hexadecimal
IPv6, not a collapsed IPv4 address. The limit/event fixtures exercise both.

HTTP tests verify JSON endpoints, error masking, no-store responses, method
restrictions, CSP/no-sniff headers and embedded assets. Snapshot tests cover file
rule order, alphabetic sets, exact numeric IPv4-before-IPv6 tie ordering, ceil
jail seconds, non-nil empty arrays, event formatting/history and detached nullable
ports. Concurrent snapshots/log calls run under the race detector.

The production batch snapshot fixture populated 100,000 source entries and
returned all counts exactly in **125.90 ms** during one concurrent test run.
This is not a million-source worst-case latency guarantee.

The final full kernel suite and private wire suite also pass. The hour-old jail
cancellation subfixture skips on this WSL instance because its monotonic uptime
is under an hour; no claim is made that the skipped subfixture was exercised.

## Sustained daemon event test

`tests/bench/stress.py` sends 90,000 unique-sequence IPv6 UDP logged drops, paced
at 25,000/s for 3.6 seconds. Sequence is encoded in source/destination ports. A
separate HTTP thread reads stats/log while four clients deliberately leave HTTP
request headers unfinished. The event drain does not depend on those clients.

Recorded passing run:

```text
90000 logged IPv6 decisions in 3.601s (24997/s)
events_read delta = 90000
rule hits / dropped delta = 90000
newest 1000 events match every field/sequence exactly
event_lost = 0; all allocation/stream diagnostics clear
```

This measures the actual running daemon, ring consumer and history, not merely
kernel ring capacity. `/health.json` exposes events_read and failure diagnostics
without adding fields to required public stats. Packet-generator backpressure is
retried with a bound; persistent generator failure fails the test.

## Reload timing / lifetime

Four CPU-affined worker threads send distinct full IPv6 sources through a rule
which must pass both adversarial policy files. Twelve sequential CLI reloads move
that rule and change a separate logged marker verdict/set. After every command,
markers must use the new policy; invalid reloads preserve it. Global pass/drop
totals must exactly equal sent frames/markers. Repeated replacement must not grow
the daemon descriptor count; old collection descriptors close after publication,
with kernel program/map references and RCU protecting in-flight readers.

Recorded passing run: **35,424 stable-pass frames** across CPUs 0–3, no unexpected
policy drops, all counters exact, maximum reload **0.321 s**. A production reload
containing **64 independent limit maps** completed in **0.769 s**.

An earlier 64-limit test hit the original 900 ms IPC read deadline. Independent
private maps were allocated serially. Preparation now uses up to four allocation
workers and bulk outer-map publication; mutations/publication stay serialized.
The IPC read budget is 970 ms. This is measured local success, not a worst-case
deadline proof for Linux 6.8 under every CPU/memory load. Each limit map still
has 65,536 sources; kernel memory is not reduced by sharing source capacity.

A later final rerun measured 24,999 logged decisions/s, 44,736 stable-pass frames,
maximum adversarial reload 0.255 s and 64-limit-rule reload 0.329 s. A maximum
10,000-prefix policy reload took 0.172 s, with exact live capacity rejection and
delete/add behavior. Earlier measurements above show run-to-run load variance.

## Actual dashboard capture

[`dashboard.png`](dashboard.png) was captured with installed Windows Chrome
headless against the real localhost demo proxy. The namespace daemon loaded
`tests/fixtures/demo.rules`; `tests/bench/demo_traffic.py` supplied synthetic frames.
Counters, jail, rules and events in the image are actual XDP results. Traffic
was idle at capture, hence zero pps. No values were inserted into the HTML.
Browser requests fetched every live endpoint repeatedly without manual refresh.
The demo/namespace/proxy were stopped after capture.

## Safety and remaining limitations

- Tests use unique private namespaces, refuse an existing singleton and clean
  only owned interfaces/processes/files. The existing-attachment check installs
  a test PASS program only on its private interface, verifies failed startup
  preserves its identity, then removes that same test program.
- Source state remains finite (1,048,576 identities); active jail/scan capacity,
  allocation pressure, event saturation, exact-LRU semantics and resource costs
  retain the kernel handoff's documented limits. Dashboard diagnostics surface
  failures, rather than silently claiming compliant accounting.
- Stats during traffic are not a globally simultaneous cross-CPU/map snapshot.
  A generation is pinned for metadata/map access; quiescent totals are exact.
- Need target Ubuntu/Linux 6.8 build/runtime, repeated long-run reclaim/memory
  stress, all worst-capacity CLI timing and final flood benchmark before claiming
  full issue acceptance. CI configuration is updated, not presumed to have run.

## PR review regressions

Runtime policy loading inspects an O_PATH descriptor before opening for reads,
then reopens the same inode through procfs. Only regular files and `/dev/null`
are accepted, with a 16 MiB total-input limit. Unit tests cover devices, FIFOs,
exact size boundaries and accepted logging policies. Namespace smoke tests reject
FIFO/device reloads, confirm generation preservation and stats responsiveness,
then stop normally. This is a cross-owner config/bench fix with no ABI change.

Log request timeouts no longer become terminal stream errors. An outstanding
flush barrier survives its request timeout; the next request must retire that
barrier before issuing another. A delayed-acknowledgment unit test verifies
recovery and that old acknowledgments cannot satisfy a new snapshot early.
Terminal read/flush errors remain visible in diagnostics.

The initially intermittent kernel capacity failure was reproduced with a captured
log: rule 1 retained only 65,408 of 65,536 inserted sources. Kernel global LRU maps
reserve up to 128 free nodes per possible CPU; CPU migration can therefore cause
early eviction when max_entries is exactly the required usable capacity. The
loader now budgets 65,536 + 128 * possible_CPUs in both inner-map specifications.
The ELF baseline and binary layouts remain unchanged; allocated capacity/memory
increase by that reserve for each limit map. See Linux kernel map_hash LRU
internals (https://docs.kernel.org/bpf/map_hash.html#internals). A deterministic
cross-CPU population test checks all 65,536 keys in two production rule maps;
the existing 64-map capacity test uses the same migration pattern. Both passed
three consecutive focused runs after the fix. A scratch raw-map control without
the reserve lost exactly 128 keys on all three runs using the same off-batch CPU
switch; it was removed after diagnosis. This is a cross-owner dataplane
and kernel-fixture correction, not a relaxed retention assertion.

Jail and health endpoints use targeted map readers rather than repeating the
full source snapshot. The shared Go TelemetryReader composes StateReader with
ReadJail/ReadHealth and a concrete JailState; it does not change C ABI layouts.
Observe fakes and production callers share this boundary. Tests ensure targeted
endpoints never invoke ReadState and remain usable after the source descriptor
is closed, while normal map lifetime locking and post-close errors are preserved.
Unjail retries back off briefly on retirement contention instead of busy-spinning.
The Log pending-barrier and fresh-barrier waits share one 700 ms timer, so retries
remain bounded by a single budget; timer expiry does not poison future snapshots.

## Integration after merging PR #5

PR #6 was updated with main after PR #5 merged. Integrated telemetry supersedes
the counter adapter and pending-log rejection from the foundation: logged
policies remain supported and the event drain owns their lifecycle. The 1.5 s
IPC response allowance is retained while command acceptance remains measured
independently by existing one-second bench deadlines. Foundation metadata and
two-limit regression tests remain, adapted to the integrated snapshot API and
canonical mapped-IPv6 formatting. No C ABI changes in conflict resolution.
