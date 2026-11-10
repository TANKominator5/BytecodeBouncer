# Issues B/C integration evidence — 10 November 2026

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

No pushes or PRs have been made for this work. Local commits were approved.
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
