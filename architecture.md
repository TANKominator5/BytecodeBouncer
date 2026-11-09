# Architecture

## Decision
C compiled to eBPF for the XDP dataplane, Go with cilium/ebpf for userspace,
and embedded HTML/CSS/JavaScript. One executable contains the BPF object and web
assets. libbpf headers are build dependencies; there is no userspace libbpf/CGO
runtime dependency. BPF stays in one compilation unit with focused headers.

The long-lived daemon owns the XDP link, maps, event consumer, localhost HTTP
server, and Unix control socket. Short-lived CLI processes send control requests.
Only the network namespace changes under the harness, so `/run/trafficcop` is a
host-wide singleton. The socket is mode 0600; an advisory lock serializes startup.
No maps need pinning while the daemon owns their descriptors. If future recovery
requires pins, use only an owned subtree and clean it on every failure/stop.

## Bootstrap implementation
- `start <ifname> <rulesfile>` accepts comments, blank lines, and at most one
  `default pass`; unsupported syntax is rejected with its original line number.
- A child daemon reports readiness only after HTTP/socket bind and native XDP
  attachment. An existing attachment is not force-replaced.
- XDP passes every packet and maintains per-CPU pass/other/default counters.
  VLAN/IP parsing is unfinished; these are bootstrap counters only.
- `stats`, `/stats.json`, dashboard polling, `stop`, signal cleanup and restart
  work. All other commands explicitly fail until implemented.
- The binary embeds the built ELF. No Go bindings generator is required yet;
  an ELF-layout test checks the shared counter ABI without root.

## Target pipeline (implementation contract)
1. Short Ethernet frames: PASS/other.
2. Parse one 802.1Q tag; short/double tags: PASS/other.
3. Non-IPv4/IPv6: PASS/other.
4. Validate IPv4/IHL/options or IPv6/max-eight extension chain.
5. Validate required transport header except on non-first fragments.
6. Drop jailed sources.
7. Update port-scan window and jail threshold-crossing sources.
8. First matching rule, then non-first-fragment policy, then default.

Malformed packets drop. Do not trust IP lengths/checksums; bound reads by
`data_end`. All address identities retain the entire IPv6 address. Actions and
logging use a common verdict-finalization path so each packet is counted once.

## Shared contracts
`include/contract.h` is authoritative for native-endian map fields and
network-order address bytes. Reserved bytes must be zero. Use fixed-width types,
explicit padding, C static assertions and Go ELF/layout tests. Rule indices and
original file line numbers are separate concepts. Event ABI and rule/map schemas
must be coordinated by A/B/C before their implementation; placeholders are not
being frozen prematurely.

## Reload gate: still to implement and prove
A complete candidate is parsed and validated before active state changes. A
packet must select one complete immutable configuration, including rules and set
references. Publish one selector only after all candidate objects are ready.
**Two or three reusable slots alone do not prove safe reuse.** Before implementing
reuse, establish a kernel-supported lifetime/quiescence mechanism and stress it
with repeated reloads on all CPUs. Retaining old objects temporarily is useful
for a prototype but is not an unbounded production strategy. Record the actual
chosen mechanism and tests here in the control-plane PR.

Never detach during reload. Invalid candidates preserve all active state. After
success returns, every new packet sees the candidate. Serialize reload and live
set commands in the daemon. Live set add/del must not rewrite the original file
or increment rules_version; preserve rule counters during set edits.

Global counters, jail and event history survive reload. Each new rules list has
fresh per-rule counters. Limit buckets may restart. Allocate at least 65,536
source entries independently per limit rule; a shared LRU capacity alone does
not ensure that isolation. Do not evict active jail entries or exact source
counts silently. Define and measure memory/capacity limits.

## Observability
Per-CPU packet counters avoid global counter contention; sum them without resets.
Reads during active traffic are not a globally simultaneous snapshot. HTTP and
CLI share serialization and schema. Snapshot/cleanup must synchronize so maps
are never closed while a request reads them. A dedicated event drain must never
wait on dashboard clients. Measure 20,000 logged decisions/second and assert zero
lost events; buffer-size estimates alone are not evidence.

## Integration and ownership
A owns bpf/. B owns CLI/config/dataplane/daemon. C owns observe/web/integration
bench. Each owner tests their features. Coordinate ABI/build changes first,
merge small PRs frequently, and reserve the last day for target-platform tests,
performance, cleanup, documentation and dashboard screenshot.

## Open clarifications
The PDF's early IPv4-only wording is extended by its later IPv6 section. Treat
IPv6 as supported everywhere, including an unconditional rule, and ask organizers
if possible. Event saturation, source-count capacity and reload reclamation
need explicit limits/tests. No model-proposed memory or throughput estimate is
a measured result. The target remains Ubuntu 24.04, Linux 6.8, x86-64, 4 CPUs;
ARM64-host testing does not replace that validation.
