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

## Current implementation
- The parser accepts the complete strict grammar, original line numbers, forward
  sets and normalized mixed-family prefixes. Start supports a honeypot interface.
- A child daemon reports readiness only after HTTP/socket bind and native XDP
  attachment. An existing attachment is not force-replaced.
- XDP implements parsing, first-match policy, sets, per-rule/source buckets,
  jail/scans, bounce/redirect, counters and event production. Start/reload publish
  complete policy generations; live set edits and atomic unjail operate on maps.
- All specified CLI verbs are integrated. Stats/jail/log commands and HTTP use
  the same typed telemetry service. Snapshots include per-rule counters, sets,
  exact top-five source ranking and currently active jail entries.
- A dedicated event consumer retains the newest 1,000 decisions across reloads;
  embedded dashboard assets poll all panels every second. Diagnostics live on a
  separate endpoint, preserving the exact required stats JSON.
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
original file line numbers are separate concepts. ABI v5 and its integration
protocol are documented in [docs/dataplane-abi.md](docs/dataplane-abi.md). The task
owner authorized this shared change; B/C review remains required before merge.

## Reload publication
Each immutable config map belongs to one loaded program generation. Build and
freeze a complete candidate, reuse persistent maps, then update the existing XDP
bpf_link program. Program/map references live through outstanding invocations;
kernel RCU reclaims retired programs after descriptors close. This avoids both
mutable/reusable config slots and an unbounded list of retained generations.
Both kernel wire and public CLI tests exercise replacement under traffic. Local
CLI stress checks include 12 adversarial reloads and a 64-limit-rule reload under
one second; worst-case Linux 6.8 timing and long-run reclamation remain open.

The production loader now creates a private BPF_F_RDONLY_PROG config map and
freezes it before program verification, reuses persistent maps and builds fresh
sets, buckets, scan state and rule counters. Only a successful link update changes
the active collection/version; failed candidates close their own resources.
Frozen ELF action/match masks are derived from each validated candidate, letting
older verifiers prune unused features despite variable rule indices. Generic
kernel fixtures keep every feature enabled; packet decisions remain inside XDP.
Mutation serialization and snapshot read locks protect collection/metadata
lifetime. All source/jail map reads use batches; jail reads take BPF_F_LOCK.
Private limit-map allocation uses at most four workers to meet the measured
reload budget; each rule still owns a separate LRU with at least 65,536 usable
source entries, plus 128 allocated slots per possible CPU for kernel free-node
reserves. The existing
template serves the first rule. All preparation workers finish before publication.

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

`StateReader` returns a detached generation-consistent native map snapshot under
the plane's read lock. C formats full numeric IPv4-before-IPv6 ordering, canonical
addresses, ceil jail seconds, and exact top five using a bounded candidate list.
No stats serialization lock is held by event draining. History is copied (nullable
port pointers included) before serialization, so clients cannot mutate it.
Log snapshots serialize ring Flush barriers: the drain appends all queued records
before acknowledging the barrier, avoiding sleep-based guesses or an empty read
that hangs until another packet. Reader Close unblocks shutdown. End-to-end
90,000-decision logging at ~25k/s with concurrent/slow HTTP clients is measured in
`docs/integration-validation.md`. `/health.json` exposes events_read, ring loss,
map allocation failures and terminal stream errors separately from stats.

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

## Expired-state recovery

Jail and scan maps reclaim expired entries on insertion pressure. A shared
maintenance map serializes collectors; locked retirement markers prevent a
concurrent writer from reviving a value after deletion. Share maintenance with
jail across program replacements. Active state is never evicted. Scan allocation
failures drop the current packet with diagnostics instead of bypassing detection.
See the ABI handoff for finite-capacity and pressure-path performance limits.

Unjail uses a separate, never-attached XDP control program invoked by test-run;
it checks retirement and clears release time under one lock, rather than a
userspace read/modify/write. Scan threshold decisions remain pending across jail
allocation contention and are retried even on repeated destination ports.

## Shared Go boundary

`internal/contract/contract.go` mirrors the C ABI and owns typed public JSON.
Dataplane counters and kernel-test fixtures use these production types, with
ELF/BTF tests checking their layout. Observe consumes StateReader rather than
concrete dataplane.Plane. B supplies decoded EventReader records and map/control
operations; C implements Telemetry snapshots/history. The daemon wires their
lifecycle and invokes the same snapshot API for CLI and HTTP. Shared Go snapshot
and flush-barrier additions do not alter the ABI v5 kernel layouts.
