# Issue B control-plane foundation

This branch implements strict rules parsing, production generation construction,
atomic link publication, live set mutations and ABI v5 atomic unjail. It does not
claim Issue B acceptance before C's telemetry provider is integrated: the old
counter-only adapter is retained for bootstrap callers, jail/log explicitly fail,
and runtime logging policies are rejected until an event consumer is integrated.
Daemon CLI/HTTP stats now use generation-consistent map snapshots, including
rule/set records, source ranking and active jail count. Use the observability integration branch for the full
daemon. One-second worst-case reload and Linux 6.8 checks remain required.

## Shared boundary coordination

No C ABI/layout/version changes. `internal/contract` gains concrete detached
`State`/`StateReader` records for B's map reads and C's aggregation. `EventReader`
gains Flush, with an immutable ErrEventsFlushed sentinel: queued samples precede
the barrier, and an empty blocked reader wakes. C must acknowledge the barrier
after appending every preceding event before returning a log snapshot. Close
also interrupts reads. There are no private duplicate rule/event/stats schemas.

## Publication and persistence

| State | Reload |
| --- | --- |
| global counters, health, sources, jail/cancellation, maintenance, event ring | same maps |
| configuration, sets and metadata, rule counters, buckets, scan state/seed | fresh generation |
| old program/maps | descriptors closed after successful bpf_link update; kernel RCU retains outstanding invocations |

The generation config is read-only to BPF and frozen before loading the program.
No mutable selector or reusable config slots are used. Preparation occurs without
locking snapshots; publication, live set edits, unjail and close are serialized.
Snapshot reads pin the active collection and metadata. Source/jail batch lookups
avoid per-entry syscall pairs. Set edits update the active LPM map and metadata
only after validation; duplicate add is idempotent. Files are never rewritten.

Unjail runs the never-attached control program against its private request map;
it never overwrites or deletes a jail value from userspace. The daemon supplies
absolute rule paths and preserves readiness, singleton locking and rollback.
After a failed child exits, stale socket cleanup first acquires the singleton
lock, so it cannot remove another daemon's socket.

## Checks

On Ubuntu 24.04/WSL2 Linux 6.18 x86-64:

- `bash ./build.sh`, `make test`: build, complete grammar/range/duplicate/line/
  capacity/normalization/forward-reference tests, CLI argument tests, race and vet.
- Root `TC_BPF_TEST=1 go test -count=1 -v ./internal/dataplane -run TestKernelProductionControl`:
  production map preparation, real packet matching, mixed-family live edits,
  detached map snapshots, atomic release/absent release, per-source limits,
  event decode/flush and blocked-reader cancellation.
- Root `bash tests/integration/bootstrap.sh`: native attachment, readiness,
  failure rollback, singleton/HTTP/stop/restart and failed/successful reload.

The smoke test's former unsupported-reload assertion was updated because reload
is now implemented. This is a necessary cross-owner test change. Target Linux
6.8, adversarial CLI reload/sets stress, command timing at worst capacities and
the complete observability provider remain integration checks, not presumed passes.

## Review fixes

Runtime policy loading inspects with O_PATH before opening for reading, accepting
regular files and `/dev/null` only. It reopens the validated descriptor through
procfs, so symlink swaps cannot bypass the type check. Total input is capped at
16 MiB, including comments, to bound work for concurrently growing files. FIFO,
device, oversized and logged-policy failures leave the active generation intact.
The complete grammar remains available through ParseReader for kernel tests.

The stats fix crosses into C's observe ownership and extends the namespace smoke
test. It uses the existing shared StateReader and JSON types with no ABI change.
Focused tests cover generation metadata, rule counters, alphabetical sets,
full IPv4/IPv6 numeric source ordering, active jail expiry and detached snapshots.

Top-five aggregation keeps five candidates instead of sorting/copying every
source. ReadState still reads all source/jail records; worst-capacity latency
must be measured. CLI response deadlines allow 1.5 seconds to receive completion;
this does not relax the specification's independently measured one-second budget.

CI on 72c7163 exposed a nonempty-policy CLI reload exceeding the smoke test's
one-second subprocess deadline on Ubuntu runners (both push and PR jobs).
The smoke test now checks nonempty metadata at startup, then successful reload
to an empty policy, metadata clearing and version increment within the unchanged
one-second command timeout. Nonempty reload timing remains a demonstrated gap;
this test arrangement does not establish that acceptance requirement.
