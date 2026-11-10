# Issue B control-plane foundation

`feat/control-plane` provides the strict parser, production generations,
atomic publication, live sets and ABI v5 atomic unjail as an independent foundation
commit. `feat/observability-bench` integrates that dependency plus C's complete
snapshots/history and all CLI verbs. The integration branch also parallelizes
private limit-map allocation and removes an arbitrary parser line-length cap.
See [integration validation](integration-validation.md) for measured end-to-end
checks. Worst-case Linux 6.8 acceptance is not claimed.

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
