# Person A dataplane handoff (ABI v3)

`include/contract.h` is the authoritative layout. Shared changes were authorized
by the task owner; B/C review is still required before merge. A also adds kernel
fixtures in `internal/dataplane/policy_test.go` and the header dependency in
`Makefile`. CLI/config/reload/dashboard implementation remains with B/C.

## Publication and lifetime (Person B)

Build **a new XDP program and private config map for each generation**. Populate
`config[0]` completely, validate every field, freeze that map with `Map.Freeze`,
and install only after every referenced map is ready. `rule_count <= 64`, set IDs
are 0..15, flags use `tc_match`, protocols/families use 0 for any. Prefix bytes
are network order; all other integers are native little endian on the target.
Reserved bytes must be zero. Counters and addresses retain their bootstrap ABI.

Use `bpf_link` program replacement (`link.Link.Update`) on the existing XDP link,
**not** detach/reattach and **not** reusable config slots. An invocation executes
one program whose map references cannot change. Linux keeps an old program/maps
alive for outstanding invocations; closing the old userspace descriptors after
successful replacement lets kernel RCU reclaim them. This avoids an unbounded
list of retired generations. Replacements must be serialized with live set edits.
Only return success after the link update succeeds. A failed candidate must close
only its own descriptors and leave the old program active.

Pass these persistent maps to `NewCollectionWithOptions` / `MapReplacements`:

| Map | Purpose |
| --- | --- |
| counters | cumulative per-CPU totals |
| health | cumulative per-CPU diagnostic failures |
| maintenance | serialized jail/scan reclamation; share whenever jail is shared |
| sources | full-address cumulative atomic packet counts |
| jail | full-address locked release times |
| events | single ordered ring, one continuous consumer |

Other maps (`config`, `rule_counters`, `sets`, `buckets`, `scans`) belong to one
generation. Scan windows and buckets restart on reload; jail/history do not.
ABI v3 reuses the jail value's former reserved word as `retired` and adds
`retired,reserved` before the scan generation (scan size 8,224; bitmap offset 32).
No userspace Go mirror is shipped as production code until B integrates it;
the typed fixtures demonstrate encoding without unsafe casts.

The zero-initialized config preserves the bootstrap default PASS, fragments DROP
with no rules. This is **not a configuration publication API**: never write an
attached program's config map in place. Production B code must explicitly set
defaults and generation (starting at 1). The bootstrap parser still rejects all
unsupported rule syntax rather than silently accepting unenforced policy.

## Address sets

One LPM trie per generation holds all 16 mixed-family sets. A key's data starts
with `{set_id, family, 0, 0}`, then 16 network-order address bytes (IPv4 in the
first four bytes, twelve trailing zeros). `prefixlen=32+prefix_bits` for insertion;
lookups use 64 for IPv4 or 160 for IPv6. This keeps /0 confined to one set/family.
Values are a nonzero uint32. Clear host bits. Handle duplicates, absent deletions,
set names and the total 10,000-prefix limit in userspace. Edits change only the
active generation's trie; they must not reset counters or increment generation.

## Stateful maps

- `buckets` is ARRAY_OF_MAPS with 64 rule-index slots. Allocate an independent
  LRU_HASH using its inner template **only for each limit rule**; insert before
  attaching. Each has 65,536 full-address entries. `bucket_template` is a concrete
  map retaining the complete inner BTF schema; reuse it for the first limit rule
  (otherwise it is an unused allocated map). Populate the private outer map with
  one `BatchUpdate` of rule indices and uint32 map FDs, avoiding 64 individual
  updates/RCU waits. Keep those FDs open through the syscall.
  Linux 6.8 does not support spinlocks in LRU maps. Each value instead has one
  64-bit virtual finish time, atomically advanced with compare-and-swap. This
  GCRA representation is a continuously refilling token bucket, with one token
  interval rounded up to nanoseconds (at most 0.1% rate error in the allowed
  range). It preserves fractional refill and never multiplies allowance by CPU
  count. A bounded 64-attempt contention retry failure increments bucket_failed.
- `jail`: HASH with no active-entry eviction. Values contain a `bpf_spin_lock`.
  Read/update with `BPF_F_LOCK` (`LookupWithFlags(..., LookupLock)` and
  `Update(..., UpdateLock)`). To unjail set `until_ns=0` on the existing entry,
  not delete: a kernel CPU may still hold its value pointer. Compare expiration
  against `CLOCK_MONOTONIC`, round positive remaining seconds up. Expired entries are reclaimed on allocation pressure. A collector takes the
  shared maintenance flag, marks an expired value retired under its spinlock,
  then deletes it outside the lock. Writers retry retired jail pointers rather
  than extending orphaned values. Preserve the retired field on userspace updates;
  retry retired records instead of reviving them. Do not independently delete
  entries or reset maintenance flags.
- `sources`: non-LRU HASH, counts every valid IP packet reaching step 6, including
  packets dropped by jail/scan. A single atomic counter includes all CPUs. Sort
  snapshots by count descending then full numeric address (v4 before v6).
- `scans`: non-LRU HASH, exact 65,536-port bitmap per source, locked reset/count.
  Repeated ports (TCP or UDP) share one window. Only a new port crossing the
  threshold triggers jail. No probabilistic/Bloom approximation.

Source/jail maps have 1,048,576 entries each, scans 65,536. Hash values are allocated
on demand (`BPF_F_NO_PREALLOC`); slots are not silently evicted. These are finite
capacities, not unlimited guarantees. Cumulative source identities consume slots until stop. Expired jail/scan
entries are reclaimed on allocation pressure (scan maps also reset on reload). Exact source ranking is only
guaranteed while identities fit. Report memory measurements separately from
logical payload: full scan values are about 514 MiB, plus kernel overhead.
Each allocated limit LRU also costs kernel memory even when empty. Loading all 64
limit rules must be tested on the target before declaring capacity acceptance.

Allocation failures increment the relevant `health` field. A missing/failed
bucket drops its matching frame. A full source map loses source accounting; a jail map full of active entries cannot enforce new jail state; a scan map
with no reclaimable entry drops the current packet without incrementing jailed. **Those conditions are failures,
not spec-compliant success**: B/C should surface them prominently (and start must
fail if required map allocation fails). Packet decisions still remain in XDP.

## Accounting/events (Person C)

Every frame returns through `finish`: exactly one passed/dropped/bounced/
honeypotted increment. Other and malformed are subsets; jailed includes only
pre-rule jail/scan drops, not the initial jail-rule hit. Fragment fallback does
not increment default hits. Per-rule counters use the zero-based rule index;
events record the original file line and generation. Both pass/drop sides of a
limit rule count as hits and produce events when logged.

`tc_event` is 80 bytes: timestamp, generation, line, final action, two full
addresses, ports, protocol, has_ports, reserved. Verdicts 1/2/3/4 mean
DROP/PASS/BOUNCE/HONEYPOT; null JSON ports when has_ports=0. Consume continuously
on a dedicated goroutine, retain the newest 1,000 in ring order across reloads.
Do not tie draining to HTTP. Ring capacity is 16 MiB; `health.event_lost` records
failed reservations. Ring sizing is not proof of the 20k/s acceptance requirement.

Honeypot uses `bpf_redirect(ifindex,0)` without changing bytes. Reject missing or
invalid interfaces before publication. A helper failure is DROP, never PASS;
post-return driver delivery errors cannot be observed as XDP policy counters.

## Checks

`make test` includes nonprivileged ELF/BTF layout checks. `bash bpf/test.sh` runs
native ASan/UBSan fixtures for sub-Ethernet lengths (the kernel test-run API
requires at least 14 bytes). `sudo bash bpf/test.sh --kernel` additionally loads
the real program and submits packet/state/concurrency fixtures without attaching
to any interface. `sudo bash bpf/netns-test.sh` creates its own namespace,
attaches only to its veths, checks actual bounce/redirect frames and replaces the
program five times during traffic. It always attempts namespace cleanup and
refuses to attach in PID 1's network namespace. Linux 6.8 target, long-run reload
timings/reclamation and daemon event throughput still require measured evidence.
See [validation](dataplane-validation.md).

## Reclamation tradeoffs

Reclamation runs only when insertion fails and stops after one expired entry.
Active release times/windows are checked under their value lock, so historical
sources no longer permanently poison a full map. A serial collector plus a
retirement marker protects stale RCU readers from reviving a deleted value.
A contending collector may temporarily prevent an insertion; scan allocation or
retirement failure is a diagnostic DROP, not a bypass or a jailed counter hit.
The bounded jail writer retries four times and reports jail_full on exhaustion.
Fully active capacity exhaustion remains a resource failure, not a claim of
unlimited state. Scanning a full active map can be costly; measure worst-case
pressure on the target, and do not claim a packet-rate bound for this path.
