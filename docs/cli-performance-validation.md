# Issue #8 — CLI component optimization, 12 November 2026

## Environment and scope

All new tests ran over SSH on the supplied **KVM VM**, Ubuntu 24.04.4,
Linux 6.8.0-134-generic x86-64, Go 1.22.2, AMD EPYC 7642 model,
**one allowed CPU, 961 MiB RAM**. No tests ran in WSL. The host interface was
not modified; kernel packet tests use test-run, integration uses private veths.
Baseline source: merged main `b54ac2f` (remote archive checkout).

The full public command-capacity wrapper still refuses this host:
`requires 1.5 GiB available; refusing host OOM pressure`. Its guard was not reduced.
The native-target gate also refuses KVM, as required by #9. These are blocked
checks, **not passes**. The user approved continuing available work on this VM.

## Profile and change

One million detached jail records fit for component benchmarks without allocating
the full production kernel maps or running simultaneous candidate generations.
`BenchmarkFullJail*` uses deterministically shuffled IPv6 identities, not presorted
input. Each benchmark ran three times with `-benchtime=1x`:

| Component | Before | After |
| --- | ---: | ---: |
| Numeric ordering + canonical address/ceil-seconds jail formatting | 651–685 ms | 278–301 ms |
| Distinct active jail count in stats | 184–204 ms | 103–128 ms |
| Standard JSON marshal of formatted jail entries | 175–202 ms | 178–241 ms (unchanged encoder) |
| JSON-encoding the 45 MiB raw payload a second time in an envelope | 406–409 ms | Removed |
| New framing + `net.Pipe` complete send/read/content comparison | n/a | 12.5–24.2 ms |

CPU profiling attributes much of baseline jail formatting time to comparison
sorting (`slices.partitionCmpFunc`, the comparison closure and address compare).
Stats also spent time inserting a million hash keys. Large snapshots now use
stable byte-radix sorting (family before full network-order bytes), skipping
constant byte scatter passes; small snapshots retain comparison sorting. The
sort acts on a private copy, deduplicates adjacent keys with the latest expiry,
and never changes caller-owned storage. Radix scratch adds ~32 MiB transient
storage at a million records; format allocations measured ~109 MiB versus ~75 MiB
baseline. This is a deliberate latency/memory tradeoff, not a memory saving.

Private IPC previously marshaled JSON, rescanned/copied it during response-envelope
encoding, then rescanned/copied it during client JSON decoding. The new response
is a bounded/versioned newline JSON header followed by exactly `length` bytes.
The client reads the complete payload before printing, so errors do not emit
partial public JSON. It does not decode/reformat the root-owned daemon's payload.
Output uses a direct byte write, not a full-size byte-to-string copy. Public
stats/jail/log schemas are unchanged. A header version mismatch fails explicitly;
restart the daemon after upgrading. Limits cover the maximum full IPv6 jail
response; negative, excessive, truncated, incompatible and short-write cases
have tests. The existing socket/command deadlines are unchanged.

The encode-to-discard benchmark only isolates the removed CPU cost; it is not an
IPC bandwidth claim. `BenchmarkResponseSocket` includes a complete in-memory
pipe roundtrip/content check, **not** kernel map reading, stdout, CLI process exit,
HTTP contention or reload pressure. Do not add the component timings and call
them full CLI acceptance. The map read path itself is unchanged in this patch.

## Reproduction / checks

```sh
./build.sh
make test  # race + vet, includes framing and randomized radix regressions
make integration  # bootstrap, policy/CLI/HTTP equivalence, lifecycle
bash bpf/test.sh --kernel
go test ./internal/observe -run '^$' -bench BenchmarkFullJail -benchtime=1x -count=3
go test ./internal/daemon -run '^$' -bench BenchmarkResponse -benchtime=1x -count=3
```

All above passed on the VM. CPU profiles, benchmark output, unit/kernel logs and
refusal logs remain in `/root/trafficcop-issues-20261112/evidence/` on that VM.
No source packet verdict or binary kernel layout changed (ABI v5 unchanged).
Changes cross B/C ownership: CLI, daemon private IPC and observe aggregation.

## Still open

- **#8:** full-production-map public commands <1 second including stdout/process
  exit, repeated with concurrent dashboard reads/reloads, still require sufficient
  memory and an eligible four-CPU host. This patch must not close #8 on component
  results alone.
- **#9:** VM is one CPU/961 MiB and KVM, not the native four-CPU target. The gate
  remains fail-closed. No resource guards or native checks were weakened.
- **#10:** VM has only loopback and SSH-facing `eth0`; no isolated physical NIC or
  external generator/receiver was supplied. No physical-NIC measurement attempted.
  A dedicated authorized lab setup is required, not a reinterpretation of veth pps.
