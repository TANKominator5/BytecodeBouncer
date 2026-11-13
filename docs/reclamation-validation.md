# Issue #11 — off-packet reclamation, 12 November 2026

## Change and explicit budget

The attached XDP program no longer invokes `bpf_for_each_map_elem` on full jail
or scan maps. Failed insertions coalesce a maintenance request with one atomic
compare-and-swap. Existing retry bounds, diagnostic failures, exact accounting,
active-state protection, retirement/cancellation checks and pending scan jail
decisions remain in the kernel. The current packet fails closed when allocation
fails; this is a resource failure, not a successful jail installation.

A daemon-owned worker polls every **100 ms**, runs at most one requested sweep
per map per tick, and each sweep removes at most **256** expired records. A sweep
may inspect the **whole map** when nothing is expired; this cost is amortized
and moved off packet/CLI execution, **not eliminated**. No per-packet map-walk
or per-source sweep queue exists. Healthy unused configurations only incur two
small maintenance flag reads each tick. No userspace code deletes a locked value
or decides a packet verdict.

The worker clones the selected generation's control-program descriptors under
the plane read lock, then drops the lock **before** executing BPF test-run. Kernel
program/map references pin that old generation until clones close. Reload and
snapshots therefore do not wait on a plane lock held over a sweep. Active state
is never evicted, and a retired collector cannot touch a newer scan map/config.
Close joins the worker before destroying maps/link. Worker failures surface via
ReadHealth; an idle tick cannot erase the failure.

This is **ABI v6**: existing binary sizes/offsets are unchanged, but maintenance
flags now mean idle=0, busy=1, requested=2, and two control-only programs are
required. C/Go constants and existing ELF/BTF checks were updated together.
Restart on upgrade; do not mix v5/v6 objects/loaders. Cross-owner A/B changes
require review; the shared contract is not silently extended on one side.

## Linux 6.8 VM evidence (not native target acceptance)

Tested by SSH on the supplied Ubuntu 24.04.4 KVM VM, Linux 6.8.0-134-generic
x86-64, **one allowed CPU, 961 MiB RAM**, Go 1.22.2, AMD EPYC 7642 model. No WSL
testing. Host interfaces untouched; test-run or dedicated namespace veths only.
Baseline source was merged main `b54ac2f`.

The diagnostic test fills **8,192 active entries** per map, then submits 256
distinct new sources. This is an explicitly reduced map size to fit the VM, not
the production capacity. Each timing includes a userspace test-run syscall and
returned verdict. Three runs before/after:

| Map | Before p50 / p99 | After p50 / p99 | Before pps | After pps |
| --- | --- | --- | ---: | ---: |
| jail | 1.395–1.410 ms / 1.461–3.080 ms | 2.66–2.67 us / 15.23–16.92 us | 645–715 | 202,084–250,271 |
| scans | 1.308–1.997 ms / 1.387–2.005 ms | 2.53–2.67 us / 12.13–17.94 us | 630–767 | 227,810–284,082 |

After-change full-active off-packet sweep: jail **0.384–0.467 ms**, scans
**1.351–1.501 ms**. The baseline test did not invoke a separate collector (it was
inline); its no-op placeholder sweep timing is not a measurement and is excluded.
No NIC/ingress-throughput conclusion follows from test-run pps.

Two-second additional novel-source runs, four goroutine submitters on the **one
CPU**, with the real maintenance worker running:

| Map | Frames = diagnostic drops | Elapsed | Test-run pps | Sampled p50 / p95 / p99 / max |
| --- | ---: | ---: | ---: | --- |
| jail | 573,479 | 2.046 s | 280,340 | 2.30 / 3.45 / 11.66 us / 1.524 ms |
| scans | 583,591 | 2.001 s | 291,685 | 2.04 / 3.33 / 13.24 us / 2.168 ms |

Every 64th syscall is sampled; max is the sampled maximum, not a hard latency
guarantee. Active records were retained unchanged. Global drops and full-map
diagnostic counts matched all submitted frames, with no PASS/jailed-count bypass.
The worker still consumes CPU and can affect scheduler latency on a single CPU;
moving the walk off ingress is not a promise that packet wall time is bounded
under arbitrary host load. At full active capacity, all these drops are expected
resource failures, not compliant successful admission of new state.

An initial combined diagnostic run encountered `cannot allocate memory` while
populating the reduced scan map on this 961-MiB VM; it was recorded as a failure,
not skipped or counted as passing. Subsequent isolated pressure runs populated
the same size without any retry code/guard reduction. This further demonstrates
why this host cannot establish full-capacity acceptance.

## Checks and regressions

```sh
./build.sh
make test
make integration
bash bpf/test.sh --kernel
bash bpf/netns-test.sh
TC_BPF_TEST=1 TC_PRESSURE_TEST=1 go test -v ./internal/dataplane \
  -run 'TestKernel(NovelSourcePressureLatency|SustainedActivePressure)' -count=1
TC_BPF_TEST=1 go test -race -v ./internal/dataplane \
  -run 'TestKernel(AsyncMaintenanceLifecycle|CollectorPinsRetiredGeneration|ConcurrentAsyncReclamation|CollectorBatchAndCoalescing)' -count=3
```

Build, race/vet, namespace integration, privileged kernel suite, actual veth wire
replacement and repeated race-enabled collector tests passed. New tests assert:

- No map-iteration helper is linked into the ingress program.
- Many failed packets coalesce one request; idle collectors do nothing, a
  productive invocation frees no more than 256 entries.
- Four concurrent submitters plus collector preserve active state and exact
  accounting; existing cancellation, pending-scan and retirement tests still pass.
- A clone from a closed/retired generation still runs but cannot alter new scan
  state; daemon worker recovery, join/idempotent shutdown and failure visibility.
- Freeing/expiring a slot recovers admission; full-capacity suite now measures
  the explicit off-packet sweep separately from the next packet.

The Linux 6.8 verifier initially failed state convergence with only an increment
and return-at-256 callback. An explicit early saturated-count check makes its
callback-state fixed point bounded; the actual 6.8 kernel suite verifies it.
Final runs use the unmodified pinned cilium/ebpf dependency, not the temporary
diagnostic copy used to expose the verifier log.

Logs remain on the VM at `/root/trafficcop-gc-20261112/evidence/`.

## Not complete

**#11 remains open** pending production-size pressure, simultaneous four-CPU
traffic/reloads, target distributions/throughput and resource evidence. The
supplied VM cannot run that acceptance. Production memory guards and native-target
gate remain unchanged. #9 also remains blocked by KVM/CPU/RAM; #10 lacks a
dedicated authorized physical NIC and external traffic peer. No physical interface
was attached, reconfigured or used for a flood.
