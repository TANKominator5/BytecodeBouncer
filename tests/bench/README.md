# Namespace bench

Run `sudo tests/integration/bootstrap.sh` after `./build.sh`. It creates a
uniquely named namespace with a veth pair, attaches only inside that namespace,
sends raw Ethernet frames, checks counters/HTTP/lifecycle, then removes the
namespace. It refuses to run when a trafficcop control socket already exists.

`make integration` additionally runs `firewall.sh` and `lifecycle.sh`: actual
CLI/HTTP policy/state/history, byte-exact bounce/honeypot with dedicated PASS
peers, failure rollback and signal cleanup. `make stress` is a separate measured
90k-event/25k-per-second scenario plus four-CPU reload traffic, 64 independent
limit-map allocation and 10,000-prefix reload/capacity checks.

`firewall.py` and `stress.py` are invoked only by their disposable-namespace shell
wrappers. `pass.bpf.c` is compiled into a temporary directory and attached only
to bench peers, never a host interface. Use `nsenter --net=...`, not `ip netns
exec`, when invoking trafficcop: the grading environment shares bpffs.

The optional `demo_traffic.py` illustrates real XDP counters inside the owned
`demo.sh` namespace. See [integration evidence](../../docs/integration-validation.md)
for methods, actual results and target-platform limitations.

## Consequential acceptance targets

- `make endurance`: five minutes of four-CPU adversarial reload/live-set traffic,
  then ten changed 64-limit policies. Every command still has a strict one-second
  assertion; descriptors, RSS, accounting and stop cleanup are checked.
- `make throughput`: four 15-second **private-veth** floods using a CPU-affined
  four-thread C `sendmmsg` generator. Measures default PASS, DROP, 64-rule last
  match, and that policy with eight IPv6 extension headers. Accepted sends must
  equal kernel verdict/rule totals. This is not a physical-NIC line-rate result.
- `sudo bash tests/integration/command-capacity.sh`: seed the owned daemon's maps
  with one million source/jail records and measure real CLI process/IPC/output
  latency. It prints every result and fails if any behavior/deadline is unmet.
  `populate` refuses the host namespace and mismatched daemon namespaces.
- `sudo env "PATH=$PATH" bash tests/integration/acceptance.sh --require-target`:
  fresh clean Ubuntu 24.04/Linux 6.8/x86-64 checkout, full suite plus capacity,
  reclamation, command latency, endurance and flood. Logs/provenance are retained
  under `TC_EVIDENCE_DIR` (or a fresh temporary directory). Wrong platforms are
  rejected before tests. `--local` explicitly labels non-target evidence.

Full-state tests require at least 1.5 GiB available host memory and do not attempt
system-wide OOM. A failing capacity timing remains an acceptance gap, not a reason
to raise the deadline. See [follow-up evidence](../../docs/remaining-work-validation.md).
