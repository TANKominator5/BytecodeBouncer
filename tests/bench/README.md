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
