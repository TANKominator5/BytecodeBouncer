# Namespace bench

Run `sudo tests/integration/bootstrap.sh` after `./build.sh`. It creates a
uniquely named namespace with a veth pair, attaches only inside that namespace,
sends raw Ethernet frames, checks counters/HTTP/lifecycle, then removes the
namespace. It refuses to run when a trafficcop control socket already exists.

Later packet tests should add bounce receiver XDP_PASS programs and a honeypot
veth pair as described in problem_Statement.md. Use `nsenter --net=...`, not
`ip netns exec`, when invoking trafficcop: the grading environment shares bpffs.
