# Bootstrap validation

Local environment: ARM64 Linux 7.0.0-1013-oracle, Go 1.26.8, system Clang 21.
Target: Ubuntu 24.04, Linux 6.8, x86-64, four CPUs.

Executed successfully during bootstrap:
- `./build.sh`: native Go executable with embedded BPF ELF and web assets.
- `make test`: Go race-enabled unit/ABI/HTTP tests and go vet.
- `sudo tests/integration/bootstrap.sh`: real native XDP attachment to isolated
  veth, raw-frame pass counters, singleton rejection, failed attachment cleanup,
  HTTP/page responses, unsupported reload preservation, detach, stopped commands,
  port/socket release and restart; start/stop each under five seconds.
- `GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -o /tmp/trafficcop-amd64 ./cmd/trafficcop`:
  target architecture cross-build. This does not prove target runtime behavior.

The integration test initially used a raw TCP bind without SO_REUSEADDR after
HTTP requests; TIME_WAIT made that assertion fail. The test now uses SO_REUSEADDR
like Go's listening socket, and separately checks actual detach and restart.

Not established locally: a fresh Ubuntu 24.04 installation, x86-64/Linux 6.8
runtime, four-CPU stress, hidden-harness compatibility, full grammar/filtering,
reload, lossless logging, bounce or honeypot redirect. GitHub Actions is configured
to run the bootstrap on Ubuntu 24.04; inspect its result rather than assuming it
passed. No full-firewall performance or completion claim is made.
