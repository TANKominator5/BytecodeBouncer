# Specification checklist

Bootstrap plus Person A's kernel implementation are exercised below. Checked
kernel items do not imply CLI integration or Linux 6.8 acceptance; see
[dataplane validation](dataplane-validation.md).

- [x] Build a self-contained ./trafficcop with embedded BPF/web assets.
- [x] Native XDP attach in isolated veth namespace, start readiness, stop cleanup.
- [x] Singleton lock, private CLI socket, failed-start resource cleanup.
- [x] Per-CPU packet counters, shared stats JSON and live dashboard scaffold.
- [x] Reject unsupported config/commands instead of silently pretending support.
- [x] Complete strict rules grammar, forward sets, normalized prefixes, limits.
- [x] Ethernet/VLAN/IPv4/options/fragments/malformed and complete IPv6 parsing.
- [x] Kernel first-match engine, all matches, fragment/default semantics, line numbers.
- [x] Independent per-rule/per-source token buckets and capacity tests (WSL kernel).
- [ ] Live address set edits, reload replacement, mixed-family prefix boundaries.
- [ ] Jail, expiration/list/release and fixed-window distinct-port detector.
  - [x] Kernel jail/expiration/locked release and exact fixed-window detector.
- [x] Bounce MAC-only mutation and unchanged honeypot redirect (private veth wire checks).
- [ ] Exact per-rule/global counters, exact source ranking and numeric ordering.
  - [x] Exact kernel counters/source totals on four CPUs; ranking remains userspace work.
- [ ] Atomic reload, safe old-object lifetime, persistence, fresh rule counters.
  - [x] Attached program replacement with shared persistent maps under traffic;
    CLI reload and long-run/timing validation remain open.
- [ ] Event ABI, no loss at 20k/s, last 1000 history and log command.
  - [x] Fixed event ABI and lossless 20,000-decision kernel burst; continuous
    daemon draining/history remains open.
- [ ] Complete dashboard panels, pps, jail and latest events.
- [ ] Full CLI grammar/timings/error behavior and failed-start rollback tests.
- [ ] Fresh Ubuntu 24.04 x86-64 build/runtime and four-CPU stress verification.
- [ ] Benchmark, README test evidence and actual dashboard screenshot.
