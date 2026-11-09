# Specification checklist

Only the bootstrap items below are implemented; all final-spec work is open.

- [x] Build a self-contained ./trafficcop with embedded BPF/web assets.
- [x] Native XDP attach in isolated veth namespace, start readiness, stop cleanup.
- [x] Singleton lock, private CLI socket, failed-start resource cleanup.
- [x] Pass-through per-CPU counters, shared stats JSON and live dashboard scaffold.
- [x] Reject unsupported config/commands instead of silently pretending support.
- [ ] Complete strict rules grammar, forward sets, normalized prefixes, limits.
- [ ] Ethernet/VLAN/IPv4/options/fragments/malformed and complete IPv6 parsing.
- [ ] First-match engine, all matches, fragment/default semantics, line numbers.
- [ ] Independent per-rule/per-source token buckets and capacity tests.
- [ ] Live address set edits, reload replacement, mixed-family prefix boundaries.
- [ ] Jail, expiration/list/release and fixed-window distinct-port detector.
- [ ] Bounce MAC-only mutation and unchanged honeypot redirect.
- [ ] Exact per-rule/global counters, exact source ranking and numeric ordering.
- [ ] Atomic reload, safe old-object lifetime, persistence, fresh rule counters.
- [ ] Event ABI, no loss at 20k/s, last 1000 history and log command.
- [ ] Complete dashboard panels, pps, jail and latest events.
- [ ] Full CLI grammar/timings/error behavior and failed-start rollback tests.
- [ ] Fresh Ubuntu 24.04 x86-64 build/runtime and four-CPU stress verification.
- [ ] Benchmark, README test evidence and actual dashboard screenshot.
