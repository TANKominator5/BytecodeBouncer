# Specification checklist

Checked items are exercised locally, not a claim of Linux 6.8 or hidden-harness
acceptance. See [integration validation](integration-validation.md) and
[dataplane validation](dataplane-validation.md).

- [x] Build a self-contained ./trafficcop with embedded BPF/web assets.
- [x] Native XDP attach in isolated veth namespace, start readiness, stop cleanup.
- [x] Singleton lock, private CLI socket, failed-start resource cleanup.
- [x] Per-CPU packet counters, shared stats JSON and live dashboard.
- [x] Reject unsupported config/commands instead of silently pretending support.
  - [x] Reject blocking special policy files; bound runtime input to 16 MiB.
- [x] Complete strict rules grammar, forward sets, normalized prefixes, limits.
- [x] Ethernet/VLAN/IPv4/options/fragments/malformed and complete IPv6 parsing.
- [x] Kernel first-match engine, all matches, fragment/default semantics, line numbers.
- [x] Independent per-rule/per-source token buckets and capacity tests (WSL kernel).
- [x] Live address set edits, reload replacement, mixed-family prefix boundaries.
- [x] Jail, expiration/list/release and fixed-window distinct-port detector.
  - [x] Kernel jail/expiration/locked release and exact fixed-window detector.
- [x] Bounce MAC-only mutation and unchanged honeypot redirect (private veth wire checks).
- [x] Exact per-rule/global counters, exact source ranking and numeric ordering.
  - [x] Four-CPU kernel/source accounting plus deterministic CLI/HTTP equivalence.
  - [x] Interrupted test-run replay regression; exact assertions retained.
  - [x] Full source/jail/scan capacities and exhaustion/recovery (WSL; see follow-up evidence).
- [x] Atomic reload, safe old-object lifetime, persistence, fresh rule counters.
  - [ ] Long-run reclamation and worst-case Linux 6.8 reload timing.
  - [x] Repeated changed 64-limit policies: retired kernel program/map IDs reclaimed (WSL).
  - [x] Million-source plus million-jail stats snapshot measured below one second (WSL).
- [x] Event ABI, lossless sustained daemon logging above 20k/s, newest 1000 history/log.
- [x] Complete dashboard panels, pps, jail and latest events; real browser screenshot.
- [x] CLI grammar/timings/error behavior and failed-start rollback tests (local fixtures).
- [ ] Fresh native Ubuntu 24.04 x86-64 build/runtime and four-CPU stress verification.
  The acceptance runner rejects containers, VMs, emulation and unavailable or
  failed virtualization detection; mocked detector checks are not target evidence.
- [ ] Benchmark, README test evidence and actual dashboard screenshot.
  - [x] README, sustained logging/reload measurements and actual dashboard screenshot.
  - [ ] Target flood speed/NIC throughput benchmark.
  - [x] Sustained four-CPU private-veth flood, exact verdict totals and recorded method.
  - [ ] All full-capacity CLI deadlines: million-entry jail timeout/stats timing remain open.
    - [x] Linux 6.8 VM component profiles, radix aggregation and framed IPC regressions;
      full-map acceptance still blocked ([details](cli-performance-validation.md)).
