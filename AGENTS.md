# BytecodeBouncer contributor instructions

## Goal and scope
Build the trafficcop firewall defined in [problem_Statement.md](problem_Statement.md).
Read [architecture.md](architecture.md) and [docs/spec-checklist.md](docs/spec-checklist.md)
before implementation. The CLI accepts bootstrap rules only; the kernel
dataplane is broader, but this is not yet a completed integrated firewall.
Do not silently accept configuration that the dataplane does not enforce.

## Build simply
- Make the smallest complete change; reuse existing helpers and dependencies.
- XDP C makes every packet verdict. Go handles configuration, lifecycle, map
  management, IPC, counters, event consumption and HTTP. No iptables/nftables/tc.
- Keep BPF in one compilation unit initially. Avoid speculative wrappers,
  services, frontend frameworks, unsafe casts, or untyped data where a concrete
  domain type is available. Replace bootstrap empty JSON arrays with typed
  records as their features land.
- Preserve validation, accessibility, security, cleanup and exact accounting.
- Never replace an existing XDP attachment or alter a real host interface while
  testing. Use the dedicated namespace bench.

## Three-person ownership
- A: `bpf/` — parser, matching, actions, kernel state and packet accounting.
- B: `cmd/`, `internal/config/`, `internal/dataplane/`, `internal/daemon/` —
  configuration, CLI, attachment, reload and live control operations.
- C: `internal/observe/`, `tests/`, dashboard and test documentation — snapshots,
  events, HTTP and integration bench. Every owner adds tests for their changes.
- Coordinate `include/contract.h`, build/dependency files, architecture changes
  and pipeline changes before editing them. Cross-owner changes must be called
  out in the PR; do not block necessary fixes behind artificial boundaries.

## Shared Go contract (required for parallel B/C work)
- Use `internal/contract/contract.go` for action/match constants, binary rule/map/
  event layouts, typed stats/jail/log JSON records, and B/C interfaces. Do not
  create private duplicate schemas, `[]any` payloads, or new mutable global state.
- `include/contract.h` remains the C ABI authority. A/B coordinate both files;
  update the existing ELF/BTF layout tests and ABI version when layouts change.
- B owns parsing, validated Config/Rule construction, map/link lifecycle and
  live commands. Raw contract structs do not validate grammar or reserved bytes.
  B provides CounterReader and the EventReader stream; Close must unblock reads.
- C owns telemetry aggregation, canonical address/verdict formatting, event
  draining/history and HTTP. Implement Telemetry for Stats/Jail/Log snapshots;
  B routes CLI commands to those same methods. The daemon owns component startup
  and shutdown. Never let an HTTP client block the event drain.
- Snapshots must be safe for concurrent CLI/HTTP use and detached from mutable
  storage. Empty collections encode as []; absent event ports encode as null.
  Preserve exact spec ordering and JSON fields. Internal binary structs are not
  public JSON and must not be serialized as stats or logs.
- Until full providers are implemented, keep unsupported commands explicit.
  The existing observe snapshot consumes CounterReader so C can use a fake
  without waiting for B. Treat new interface methods as coordinated changes,
  not independent extensions on each branch.

## Workflow and verification
- Branch from current origin/main, one branch per issue. No direct main pushes
  after bootstrap. Do not commit generated ELF files or the trafficcop binary.
- Run `./build.sh`, `make test`, and `sudo tests/integration/bootstrap.sh`.
  Add feature-specific tests. Report unavailable privileged checks honestly.
- Keep CLI stdout valid JSON where required; errors are one stderr line, exit 1.
- PRs explain the concrete behavior, tests run, limitations and ABI changes;
  include `Closes #<issue>`. Request review from the other two people. Do not
  merge with failing required checks or an unreviewed shared contract change.
- Update the spec checklist and README with implemented behavior. Do not mark a
  requirement complete without exercising it.
- Questions/reviews are read-only unless implementation is requested. Do not
  install, edit, commit, push or publish merely to answer a question.
- Work alone for ordinary tasks. If explicitly delegating, use T3 capability
  discovery and delegate_task; provide context, separate ownership, and verify
  results yourself. Never treat model recommendations as verified facts.
