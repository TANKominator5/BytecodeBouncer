# BytecodeBouncer / trafficcop

Hackathon eBPF/XDP firewall for the Bytecode Bouncer problem. **Person A's kernel
dataplane is implemented; the CLI still accepts only bootstrap configuration.**
This is not yet the complete, integrated firewall. Deadline: 13 November 2026,
11:59 p.m. IST.

Read [problem statement](problem_Statement.md), [architecture](architecture.md),
[contributor instructions](AGENTS.md), and [implementation checklist](docs/spec-checklist.md).

## Build

On Ubuntu 24.04 with root/sudo and network access:

```sh
./build.sh --install-deps
```

The script installs clang, llvm, libbpf-dev, linux-libc-dev, gcc, make, golang-go,
iproute2, python3, ca-certificates and git, then compiles `./trafficcop`.
Go 1.22+ is required. Go dependencies are pinned in go.mod/go.sum. Subsequent
builds use `./build.sh`. The daemon needs root, BPF/network-admin capabilities,
and a kernel with native XDP/bpf_link support. No CGO or external object file is
needed at runtime. Native XDP is required; there is no silent generic-mode fallback.

The Go cilium/ebpf library loads the BPF object; libbpf is used only for its C
headers at build time. The target is x86-64 Ubuntu 24.04/Linux 6.8, four CPUs.

## Run safely

```sh
make test
sudo tests/integration/bootstrap.sh
```

The integration test creates its own namespace and veth pair and always attempts
cleanup. It checks readiness/time limits, native XDP attachment, packet counters,
stats HTTP schema, singleton handling, unsupported commands, detach and restart.
Never attach this scaffold to a production interface.

For a persistent demo, the setup script creates its own namespace and veth pair:

```sh
sudo ./demo.sh start
sudo ./demo.sh stats
sudo ./demo.sh dashboard
```

The last command runs a foreground localhost proxy. Open **http://127.0.0.1:8088/**
in your normal browser. Ctrl+C stops the proxy; the demo remains running.
The proxy uses Python's standard library and forwards only the dashboard and
stats endpoints into the namespace. It fails clearly if host port 8088 is busy.

When finished:

```sh
sudo ./demo.sh stop
```

Stop removes the owned namespace and stops its trafficcop instance. If you left
the foreground dashboard proxy running in another terminal, stop it with Ctrl+C.
Repeated stop is harmless. Start refuses existing resources or another instance;
namespace/socket ownership is checked before cleanup. Failed startup rolls back
resources it created. Build and demo setup remain separate; `trafficcop start`
still operates on an existing interface as the grading harness requires.

Only blank lines, comments and one optional `default pass` are accepted. `reload`,
`set`, `jail`, `unjail`, `log`, filtering and the honeypot argument are explicitly
unsupported. Counters for unfinished features are zero and record arrays empty.
The kernel now parses Ethernet/VLAN/IPv4/options/fragments/IPv6 extensions and
classifies malformed frames correctly. With bootstrap configuration, valid IP
passes except unmatched non-first fragments, which drop. Policy-rule loading
and live commands still need Person B's integration; stats panels/event history
need Person C's integration. Do not assume the CLI enables those features yet.

### Person A dataplane tests and handoff

```sh
bash bpf/test.sh                # exact short parser fixtures, ASan/UBSan
sudo bash bpf/test.sh --kernel  # actual BPF packet/state/ABI/four-CPU tests
sudo bash bpf/netns-test.sh     # private veth wire actions/replacement under load
```

The XDP implementation supports all rule conditions and actions, mixed-family
sets, independent 65,536-source limit maps, jail/scans and logged decisions.
See [ABI and B/C handoff](docs/dataplane-abi.md) and
[actual validation/limitations](docs/dataplane-validation.md). The ABI includes
explicit diagnostic counters for finite map capacity and event-ring failures.

The daemon reports readiness through a pipe, owns an exclusive lock and private
Unix socket under `/run/trafficcop`, and embeds its web assets. No BPF maps are
pinned. Stop releases the XDP link, map/program descriptors, control socket and
HTTP port; SIGTERM/SIGINT also clean up. SIGKILL/crash recovery beyond automatic
FD closure is not yet a tested lifecycle guarantee. Startup diagnostics append
to `/run/trafficcop-bootstrap.log`. The lock file remains as a harmless reusable
inode; do not delete it while a daemon is running.

## Contribute and raise a PR

Use the three implementation issues for ownership and acceptance criteria:

- [Person A: XDP dataplane](https://github.com/TANKominator5/BytecodeBouncer/issues/1)
- [Person B: control plane and reload](https://github.com/TANKominator5/BytecodeBouncer/issues/2)
- [Person C: observability and test bench](https://github.com/TANKominator5/BytecodeBouncer/issues/3)

```sh
git fetch origin
git switch -c feat/<area> origin/main
# implement and test your issue
./build.sh
make test
sudo tests/integration/bootstrap.sh
git add <your-files>
git commit -m "Describe the problem and resulting behavior"
git push -u origin feat/<area>
gh pr create --base main --head feat/<area> --title "Concrete behavior" --body-file /tmp/pr.md
```

In `/tmp/pr.md`, explain behavior, list checks actually run, disclose missing
checks/limitations, call out shared ABI changes, and include `Closes #<issue>`.
Ask the other two people to review. Keep shared-ABI changes small and agreed in
advance. Merge green, reviewed PRs frequently; update your branch from main
before integrating. Each person uses a separate clone/worktree and branch.

## Validation evidence

See [docs/bootstrap-validation.md](docs/bootstrap-validation.md) for actual checks
and platform limitations. CI runs build, unit/race checks, vet and the privileged
namespace smoke test on Ubuntu 24.04. A full-spec benchmark and dashboard
screenshot are still required before submission; no screenshot is fabricated.
