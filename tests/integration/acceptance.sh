#!/usr/bin/env bash
# Run from a fresh checkout on the target, after installing documented deps.
# --local explicitly records a non-target run; it must not be called acceptance.
set -euo pipefail
cd "$(dirname "$0")/../.."
mode=${1:---require-target}
[[ $mode == --require-target || $mode == --local ]] || { echo 'usage: acceptance.sh [--require-target|--local]' >&2; exit 1; }
[[ $EUID == 0 ]] || { echo 'run with sudo, preserving Go in PATH' >&2; exit 1; }
[[ ! -S /run/trafficcop/control.sock ]] || { echo 'trafficcop running; refusing acceptance suite' >&2; exit 1; }
if [[ $mode == --require-target ]]; then
    . /etc/os-release
    kernel=$(uname -r)
    . tests/integration/native-target.sh
    [[ $ID == ubuntu && $VERSION_ID == 24.04 && $(uname -m) == x86_64 && $kernel == 6.8.* && $kernel != *microsoft* && $kernel != *WSL* ]] &&
        is_native_target || {
        echo 'target required: native Ubuntu 24.04 / Linux 6.8 / x86-64; this environment does not qualify (use --local for explicitly non-target evidence)' >&2; exit 1;
    }
    (( $(nproc) >= 4 )) || { echo 'target acceptance requires four allowed CPUs' >&2; exit 1; }
fi
# Trust only this process's chosen checkout for root builds; no global git edits.
export GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=safe.directory GIT_CONFIG_VALUE_0="$PWD"
if [[ $mode == --require-target && -n $(git status --porcelain) ]]; then
    echo 'target acceptance requires a clean fresh checkout; refusing to discard changes' >&2; exit 1;
fi
if [[ -n ${TC_EVIDENCE_DIR:-} ]]; then
    out=$TC_EVIDENCE_DIR
    mkdir "$out" || { echo 'evidence directory must not already exist' >&2; exit 1; }
else
    out=$(mktemp -d)
fi
python3 - "$mode" > "$out/platform.json" <<'PY'
import json,os,platform,shutil,subprocess,sys
def command(*args):return subprocess.check_output(args,text=True).strip()
print(json.dumps(dict(mode=sys.argv[1],kernel=platform.release(),machine=platform.machine(),
                     os_release=open('/etc/os-release').read(),cpus=sorted(os.sched_getaffinity(0)),
                     commit=command('git','rev-parse','HEAD'),dirty=command('git','status','--porcelain'),
                     virtualization=(subprocess.run(['systemd-detect-virt'],capture_output=True,text=True).stdout.strip() if shutil.which('systemd-detect-virt') else 'unavailable'),
                     go=command('go','version'),clang=command('clang','--version')),indent=2))
PY
echo "Evidence directory: $out"
stage() { local name=$1; shift; "$@" 2>&1 | tee "$out/$name.log"; }
stage build bash ./build.sh
stage unit make test
stage bootstrap bash tests/integration/bootstrap.sh
stage demo bash tests/integration/demo.sh
stage firewall bash tests/integration/firewall.sh
stage lifecycle bash tests/integration/lifecycle.sh
stage kernel env TC_BPF_TEST=1 go test -count=1 -v ./internal/dataplane
stage wire bash bpf/netns-test.sh
stage capacity env TC_BPF_TEST=1 TC_BPF_CAPACITY=1 go test -count=1 -v ./internal/dataplane -run TestKernelFull
stage command-capacity bash tests/integration/command-capacity.sh
stage reclamation env TC_BPF_TEST=1 TC_BPF_ENDURANCE=1 go test -count=1 -v ./internal/dataplane -run TestKernelRetiredGenerationObjects
stage endurance bash tests/integration/endurance.sh
stage veth-throughput bash tests/integration/throughput.sh
printf '%s\n' "PASS: all stages; mode=$mode; private-veth benchmark is not physical-NIC evidence" | tee "$out/result.txt"
