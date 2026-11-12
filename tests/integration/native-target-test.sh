#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
. tests/integration/native-target.sh

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
# Override only the detector; test missing command separately below.
cat > "$tmp/systemd-detect-virt" <<'MOCK'
#!/usr/bin/env bash
printf '%s\n' "$DETECT_RESULT"
exit "$DETECT_STATUS"
MOCK
chmod +x "$tmp/systemd-detect-virt"
original_path=$PATH
export PATH="$tmp:$PATH"
check() {
    local result=$1 status=$2 expected=$3
    export DETECT_RESULT=$result DETECT_STATUS=$status
    if is_native_target 2>/dev/null; then actual=accept; else actual=reject; fi
    [[ $actual == "$expected" ]] || { echo "detector $result/$status: expected $expected, got $actual" >&2; exit 1; }
}
check none 1 accept
check none 0 reject
check none 2 reject
check '' 1 reject
check error 1 reject
check error 2 reject
for result in docker podman lxc systemd-nspawn unknown-container kvm qemu vmware oracle microsoft wsl uml; do
    check "$result" 0 reject
done
rm "$tmp/systemd-detect-virt"
# A PATH without the detector simulates a missing installation.
PATH=$tmp
if is_native_target 2>/dev/null; then echo 'missing detector accepted' >&2; exit 1; fi
PATH=$original_path
echo 'native target detector tests passed'
