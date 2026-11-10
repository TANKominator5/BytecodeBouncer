#!/usr/bin/env bash
# No interface attachment: native parser tests, then opt-in BPF test-run fixtures.
set -euo pipefail
cd "$(dirname "$0")/.."
tmp=$(mktemp -d)
trap 'rm -f "$tmp/parser"; rmdir "$tmp"' EXIT
"${CLANG:-/usr/bin/clang}" -O2 -g -Wall -Werror -fsanitize=address,undefined -Iinclude -Ibpf bpf/tests/parser.c -o "$tmp/parser"
"$tmp/parser"
if [[ ${1:-} == --kernel ]]; then
    [[ $EUID == 0 ]] || { echo 'kernel tests require root' >&2; exit 1; }
    TC_BPF_TEST=1 go test -count=1 -v ./internal/dataplane
elif [[ $# != 0 ]]; then
    echo 'usage: bpf/test.sh [--kernel]' >&2
    exit 1
fi
