#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
# Network access is needed for apt and the pinned Go module downloads.
if [[ ${1:-} == --install-deps ]]; then
  privilege=()
  if [[ $EUID -ne 0 ]]; then privilege=(sudo); fi
  "${privilege[@]}" apt-get update
  "${privilege[@]}" apt-get install -y clang llvm libbpf-dev linux-libc-dev gcc make golang-go iproute2 python3 ca-certificates git
elif [[ $# -ne 0 ]]; then
  echo 'usage: ./build.sh [--install-deps]' >&2
  exit 1
fi
for tool in /usr/bin/clang gcc make go; do
  command -v "$tool" >/dev/null || { echo "missing $tool; run ./build.sh --install-deps" >&2; exit 1; }
done
make all
