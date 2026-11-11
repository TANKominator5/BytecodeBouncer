#!/usr/bin/env bash
# Same owned-namespace checks, with consequential duration and maximum reloads.
set -euo pipefail
cd "$(dirname "$0")/../.."
export TC_STRESS_SECONDS=${TC_STRESS_SECONDS:-300}
export TC_STRESS_RELOADS=${TC_STRESS_RELOADS:-100}
export TC_STRESS_LIMIT_RELOADS=${TC_STRESS_LIMIT_RELOADS:-10}
exec bash tests/integration/stress.sh
