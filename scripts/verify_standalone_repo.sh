#!/usr/bin/env bash

set -euo pipefail

repo_root="$(cd "$(dirname "$0")/../../.." && pwd)"

"$repo_root/scripts/public_repo_mirror.sh" verify ex_openid4vc "${1:-}"
