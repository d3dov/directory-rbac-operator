#!/usr/bin/env bash
# Enforces per-package test coverage thresholds across the packages that
# hold this operator's business logic. Deliberately not gated here at all:
# main.go (wiring, no branching logic of its own), api/v1alpha1 (types plus
# generated zz_generated.deepcopy.go - see `make generate`), and
# internal/version (a single build-time-injected var, nothing to branch on).
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

# "package:minimum required coverage percentage" (integer, truncated). A
# plain list rather than an associative array so this also runs under the
# bash 3.2 macOS ships (declare -A needs bash 4+).
THRESHOLDS=(
	"internal/controller:90"
	"internal/ldapclient:100"
	"internal/ldapclient/fake:100"
	"internal/rbacsync:100"
	"internal/metrics:100"
)
# internal/webhook joins this list once it exists.

status=0
for entry in "${THRESHOLDS[@]}"; do
	pkg="${entry%%:*}"
	want="${entry##*:}"
	profile="$(mktemp)"
	go test "./${pkg}/..." -coverprofile="$profile" -covermode=atomic >/dev/null
	got="$(go tool cover -func="$profile" | tail -1 | grep -oE '[0-9]+\.[0-9]+')"
	rm -f "$profile"
	got_int="${got%.*}"

	if [ "$got_int" -lt "$want" ]; then
		echo "FAIL: $pkg coverage ${got}% is below the required ${want}%"
		status=1
	else
		echo "OK:   $pkg coverage ${got}% >= required ${want}%"
	fi
done

if [ "$status" -ne 0 ]; then
	cat <<'EOF'

internal/controller's threshold is intentionally below 100%: the remaining
gap is defensive branches where the Kubernetes API server itself fails on
Get/Create/Update/Delete/Status().Update, or an owner-reference conflict
that isn't reachable through this reconciler's own call pattern. Reaching
those deterministically needs a purpose-built error-injecting fake client,
tracked as follow-up rather than done here. Every other branch - including
every fail-safe status-condition path - is covered.
EOF
fi

exit $status
