#!/usr/bin/env bash
# Fails when a fork-only Go test present on the base commit is missing from HEAD.
#
# An upstream sync resolves conflicts by taking upstream's side of a shared test
# file, which deletes the fork's tests in it without any compile or test failure.
# The v0.26.0 sync dropped fork security guarantees together with their tests
# that way (VD-6903). This check makes such a removal visible.
#
# A fork-only test is a `func Test…` that exists on BASE but not on the upstream
# commit BASE was last synced to (upstreamHeadSha in BASE's
# .accelerate/upstream-sync.json). Tests are identified by package directory and
# name, so moving a test to another file in the same directory is not a removal.
# Upstream deleting its own tests is not flagged.
#
# A deliberate removal is recorded in .accelerate/fork-test-removals.txt as
#   <package dir> <TestName> <reason>
#
# Usage: bash scripts/check-fork-test-survival.sh [BASE]   (default origin/main)
# The upstream commit named by BASE's metadata must be available locally; CI
# fetches the upstream branch before running this.

set -euo pipefail

BASE="${1:-origin/main}"
META=".accelerate/upstream-sync.json"
ALLOW=".accelerate/fork-test-removals.txt"

fail() {
  echo "::error::$*" >&2
  echo "FAIL: $*"
  exit 1
}

git cat-file -e "${BASE}^{commit}" 2>/dev/null || fail "base '${BASE}' is not available locally"

UPSTREAM="$(git show "${BASE}:${META}" 2>/dev/null | jq -r '.upstreamHeadSha // empty' || true)"
[ -n "$UPSTREAM" ] || fail "${META} on ${BASE} records no upstreamHeadSha"
git cat-file -e "${UPSTREAM}^{commit}" 2>/dev/null \
  || fail "upstream commit ${UPSTREAM} (from ${META} on ${BASE}) is not available locally; fetch the upstream branch"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# Prints "<package dir> <TestName>" for every top-level Go test on a commit.
list_tests() {
  git grep -E '^func Test[A-Za-z0-9_]*\(' "$1" -- '*_test.go' 2>/dev/null \
    | sed -E 's#^[^:]+:(.*)/[^/]+_test\.go:func (Test[A-Za-z0-9_]*)\(.*#\1 \2#; s#^[^:]+:[^/]+_test\.go:func (Test[A-Za-z0-9_]*)\(.*#. \1#' \
    | sort -u
}

list_tests "$BASE" > "$WORK/base"
list_tests HEAD > "$WORK/head"
list_tests "$UPSTREAM" > "$WORK/upstream"

touch "$WORK/allowed"
if [ -f "$ALLOW" ]; then
  while read -r dir name reason || [ -n "$dir" ]; do
    case "$dir" in '' | '#'*) continue ;; esac
    [ -n "$name" ] && [ -n "$reason" ] \
      || fail "${ALLOW}: entry '${dir} ${name}' needs a package dir, a test name and a reason"
    echo "$dir $name" >> "$WORK/allowed"
  done < "$ALLOW"
  sort -u -o "$WORK/allowed" "$WORK/allowed"
fi

comm -23 "$WORK/base" "$WORK/head" \
  | comm -23 - "$WORK/upstream" \
  | comm -23 - "$WORK/allowed" > "$WORK/dropped"

if [ -s "$WORK/dropped" ]; then
  echo "Fork-only tests present on ${BASE} are missing from HEAD:"
  sed 's/^/  /' "$WORK/dropped"
  fail "$(wc -l < "$WORK/dropped" | tr -d ' ') fork-only test(s) were removed. Restore them (in a fork-only *_claim_test.go file so the next sync cannot drop them) or record each deliberate removal in ${ALLOW}."
fi

echo "OK: every fork-only test on ${BASE} survives on HEAD (upstream base ${UPSTREAM:0:12})"
