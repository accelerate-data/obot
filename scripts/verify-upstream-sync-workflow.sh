#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
sync_workflow="${repo_root}/.github/workflows/upstream-sync.yml"
verify_workflow="${repo_root}/.github/workflows/verify-sync-metadata.yml"
publish_workflow="${repo_root}/.github/workflows/build-vibedata-image.yml"
publish_script="${repo_root}/scripts/build-vibedata-image.sh"

require_literal() {
  local file="$1"
  local value="$2"
  local message="$3"
  if ! grep -Fq -- "${value}" "${file}"; then
    echo "${message}" >&2
    exit 1
  fi
}

literal_line() {
  local file="$1"
  local value="$2"
  local message="$3"
  local match
  match="$(grep -nF -- "${value}" "${file}" || true)"
  if [ -z "${match}" ]; then
    echo "${message}" >&2
    exit 1
  fi
  match="${match%%:*}"
  printf '%s\n' "${match}"
}

require_literal "${sync_workflow}" "issues: write" "Upstream sync must be allowed to create labels"
for label in upstream-sync sync:clean sync:touches-customized-files sync:conflicts; do
  require_literal "${sync_workflow}" "gh label create \"${label}\"" "Upstream sync must create ${label}"
done
require_literal "${sync_workflow}" "--force" "Upstream sync label creation must be idempotent"
require_literal "${sync_workflow}" "upstreamObotVersion" "Sync metadata must record the stable upstream version"
require_literal "${sync_workflow}" "RECORDED_HEAD=\"\$(jq -r '.upstreamHeadSha" "Sync analysis must prefer the recorded upstream checkpoint"
require_literal "${sync_workflow}" "--max-count=50" "Upstream commit summaries must use git's max-count option"
if grep -Eq 'head[[:space:]]+-?50' "${sync_workflow}"; then
  echo "Upstream commit summaries must not pipe into head under pipefail" >&2
  exit 1
fi
require_literal "${sync_workflow}" 'echo "git fetch origin \"${BRANCH}\""' "Conflict handoff must fetch the sync branch"
require_literal "${sync_workflow}" 'echo "git switch -C \"${BRANCH}\" \"origin/${BRANCH}\""' "Conflict handoff must check out the exact sync branch"
require_literal "${sync_workflow}" 'echo "git merge --no-ff \"upstream/${UPSTREAM_BRANCH}\""' "Conflict handoff must merge upstream explicitly"

require_literal "${verify_workflow}" 'git fetch upstream "$UPSTREAM_BRANCH" --tags' "Metadata verification must fetch the upstream branch and tags"
require_literal "${publish_workflow}" "bash scripts/build-vibedata-image.sh" "Publication must use the version resolver"
require_literal "${publish_script}" "jq -r '.upstreamObotVersion" "Publication must resolve its version from sync metadata"
require_literal "${publish_script}" '${UPSTREAM_VERSION}-vibedata' "Publication must create versioned image tags"

consumer_tags_line="$(literal_line "${publish_workflow}" '-t "${IMAGE}:${VERSIONED_TAG}"' "Publication must assign the versioned consumer tag")"
architecture_verification_line="$(literal_line "${publish_workflow}" "grep -q 'linux/amd64'" "Publication must verify the staging manifest architecture")"
signing_line="$(literal_line "${publish_workflow}" 'cosign sign --yes' "Publication must sign the staging manifest digest")"
if [ "${consumer_tags_line}" -le "${architecture_verification_line}" ] || [ "${consumer_tags_line}" -le "${signing_line}" ]; then
  echo "Consumer tags must advance only after architecture verification and signing" >&2
  exit 1
fi

require_literal "${publish_workflow}" 'STAGING_TAG: build-${{ github.run_id }}-${{ github.run_attempt }}' "Publication must use a run-scoped staging tag"
require_literal "${publish_workflow}" 'cosign sign --yes "${IMAGE}@${DIGEST}"' "Publication must sign the immutable digest exactly once"
if [ "$(grep -Fc -- 'cosign sign --yes' "${publish_workflow}")" -ne 1 ]; then
  echo "Publication must issue exactly one cosign signature for the immutable digest" >&2
  exit 1
fi

echo "Upstream sync, metadata, and publication workflow contracts are valid"
