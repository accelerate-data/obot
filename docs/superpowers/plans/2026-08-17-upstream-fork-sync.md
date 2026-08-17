# Obot Upstream Fork Sync Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Synchronize `accelerate-data/obot` with `obot-platform/obot` at `a71bd40c8db565885c1012871d75aa77913d724c`, retain the net Accelerate behavior, merge PR #45 with upstream ancestry, and verify the stable `v0.25.1` publication.

**Architecture:** Reconstruct the existing PR branch from upstream `main` and apply the net fork delta from the actual upstream parent used by PR #31, `887fc6af10f091c71ed88e616e362e2792f4d1b7`. Resolve the 22 conflicting paths by treating upstream as canonical and preserving only unique Accelerate behavior. Update the existing remote branch with force-with-lease and merge through protected `main` with a merge commit after providers publication succeeds.

**Tech Stack:** Git, GitHub Actions, Bash, Go 1.26, SvelteKit, pnpm, Docker Buildx, Helm

**Spec:** `docs/adr/0001-upstream-fork-synchronization.md`

## Global Constraints

- Providers publication for stable `v0.25.1` must succeed before Obot reconciliation begins.
- Upstream is canonical when it provides equivalent behavior.
- Exclude historical sync commits and `.accelerate/upstream-sync.json` from the replayed fork delta.
- Preserve undocumented unique behavior and flag it in PR #45.
- Record `a71bd40c8db565885c1012871d75aa77913d724c` as upstream head and `v0.25.1` as the stable version.
- Never force-push fork `main`; update only `sync/upstream-20260817-a71bd40` with force-with-lease.
- Merge PR #45 with a merge commit after all local and GitHub gates pass.
- Repair publication failures forward.

---

### Task 1: Rebuild the Obot sync branch and apply the net fork delta

**Files:**
- Create: `docs/adr/0001-upstream-fork-synchronization.md`
- Create: `docs/superpowers/plans/2026-08-17-upstream-fork-sync.md`
- Modify: `.accelerate/upstream-sync.json`
- Retain net fork files from `887fc6af10f091c71ed88e616e362e2792f4d1b7..origin/main`

**Interfaces:**
- Consumes: `upstream/main=a71bd40c8db565885c1012871d75aa77913d724c`, `origin/main=8e74b46ecc5a86da45847d5748943b0c7371dc59`, and PR #31 head `d9e6b82de3e2e171361dce8347c9bc1e78143e82`
- Produces: local `sync/upstream-20260817-a71bd40` based on current upstream with the net fork delta applied

- [ ] **Step 1: Verify provenance**

Fetch `origin`, `upstream`, tags, and `pull/31/head`; prove PR #31's actual upstream parent and tree equivalence to squash commit `83d4c0c53df338005cc36928a456cc774a5724f0`.

- [ ] **Step 2: Rebuild the temporary branch**

After preserving the ADR and plan commit, switch the worktree to a new branch at `upstream/main`. Apply the net diff from `887fc6af10f091c71ed88e616e362e2792f4d1b7` to `origin/main`, excluding `.accelerate/upstream-sync.json`, one path at a time so successful paths remain staged and conflicting paths remain explicit.

- [ ] **Step 3: Reconcile the exact conflict inventory**

Resolve these groups:

- Required-check workflows: `.github/workflows/go.yml`, `test-docker-build.yml`, and `user-ui.yml` retain required context names and Accelerate publication boundaries while adopting upstream action/runtime changes.
- Generated dependency files: resolve `go.sum`, `ui/user/package.json`, and `ui/user/pnpm-lock.yaml` from the reconciled manifests, then regenerate with `go mod tidy` and `pnpm install --frozen-lockfile=false` followed by the frozen verification command.
- MCP OAuth/gateway behavior: reconcile the handler, token, gateway, and client conflicts by using upstream APIs while retaining tested Studio JWT translation, base-path audience, user OAuth instance, and static OAuth behavior.
- Catalog behavior: retain the Accelerate default catalog source and migration while adopting upstream catalog synchronization and validation behavior.
- Removed files: do not restore `pkg/api/handlers/mcpgateway/tokenstore.go` or `pkg/mcp/loader_test.go`; port any still-unique assertions to their current upstream owners.
- Generated OpenAPI: regenerate `pkg/storage/openapi/generated/openapi_generated.go` from the reconciled source definitions.

- [ ] **Step 4: Write current metadata and grouped commits**

Set exact upstream SHA, actual merge base, stable version `v0.25.1`, branch, and UTC timestamp. Commit retained changes by release/CI, auth, MCP gateway/catalog, chart/runtime, UI, and documentation concerns.

### Task 2: Make Obot upstream-sync automation self-contained

**Files:**
- Create: `scripts/verify-upstream-sync-workflow.sh`
- Modify: `.github/workflows/upstream-sync.yml`
- Modify: `.github/workflows/verify-sync-metadata.yml`

**Interfaces:**
- Consumes: GitHub token permissions and repository labels
- Produces: required-label bootstrap, safe log generation, exact conflict handoff, and metadata-parent consistency checks under required context `verify`

- [ ] **Step 1: Add the failing contract test**

Assert `issues: write`, all four required labels created with `gh label create --force`, `git log --max-count=50`, no `git log | head`, conflict PR checkout/merge instructions, and verification that metadata `upstreamHeadSha` matches the upstream parent incorporated by the resolved branch.

- [ ] **Step 2: Verify RED**

Run `bash scripts/verify-upstream-sync-workflow.sh` and confirm it fails on missing permission/label bootstrap and incomplete conflict handoff.

- [ ] **Step 3: Implement the minimal workflow repair**

Add `issues: write`, bootstrap labels, replace unsafe pipelines, include exact conflict-resolution commands, and run the structural verifier from the existing `verify` workflow.

- [ ] **Step 4: Verify GREEN**

Run both sync verification scripts and the focused workflow checks; commit as `fix(ci): make Obot upstream sync self-contained`.

### Task 3: Verify retained fork behavior

**Files:**
- Test existing or ported tests adjacent to each retained product behavior
- Verify release workflows and metadata scripts

**Interfaces:**
- Consumes: reconciled source tree
- Produces: automated evidence for every retained fork behavior

- [ ] **Step 1: Run focused tests while resolving each product group**

Use package-level Go tests for auth, MCP gateway/catalog, controller, gateway client, and MCP manager changes. Run focused Svelte checks for modified UI services/components.

- [ ] **Step 2: Run the complete local gate**

Run:

```bash
make build
PATH="$(go env GOPATH)/bin:$PATH" make validate-go-code
make test
bash scripts/verify-sync-metadata.sh
cd ui/user && pnpm install --frozen-lockfile && pnpm run ci
```

Expected: all commands exit 0 and `git diff --check` is clean.

### Task 4: Publish, review, merge, and verify Obot

**Files:**
- Modify: PR #45 title/body/branch
- Verify: `.accelerate/upstream-sync.json`

**Interfaces:**
- Consumes: verified providers publication and fully verified Obot sync branch
- Produces: merged `origin/main` containing upstream `a71bd40`, passing Obot publication, and stable version `v0.25.1`

- [ ] **Step 1: Publish with an exact lease**

Read the live remote branch SHA and push with force-with-lease against `d06bb2e9ddee7776b6f66f11c4129b8c0dd14ef6` if unchanged.

- [ ] **Step 2: Update and ready PR #45**

Document retained behavior, upstream-equivalent code dropped, flagged unproven behavior, exact conflict resolutions, validation evidence, upstream SHA, and stable version. Mark ready and wait for `lint-go`, `test`, and `verify`.

- [ ] **Step 3: Merge with a merge commit**

Run `gh pr merge 45 --repo accelerate-data/obot --merge --delete-branch=false` only after all checks pass.

- [ ] **Step 4: Verify source and publication**

Fetch `origin/main`; prove `upstream/main` is an ancestor; verify metadata and highest merged stable tag; wait for `Build and Push obot-vibedata`; and confirm `latest` and `v0.25.1-vibedata` resolve to the synchronized source and both architectures.
