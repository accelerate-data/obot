# VD-4883 Local MCP OAuth Reliability Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make local Studio MCP OAuth use Dynamic Client Registration (DCR), preserve the canonical Studio runtime origin in every MCP session, and make static OAuth catalog mutation and grant cleanup safe under reconciliation races.

**Architecture:** `services.Config.ForceDynamicClient` is propagated into `mcp.SessionManager`, which advertises a Client ID Metadata Document (CIMD) only when the runtime origin is HTTPS and DCR has not been forced. Static OAuth grants remain explicitly owned by their catalog entry and credential generation. Routine static-credential reconciliation deletes only grants with that ownership fence; catalog-entry deletion uses a separate, explicit full-purge operation. Every catalog apply path takes the catalog mutation lock before inspecting removals or mutating entries, keeping catalog reconciliation serialized with static OAuth credential changes.

**Tech Stack:** Go, GORM, controller-runtime/Kubernetes clients, MCP OAuth, OAuth 2.0 DCR/CIMD, SQLite/PostgreSQL-compatible gateway storage

**Spec:** [VD-4883](https://linear.app/acceleratedata/issue/VD-4883/local-studio-rejects-linear-mcp-oauth-with-an-unreachable-client), `/Users/hbanerjee/src/studio/docs/functional/configure-connectors/README.md`, `/Users/hbanerjee/src/studio/docs/design/mcp/mcp-studio-runtime/README.md`, and `/Users/hbanerjee/src/studio/docs/design/mcp/mcp-studio-obot-transport/README.md`

## Global Constraints

- Keep this PR limited to the items under **Put in the current Obot PR (VD-4883)**: runtime client selection, static-grant ownership cleanup, catalog mutation locking, and their regression tests.
- `ForceDynamicClient=true` always selects DCR. A non-HTTPS runtime origin also always selects DCR because a CIMD URL must be publicly reachable over HTTPS. CIMD remains eligible only for an HTTPS origin when DCR is not forced.
- Preserve dynamic and container OAuth grants during routine static-credential reconciliation and static-to-dynamic transitions. Never infer grant ownership from `mcp_id` alone.
- A catalog entry's actual deletion is the only path authorized to purge every local grant for all of that entry's deployment IDs.
- Acquire `system.MCPStaticOAuthCatalogMutationLock` before partial apply, removal reconciliation, or full apply, and hold it until that mutation path finishes.
- Do not include the four broader follow-ups in this PR. They are independently tracked as [VD-4887](https://linear.app/acceleratedata/issue/VD-4887/dynamic-mcp-oauth-token-exchange-bypasses-egress-protections-and), [VD-4888](https://linear.app/acceleratedata/issue/VD-4888/mcp-oauth-callback-states-are-not-atomically-one-use-or-ttl-enforced), [VD-4889](https://linear.app/acceleratedata/issue/VD-4889/multi-user-oauth-token-changes-trigger-the-wrong-reconciliation), and [VD-4890](https://linear.app/acceleratedata/issue/VD-4890/interrupted-static-oauth-credential-tests-remain-falsely-pending).
- Build and manually test a local Obot image before raising the Obot PR. After the Obot PR merges and publishes, update Studio's `package.json` Obot image pin in a separate Studio PR; do not point Studio at an unpublished digest.
- Add each regression test first, observe it fail for the intended reason, then make the smallest production change that passes it.

---

### Task 1: Make MCP session client selection origin-aware

**Files:**
- Modify: `pkg/mcp/manager.go`
- Modify: `pkg/mcp/client.go`
- Modify: `pkg/mcp/client_test.go`
- Modify: `pkg/services/config.go`
- Test: `pkg/mcp/client_test.go`

**Interfaces:**
- Consumes: `services.Config.ForceDynamicClient` and the resolved Obot/Studio runtime origin passed as `baseURL`
- Produces: an empty OAuth client metadata URL for DCR, or `${baseURL}/oauth/client-metadata.json` only for an eligible HTTPS origin

- [x] **Step 1: Extend the failing table test**

Cover all decision branches in `TestSessionManagerClientIDMetadataDocument`:

```go
tests := []struct {
    name               string
    baseURL            string
    forceDynamicClient bool
    want               string
}{
    {name: "https uses CIMD by default", baseURL: "https://studio.example.com", want: "https://studio.example.com/oauth/client-metadata.json"},
    {name: "forced DCR omits CIMD on https", baseURL: "https://studio.example.com", forceDynamicClient: true},
    {name: "http automatically uses DCR", baseURL: "http://host.docker.internal:3000"},
}
```

- [x] **Step 2: Verify RED**

Run:

```bash
go test ./pkg/mcp -run TestSessionManagerClientIDMetadataDocument -count=1
```

Expected: the HTTP-origin case fails because the helper still returns a CIMD URL.

- [x] **Step 3: Implement the complete selection rule**

Keep `forceDynamicClient` on `SessionManager`, pass `config.ForceDynamicClient` from `services.New`, and make the helper parse the runtime origin:

```go
func (sm *SessionManager) clientIDMetadataDocument() string {
    runtimeOrigin, err := url.Parse(sm.baseURL)
    if err != nil || sm.forceDynamicClient || !strings.EqualFold(runtimeOrigin.Scheme, "https") {
        return ""
    }
    return system.OAuthClientIDMetadataURL(sm.baseURL)
}
```

The session must pass this result into `newOAuth`; do not recompute the origin from an MCP server URL or request headers.

- [x] **Step 4: Verify GREEN and constructor coverage**

Run:

```bash
go test ./pkg/mcp ./pkg/services -count=1
```

Expected: the scheme table and every `NewSessionManager` caller compile and pass.

- [x] **Step 5: Commit the session-selection change**

```bash
git add pkg/mcp/manager.go pkg/mcp/client.go pkg/mcp/client_test.go pkg/services/config.go
git commit -m "fix(mcp): select DCR for local session origins"
```

---

### Task 2: Separate static-owned cleanup from catalog-entry purge

**Files:**
- Modify: `pkg/gateway/client/mcpoauthtoken.go`
- Modify: `pkg/gateway/client/mcpoauthtoken_test.go`
- Modify: `pkg/api/handlers/mcpcatalogs.go`
- Modify: `pkg/api/handlers/mcpcatalogs_test.go`
- Modify: `pkg/api/handlers/mcp_oauth_credential_test_test.go`
- Modify: `pkg/controller/handlers/mcpservercatalogentry/mcpservercatalogentry.go`
- Modify: `pkg/controller/handlers/mcpservercatalogentry/mcpservercatalogentry_test.go`
- Test: `pkg/gateway/client/mcpoauthtoken_test.go`
- Test: `pkg/controller/handlers/mcpservercatalogentry/mcpservercatalogentry_test.go`

**Interfaces:**
- `DeleteMCPStaticOAuthCredential(ctx, entryName, reconcileMCPIDs...)` deletes the shared static application, its pending proofs, and only grants whose `catalog_entry_name` equals `entryName`; the separately named IDs are notification targets and never broaden deletion.
- `DeleteMCPStaticOAuthCredentialGeneration(ctx, entryName, expectedGeneration, reconcileMCPIDs...)` applies the same owned-grant scope after verifying the reviewed generation.
- `DeleteMCPStaticOAuthStateForDeletedCatalogEntry(ctx, entryName, deploymentIDs...)` is the explicit destructive boundary used only after the catalog entry itself is being deleted; it removes owned grants plus every grant for the supplied deployments.

- [x] **Step 1: Add failing gateway ownership tests**

Add fixtures for the same deployment ID containing:

```go
[]gwtypes.MCPOAuthToken{
    {MCPID: "server-1", UserID: "static-user", CatalogEntryName: "entry-1", CatalogCredentialGeneration: "generation-1"},
    {MCPID: "server-1", UserID: "dynamic-user"},
    {MCPID: "instance-1", UserID: "container-user"},
}
```

Assert:

- routine cleanup with no credential deletes the fenced `entry-1` row and preserves the unfenced dynamic/container rows;
- credential replacement and generation-checked clear delete only `entry-1` rows, even if dynamic authorization completes concurrently for the same `mcp_id`;
- the explicit deleted-entry purge removes all grants for `server-1` and `instance-1`;
- grants for another catalog entry and unrelated deployment IDs always survive;
- notifications contain exactly the MCP IDs whose rows changed.

- [x] **Step 2: Verify RED**

Run:

```bash
go test ./pkg/gateway/client -run 'Test(Delete|Replace)MCPStaticOAuth' -count=1
```

Expected: routine cleanup or replacement deletes an unfenced grant because `deleteMCPStaticOAuthTokens` broadens its query with `mcp_id IN ?`.

- [x] **Step 3: Implement explicit cleanup scopes**

Remove deployment IDs from the routine deletion predicate. Keep the routine SQL ownership-based and carry separately named `reconcileMCPIDs` only so a post-commit notification failure remains retryable:

```go
owned := tx.Model(&types.MCPOAuthToken{}).
    Where("catalog_entry_name = ?", entryName)
```

Do not add `mcp_id` as an `OR` predicate on this path. Unfenced rows are not provably static-owned and must survive routine reconciliation and transitions.

Add a separate deleted-entry helper whose name and signature make the full purge explicit:

```go
func (c *Client) DeleteMCPStaticOAuthStateForDeletedCatalogEntry(
    ctx context.Context,
    entryName string,
    deploymentIDs ...string,
) (bool, error)
```

Inside one transaction, delete the credential and pending static tests, then delete grants matching `catalog_entry_name = entryName OR mcp_id IN deploymentIDs`. Trigger reconciliation only after commit.

- [x] **Step 4: Route controller paths by lifecycle intent**

- `CleanupUnusedOAuthCredential` calls ownership-only `DeleteMCPStaticOAuthCredential` while holding both catalog and credential locks.
- static credential replacement and generation-checked clear call the ownership-only APIs.
- `RemoveOAuthCredentials`, which runs for actual catalog-entry deletion, resolves the server and instance deployment IDs and calls `DeleteMCPStaticOAuthStateForDeletedCatalogEntry`.

Add controller tests proving a static-to-dynamic transition preserves the new dynamic grant and actual entry deletion performs the full purge.

- [x] **Step 5: Verify GREEN**

Run:

```bash
go test ./pkg/gateway/client ./pkg/controller/handlers/mcpservercatalogentry -count=1
```

Expected: every ownership, generation, transition, deletion, and notification assertion passes.

- [x] **Step 6: Commit the ownership change**

```bash
git add pkg/gateway/client/mcpoauthtoken.go pkg/gateway/client/mcpoauthtoken_test.go pkg/controller/handlers/mcpservercatalogentry/mcpservercatalogentry.go pkg/controller/handlers/mcpservercatalogentry/mcpservercatalogentry_test.go
git commit -m "fix(mcp): preserve non-static grants during catalog cleanup"
```

---

### Task 3: Serialize every catalog apply path with static OAuth mutation

**Files:**
- Modify: `pkg/controller/handlers/mcpcatalog/mcpcatalog.go`
- Modify: `pkg/controller/handlers/mcpcatalog/mcpcatalog_sync_test.go`
- Test: `pkg/controller/handlers/mcpcatalog/mcpcatalog_sync_test.go`
- Test: `pkg/controller/handlers/mcpcatalog/catalog_removal_test.go`

**Interfaces:**
- Consumes: `system.MCPStaticOAuthCatalogMutationLock`
- Produces: one serialized critical section covering partial apply, removed-entry reconciliation, and complete apply

- [x] **Step 1: Add failing lock-order tests**

Use a held credential lock and a second handler/client to prove:

- a partial sync with source errors does not call `app.Apply` before the lock is released;
- a clean sync does not call `reconcileRemovedEntries` before the lock is released;
- removal reconciliation and the following apply happen within the same acquired critical section;
- cancellation while waiting returns without mutating catalog entries.

- [x] **Step 2: Verify RED**

Run:

```bash
go test ./pkg/controller/handlers/mcpcatalog -run 'Test.*Catalog.*MutationLock' -count=1
```

Expected: partial apply and removed-entry reconciliation are observed before the lock is acquired.

- [x] **Step 3: Move the lock to the mutation boundary**

Acquire the lock immediately after constructing the no-prune apply set and before branching on `SyncErrors`:

```go
releaseCatalogMutationLock, err := h.gatewayClient.AcquireCredentialLock(
    req.Ctx,
    system.MCPStaticOAuthCatalogMutationLock,
)
if err != nil {
    return fmt.Errorf("failed to coordinate catalog sync with static OAuth: %w", err)
}
defer releaseCatalogMutationLock()

if len(mcpCatalog.Status.SyncErrors) > 0 {
    return app.Apply(req.Ctx, mcpCatalog, toAdd...)
}
if err := reconcileRemovedEntries(req.Ctx, req.Client, mcpCatalog, toAdd); err != nil {
    return err
}
return app.Apply(req.Ctx, mcpCatalog, toAdd...)
```

Keep source reads, conflict filtering, and status updates outside the critical section; only catalog mutation and the state inspection that decides removals belong inside it.

- [x] **Step 4: Verify GREEN**

Run:

```bash
go test ./pkg/controller/handlers/mcpcatalog -count=1
```

Expected: lock-order tests and existing partial-sync/removal tests pass.

- [x] **Step 5: Commit the serialization change**

```bash
git add pkg/controller/handlers/mcpcatalog/mcpcatalog.go pkg/controller/handlers/mcpcatalog/mcpcatalog_sync_test.go pkg/controller/handlers/mcpcatalog/catalog_removal_test.go
git commit -m "fix(mcp): serialize catalog apply with oauth mutation"
```

---

### Task 4: Run the Obot regression and repository gates

**Files:**
- Verify all files changed by Tasks 1-3

**Interfaces:**
- Consumes: the final branch diff against `origin/main`
- Produces: focused race evidence, full package evidence, formatting, generated-code consistency, and a clean diff

- [x] **Step 1: Format and inspect the complete diff**

```bash
gofmt -w pkg/mcp/manager.go pkg/mcp/client.go pkg/mcp/client_test.go pkg/services/config.go pkg/gateway/client/mcpoauthtoken.go pkg/gateway/client/mcpoauthtoken_test.go pkg/controller/handlers/mcpservercatalogentry/mcpservercatalogentry.go pkg/controller/handlers/mcpservercatalogentry/mcpservercatalogentry_test.go pkg/controller/handlers/mcpcatalog/mcpcatalog.go pkg/controller/handlers/mcpcatalog/mcpcatalog_sync_test.go pkg/api/handlers/mcpcatalogs.go pkg/api/handlers/mcpcatalogs_test.go pkg/api/handlers/mcp_oauth_credential_test_test.go
git diff --check
git diff --stat origin/main...HEAD
```

- [x] **Step 2: Run focused race coverage**

```bash
go test -race ./pkg/gateway/client -run 'Test(Delete|Replace)MCPStaticOAuth' -count=1
go test -race ./pkg/controller/handlers/mcpservercatalogentry -run 'Test.*OAuth' -count=1
go test -race ./pkg/controller/handlers/mcpcatalog -run 'Test.*(MutationLock|Partial|Removal)' -count=1
go test -race ./pkg/mcp -run TestSessionManagerClientIDMetadataDocument -count=1
```

Do not dismiss a race as environmental. If a broader package race run reaches a pre-existing unrelated test, record the exact test and still keep the changed-path race tests green.

- [x] **Step 3: Run the package and repository gates**

```bash
go test ./pkg/gateway/client ./pkg/controller/handlers/mcpservercatalogentry ./pkg/controller/handlers/mcpcatalog ./pkg/mcp ./pkg/services -count=1
PATH="$(go env GOPATH)/bin:$PATH" make validate-go-code
make test
git diff --check
```

Expected: all commands exit 0. Investigate the first causal failure rather than weakening assertions or changing timeouts.

- [x] **Step 4: Audit the final scope**

```bash
git diff --name-only origin/main...HEAD
git grep -n 'DeleteMCPStaticOAuthCredential\|DeleteMCPStaticOAuthStateForDeletedCatalogEntry'
git grep -n 'NewSessionManager('
```

Confirm every caller uses the intended cleanup scope, every session receives the resolved runtime-origin contract, and no code for VD-4887 through VD-4890 entered the diff.

---

### Task 5: Build a local Obot image and manually verify Studio

**Files:**
- Verify: the local Obot worktree and Studio runtime configuration
- Later, in a separate Studio PR: `package.json` and generated Obot image projections required by Studio's image-pin workflow

**Interfaces:**
- Consumes: the committed Obot branch image and Studio's product `OBOT_IMAGE` override
- Produces: manual proof that local HTTP Studio uses DCR and Linear OAuth remains connected after callback and refresh

- [x] **Step 1: Build the local Obot image**

Build the worktree with the same Dockerfile used by the repository's image workflow and record the source SHA and image ID in the test notes:

```bash
docker build -t obot:vd-4883-local .
git rev-parse HEAD
docker image inspect obot:vd-4883-local --format '{{.Id}}'
```

- [x] **Step 2: Launch Studio against the local image**

Set Studio's supported product override:

```bash
OBOT_IMAGE=obot:vd-4883-local
```

Keep `OBOT_INTERNAL_BASE_URL` and `AGENT_TO_STUDIO_BASE_URL` set to the canonical runtime-origin contract used by the worktree launcher.

- [x] **Step 3: Verify the user flow**

1. Open User Settings -> MCP Servers.
2. Start Linear OAuth from a local HTTP Studio origin.
3. Confirm the provider accepts the dynamically registered client.
4. Complete the callback and return to Studio.
5. Refresh the MCP Servers page and confirm Linear remains connected.
6. Disconnect and reconnect once to exercise cleanup and recreation.
7. Run a catalog refresh and confirm it does not report synchronization errors caused by credential cleanup.

- [x] **Step 4: Prepare the Obot PR handoff**

Record focused tests, repository gates, local image ID, manual steps, and the four explicitly deferred Linear issues. Raise the Obot PR only after review and all local checks pass.

- [ ] **Step 5: Advance Studio only after Obot publication**

After the Obot PR merges and its image is published, update Studio's `package.json` Obot image pin through the normal generated image-projection workflow, run Studio's required local gate, and raise a separate Studio PR referencing VD-4883 and the merged Obot PR.
