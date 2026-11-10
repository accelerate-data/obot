# VD-7318: a shared vMCP connect exposes its ready components

- **Linear:** [VD-7318](https://linear.app/acceleratedata/issue/VD-7318/shared-vmcp-connect-fails-entirely-when-any-granted-component-is-mid)
- **Repo:** `accelerate-data/obot` (this repository). Studio's share of VD-7318 is an image digest
  bump and removing five `it.fails` quarantines; it is out of scope here and stacks on VD-7177.
- **Branch:** `fix/vd-7318-vmcp-partial-connect`, based on `origin/main`.

## Problem

`serverConfigForVMCP` (`pkg/mcp/vmcp.go:36-211`) builds the aggregate for every vMCP connection. It
is the single entry point for both the agent-session path
(`pkg/api/handlers/mcpgateway/handler.go:558`) and the action/consent path
(`pkg/mcp/action.go:121`).

It resolves components as one all-or-nothing unit:

1. `configuredComponents` comes from `EnabledComponents` (`pkg/vmcp/profiles.go:110`), which filters on
   profile grants only. A granted component the user has never configured is included.
2. Three sequential `wait.ForList` phases resolve shared component servers, per-instance component
   servers, then per-user connections. Each waits up to 2 minutes by default (`pkg/wait/waitfor.go`,
   `completeListOptions`).
3. Any phase that times out returns `ServerConfig{}, err` and discards `serversByComponent` and
   `connections`, which by then already hold every healthy component resolved earlier.
4. `Components` is assembled only after all three phases succeed.

One component that cannot reach the synced state the waits require therefore removes every component
from the aggregate. A vMCP is documented as deciding deployment mode per component ("Obot makes this
decision independently for every component", `docs/docs/mcp-gateway/server-types.md:104`), so
all-or-nothing connect is an implementation artifact, not a documented contract.

**The phase that stalls depends on the component's configuration kind**, and the fix must cover all
three:

- user-allowed **non-header** input missing (the VD-7213 case) → the component is a dedicated per-user
  deployment, whose `MCPServer` never reports the synced hashes → `instanceComponents` wait stalls;
- user-allowed **header** only → the component is shared; a missing required header does not stall a
  wait today, but it cannot produce a working tool call either;
- transient controller lag on any component → whichever phase owns it stalls.

## Decision

A connect resolves the components that are ready and omits the rest. An unready component is pending,
not fatal. This mirrors the two behaviours already in the tree:

- `prepareOAuthConsent` (`pkg/api/handlers/mcpgateway/oauth/authorize.go:314-327`) already treats
  missing required configuration as a promptable state (`ConsentMCPConfigRequired`) and short-circuits
  before `serverForVMCPAction`, so the interactive prompt is unaffected by this change.
- `restrictComponentTools` (`pkg/mcp/vmcp.go:253`) already narrows a single component without failing
  the aggregate.

Vocabulary: use `userAllowed` (the shipped policy name, `apiclient/types/vmcp.go:13`) throughout.
Do not introduce "user-supplied" or "user-provided" in new code, tests, or docs.

### Non-goals

- No change to the legacy per-deployment path (`ServerForAction`, deployed `MCPServer` /
  `MCPServerInstance`). VD-7177 ports Studio to vMCP; only the vMCP path is in scope.
- No change to the per-user field mechanism from VD-7213.
- No repo-wide prose sweep of existing "user-provided" wording. Only text this change adds.
- No change to which components a user is granted, or to tool grants.

## Tasks

Task 1 and Task 2 are independent and dispatch in parallel. Task 3 depends on both. Task 4 depends on
Task 3. Task 5 is independent.

### Task 1 — `pkg/wait`: a timeout the caller can distinguish

`wait.For` and `wait.ForList` return a bare `fmt.Errorf` whenever the watch channel ends, so an
elapsed timeout, an early watch close (client-go closes the channel silently on `io.EOF` and friends,
so a storage-apiserver restart looks identical) and caller cancellation are currently
indistinguishable. A caller that degrades on a timeout would therefore also swallow infrastructure
faults.

Run both waits under their own deadline and report the three outcomes distinctly:
`ErrTimeout` when that deadline elapses, `ErrWatchClosed` when the watch ends sooner, and the
caller's context error on cancellation. Keep the existing timeout message byte-identical
(`fmt.Errorf("%w waiting for %s list", ErrTimeout, kind)`); no test asserts these strings today.
A local deadline also removes the reliance on the server honouring `TimeoutSeconds`, which truncates
a sub-second timeout to "no timeout".

_Test:_ `pkg/wait` unit tests asserting `ErrTimeout` on a real elapsed timeout, `ErrWatchClosed` on an
early close (and that it is not `ErrTimeout`), and that a condition error is neither.

### Task 2 — `pkg/vmcp`: classify components that still need `userAllowed` input

Add `ConfiguredComponents(components []types.VMCPComponent, missing []string) []types.VMCPComponent`
to `pkg/vmcp/configurationstatus.go`.

`instance.Status.MissingRequiredConfiguration` is a flat, component-scoped key list. Reuse
`MissingRequiredConfiguration(component, nil, true)` to get each component's own required `userAllowed`
keys and drop the component when any of them appears in `missing`. No string parsing of the key.

Reading `instance.Status` here is safe: `waitForVMCPInstanceConfiguration` already blocks until the
reconcile that wrote it has landed, so the list is never staler than the configuration hash.

_Test:_ `pkg/vmcp/configurationstatus_test.go` — component dropped when its own required key is
missing; kept when the key is supplied; kept when only another component's key is missing (guards the
collision the component-scoped keys exist to prevent).

### Task 3 — `pkg/mcp/vmcp.go`: partial aggregate

1. **Classify before waiting.** Filter `configuredComponents` through the Task 2 helper immediately
   after `EnabledComponents`. This is what keeps connect fast: a permanently unready component must not
   cost the full 2-minute timeout on every connect.
2. **Degrade only on a real timeout.** Each per-component wait continues on `wait.ErrTimeout` and
   returns on every other error. To make that distinction meaningful, `wait.For` and `wait.ForList`
   run under their own deadline: they report `ErrTimeout` only when it elapses, `ErrWatchClosed` when
   the watch ends sooner, and the caller's context error on cancellation. Otherwise a storage fault
   that closes a watch would be indistinguishable from readiness and would silently shrink the
   aggregate.
3. **Never emit an unresolved component.** Build `Components` only from resolved servers and
   connections: skip a component whose server is absent, and skip a multi-user component with no entry
   in `connections`. Emitting a zero-value `ComponentServer` would produce `LocalMCPConnectURL("")` —
   the accidental-exposure risk in the ticket.
4. **Do not wait twice for the same component.** A shared component whose server did not resolve
   cannot have a connection, so drop it from `connectionsNeeded` before the connection wait. Otherwise
   one stalled component spends a second full timeout before the aggregate is returned.
5. **Carry the grant with its own component.** The old `restrictComponentTools(&components[i],
   allowedTools, configuredComponents[i].ID)` relied on two slices staying index-aligned; once a
   component can be skipped, that pairing silences or misdirects a grant. Apply
   `restrictComponentTools` to each server while building it, using that component's own ID, so there
   is no index invariant left to break.
6. **Keep instance-level waits fatal.** The create-instance wait and
   `waitForVMCPInstanceConfiguration` are per-user, not per-component.
7. **Add the testability seam.** `SessionManager.vmcpComponentTimeout time.Duration`, passed as
   `wait.ListOption.Timeout` on the three per-component waits. Zero keeps the 2-minute default, so
   production behaviour is unchanged and a test can exercise the degrade path in milliseconds.
8. **Log the omission once per connect** at warn, naming the vMCP and omitted component IDs.
9. **Respect cancellation.** A caller whose context ends gets that context's error, not a partial
   config. The re-check after tolerating a timeout stays as the belt to the wait's braces, since the
   deadline and a cancellation can race.

`ConfigHash` deliberately stays `instance.Status.ConfigurationCheckHash`. It reaches mmmcp as
`DiscoveryRevision` (`pkg/mcp/backend.go`), but it is not the cache key: mmmcp fingerprints the whole
configuration it is handed, including the server list
(`mmmcp/catalog.Fingerprint` → `canonicalConfig`), and Obot supplies that configuration per request
(`mmmcp.ContextWithConfig` in `pkg/api/handlers/mcpgateway/handler.go`). A component becoming ready
changes the fingerprint through the server list itself, so no extra input is needed — and the existing
test asserts that the hash stays the controller revision.

An aggregate with zero resolved components returns an empty `Components`, not an error. mmmcp
tolerates it (`frontendImplementation` special-cases only `len(Servers) == 1`, yielding an aggregate
with an empty catalog), and "everything on this instance is unavailable" is a truthful answer.

### Task 4 — tests for the connect path

In `pkg/mcp/vmcp_test.go`, reusing `newVMCPTestStorage`, `syncedVMCPInstance`,
`syncedVMCPConnection`:

- **One component needs configuration** — two components, one listed in
  `instance.Status.MissingRequiredConfiguration`; assert the result carries only the ready component,
  its own server/connection, and returns promptly.
- **One component never syncs** — `vmcpComponentTimeout` set low; assert the ready component is still
  returned, the never-synced one is absent, and the ready component's tool grant was applied through
  its own ID (guards Task 3.4).
- **A real error still fails** — a storage whose `Watch` returns an error must fail the connection and
  must not be reported as a timeout; a canceled caller must get `context.Canceled` rather than a
  partial config.
- **An early watch close is not readiness** — covered in `pkg/wait`, where `ErrWatchClosed` is
  asserted separately from `ErrTimeout`.

### Task 5 — docs and ADR

- `adr/2026-10-25-vmcp-partial-connect.md`: record that a vMCP connect exposes ready components and
  omits unready ones, why all-or-nothing was wrong, and that omission cannot widen a grant.
- One line in `docs/docs/mcp-gateway/troubleshooting.md` (or `server-types.md` § *How configuration
  affects deployment*): a component that still needs `userAllowed` input is omitted from the
  connection until it is configured, and does not block the other components.
- No changes to `docs/versioned_docs/**`.

## Verification

- `go test ./pkg/wait/ ./pkg/vmcp/ ./pkg/mcp/` during development.
- `make build && make validate-go-code` (fork gate: tidy, generate, lint, uncommitted-change check).
- `make test` before handoff.

## Mandatory gates before a PR

Run in order, recording each result in the Linear issue:

1. Changed-area validation plus the `implementing-linear-issue` quality gates via subagents: code
   review, simplification review, test-coverage review, and acceptance-criteria review.
2. Reconcile against Linear: tick AC1 and AC2 on evidence from the tests above, and report AC3 as
   blocked on the Studio image pin and the five quarantines, which are not fixable from this
   repository.
3. `ai-pr-review-guide` review by subagent. If it does not return ready-to-merge, **do not raise the
   PR**; discuss the findings first.
4. Only if 1-3 are green: push `fix/vd-7318-vmcp-partial-connect` to `accelerate-data/obot` and open
   the PR there, referencing VD-7318 without a closing keyword.

## Risks

- **Grant widening.** The aggregation change touches which components a session can reach. Task 3.3
  and 3.5 are what keep it strictly narrowing, and Task 4 covers the grant case with a test that would
  fail if a component's tools were applied through another component's ID.
- **Silent absence.** A component omitted for a transient reason is invisible to a caller that does
  not read `instance.Status`. Studio's attach status already derives its unavailable set from its own
  pre-connect skip and the bridge status file, so this change does not make it less truthful; the
  warning log and the per-component vMCP status remain the operator-facing record. A *watch fault* is
  deliberately not silent: it fails the connection rather than shrinking the aggregate.
- **Time-to-first-connect.** Classification removes the stall for the common case. A component that is
  unready for another reason still costs up to one readiness wait — Task 3.4 is what keeps that to one
  rather than two — and a missing fixed (administrator) required field costs it on every connect,
  because only user inputs appear in `instance.Status.MissingRequiredConfiguration`.
