# 2026-10-25: A vMCP connection exposes its ready components

- **Status:** Accepted
- **Date:** 2026-10-25
- **Supersedes:** None
- **Superseded by:** None

## Related issues

- [VD-7318](https://linear.app/acceleratedata/issue/VD-7318/shared-vmcp-connect-fails-entirely-when-any-granted-component-is-mid) — a shared vMCP connect failed entirely when any granted component was mid-setup.
- [obot-platform/obot#7724](https://github.com/obot-platform/obot/issues/7724) — the vMCP resource this decision applies to.

## Related ODPs

None. This records behaviour of the already-accepted virtual MCP design
([2026-09-01: Virtual MCPs](2026-09-01-virtual-mcps.md)), which did not specify what a
connection does while one component is still being configured.

## Context

A vMCP decides each component's deployment mode independently: a component with a
`userAllowed` non-header input gets a per-user deployment, and one with only fixed or
`userAllowed` header inputs shares a deployment across connections
(`docs/docs/mcp-gateway/server-types.md`). A user's connection therefore mixes components
that can be resolved immediately with components that cannot be resolved until that user
supplies a value.

`serverConfigForVMCP` resolved all three per-component readiness phases before building any
result, and returned an error if any single phase timed out. A component with a required
`userAllowed` input the user had not supplied never reached the synced state those phases
wait for, so its timeout discarded the components that had already resolved. Granting a new
catalog entry with a required per-user field therefore broke every existing user's
connection to that vMCP, including components unrelated to the new one.

This was a regression from the per-deployment model, where each server resolved on its own.

## Decision

A vMCP connection resolves the components that are ready and omits the rest.

- Components still missing a required `userAllowed` input are classified out before the
  readiness waits, so they neither block the connection nor cost it the readiness timeout.
- A per-component readiness timeout omits the components that did not resolve. A watch that
  fails, or that ends before the timeout elapses, still fails the connection, as does a
  caller whose context is done: a transport fault must never look like a component that is
  merely not ready.
- A shared component whose server did not resolve is not also waited on for a connection. A connect
  therefore waits at most one readiness wait per phase — shared servers, instance servers,
  connections — so its worst case is bounded by the number of phases, not by the number of unready
  components.
- An unresolved component is never emitted. The component identity travels with each emitted
  server, so omitting one cannot shift another component's tool grant.

The aggregate may contain no components. That is a truthful answer to "what is ready for
this user", not an error.

## Rationale

The interactive consent flow already treats a missing required input as a state to prompt
for (`vmcpConsentMissingConfiguration` runs before the aggregate is built). Only the
non-interactive path — an agent session, which has nobody to prompt — treated the same state
as fatal. Resolving readiness per component matches how the deployment mode is already
decided, and follows `restrictComponentTools`, which has always narrowed one component
without failing the aggregate.

The alternatives were rejected: failing the connection contradicts the documented
per-component model; narrowing the profile grant hides the component the user is trying to
configure, along with the problem.

## Consequences

- A caller must not read an omitted component as "not granted". Readiness and grants are
  different questions, and the per-component vMCP status plus
  `VMCPInstanceStatus.MissingRequiredConfiguration` remain the record of which is which.
- Each connect logs a warning naming any component omitted because a wait timed out. A
  component removed for missing input is not logged: that is the expected state, and it is
  already reported by the status above.
- A component that is unready for a reason other than a missing user input can still cost up
  to one readiness wait per connect. Two such reasons are worth naming. Controller lag is
  transient. A missing **fixed** (administrator) required field is not transient but is also
  not in `VMCPInstanceStatus.MissingRequiredConfiguration`, which lists user inputs only, so
  it is not classified out; it is reported by `VMCP.Status.Components[].ConfigurationError`
  instead.
- The vMCP OAuth and consent paths now see the same partial component list. An unconfigured
  component has nothing to authenticate, so this is the correct order, but it does mean
  `GET /api/oauth/vmcp/{id}/components/{server}` answers "does not belong to this vMCP
  connection" for a component that belongs and is merely not ready yet. Configuration, not
  that endpoint, is the way to bring a component into the aggregate.

## References

- `pkg/mcp/vmcp.go` — `serverConfigForVMCP`.
- `pkg/vmcp/configurationstatus.go` — `ConfiguredComponents` and `MissingRequiredConfiguration`.
- `pkg/wait/waitfor.go` — `ErrTimeout` and `ErrWatchClosed`, which keep a readiness timeout distinct from a fault.
- `pkg/api/handlers/mcpgateway/oauth/authorize.go` — the consent-time configuration check.
- `docs/docs/mcp-gateway/server-types.md` — configuration policies and per-component deployment modes.
