# 2026-10-25: Administrators can revoke a user's shared vMCP OAuth grants

- **Status:** Accepted
- **Date:** 2026-10-25
- **Supersedes:** None
- **Superseded by:** None

## Related issues

- [VD-7328](https://linear.app/acceleratedata/issue/VD-7328/obots-vmcp-oauth-model-has-no-admin-scoped-revocation-so-vd-6304-user)

## Related ODPs

None. This extends the accepted [Virtual MCPs](2026-09-01-virtual-mcps.md) design with an administrative cleanup operation.

## Context

The component OAuth clear route always uses the caller's UID. Studio offboarding uses a machine admin identity, so that route cannot clear a departing user's grants. Shared Obot may also hold grants outside Studio's shared vMCP, which Studio must leave alone.

## Decision

An admin-only route takes a shared vMCP ID and target UID. Obot resolves that user's vMCP instances to their dedicated servers and shared-component connection IDs. It revokes only the target UID's tokens and pending OAuth states under those IDs. An absent vMCP connection is an error because Obot cannot then prove which token IDs belong to this vMCP.

The same database transaction records a permanent `(user_id, mcp_id)` revocation fence and removes the tokens and pending states. Token writes take the same cross-process connection lock and reject fenced IDs, including a callback that claimed its pending state before revocation. A retry repeats reconciliation notifications even if the token rows were removed by the first attempt.

## Rationale

Caller-scoped clear targets the admin's grants. Deleting every grant for the target UID would also affect unrelated Obot connections. Resolving vMCP ownership in Obot keeps the scope authoritative. The persisted fence closes the gap between an in-flight provider callback and token deletion.

## Consequences

Revoked connection IDs cannot authorize again for that UID. A user who needs access again must use a new connection. Offboarding must call this route while the user's vMCP instance graph still exists. A missing graph reports an error for residual handling.

## References

- `pkg/api/handlers/mcp.go`
- `pkg/gateway/client/mcpoauthtoken.go`
- `pkg/gateway/types/tokens.go`
