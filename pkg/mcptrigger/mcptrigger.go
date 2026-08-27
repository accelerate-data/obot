// Package mcptrigger enqueues controller reconciles for MCP servers.
//
// It exists so that every caller that reacts to an MCP OAuth credential change
// enqueues the same object under the same key. Two properties are easy to get
// wrong at a call site and are therefore centralized here:
//
//   - MCPServer is namespace-scoped, so a trigger key must carry the namespace.
//     nah parses a key as "<namespace>/<name>" and falls back to an empty
//     namespace, where no MCPServer is ever stored; the cache lookup then misses
//     and every handler is skipped as if the object did not exist.
//   - A multi-user MCP identifier names an MCPServerInstance, not an MCPServer.
//     Instances have no status and no OAuth handlers; the reconcile that owns
//     OAuth status runs on the MCPServer the instance points at.
package mcptrigger

import (
	"context"
	"fmt"

	nahbackend "github.com/obot-platform/nah/pkg/backend"
	v1 "github.com/obot-platform/obot/pkg/storage/apis/obot.obot.ai/v1"
	"github.com/obot-platform/obot/pkg/system"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	kclient "sigs.k8s.io/controller-runtime/pkg/client"
)

var mcpServerGVK = v1.SchemeGroupVersion.WithKind("MCPServer")

// Server enqueues a reconcile for the named MCPServer. An empty name means
// there is nothing to reconcile.
func Server(ctx context.Context, backend nahbackend.Trigger, serverName string) error {
	if backend == nil {
		return fmt.Errorf("MCP server controller backend is not configured")
	}
	if serverName == "" {
		return nil
	}
	return backend.Trigger(ctx, mcpServerGVK, system.DefaultNamespace+"/"+serverName, 0)
}

// OwningServer enqueues a reconcile for the MCPServer that owns mcpID.
//
// An MCPServerInstance ID is resolved to its owning MCPServer; any other ID is
// treated as an MCPServer name.
func OwningServer(ctx context.Context, c kclient.Reader, backend nahbackend.Trigger, mcpID string) error {
	if !system.IsMCPServerInstanceID(mcpID) {
		return Server(ctx, backend, mcpID)
	}
	if c == nil {
		return fmt.Errorf("cannot resolve MCP server instance %s: no storage client is configured", mcpID)
	}

	var instance v1.MCPServerInstance
	if err := c.Get(ctx, kclient.ObjectKey{Namespace: system.DefaultNamespace, Name: mcpID}, &instance); err != nil {
		if apierrors.IsNotFound(err) {
			// Credential rows outlive the instance they were created for, so a
			// deleted instance is expected here. There is no owner left to
			// reconcile, and failing would break the caller's delete. A read
			// that fails for any other reason is not expected steady state, so
			// it surfaces like any other trigger failure.
			return nil
		}
		return fmt.Errorf("failed to get MCP server instance %s: %w", mcpID, err)
	}
	return Server(ctx, backend, instance.Spec.MCPServerName)
}

// OwningServerTrigger returns the MCP OAuth credential-change notification the
// gateway client is constructed with. Production and tests install this same
// value, so a test cannot pass against a hand-written copy of the wiring.
func OwningServerTrigger(c kclient.Reader, backend nahbackend.Trigger) func(context.Context, string) error {
	return func(ctx context.Context, mcpID string) error {
		return OwningServer(ctx, c, backend, mcpID)
	}
}
