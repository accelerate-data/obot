package mcp

// Fork-only guarantee (fork #47, restored by VD-6903): SessionManager.ensureDeployment hands the backend the caller's context without its own StartupTimeout deadline, so image acquisition is never charged against the startup budget. Kept in its own file so an upstream sync cannot drop these tests by merging over a shared one.

import (
	"context"
	"io"
	"testing"
	"time"

	"github.com/obot-platform/obot/apiclient/types"
)

// startupTimeoutCtxCapturingBackend records the ctx ensureServerDeployment
// receives so the test can inspect the deadline SessionManager imposed.
type startupTimeoutCtxCapturingBackend struct {
	capturedCtx context.Context
}

func (b *startupTimeoutCtxCapturingBackend) ensureServerDeployment(ctx context.Context, server ServerConfig) (ServerConfig, error) {
	b.capturedCtx = ctx
	return server, nil
}

func (b *startupTimeoutCtxCapturingBackend) deployServer(context.Context, ServerConfig) error {
	return nil
}

func (b *startupTimeoutCtxCapturingBackend) streamServerLogs(context.Context, string) (io.ReadCloser, error) {
	return nil, nil
}

func (b *startupTimeoutCtxCapturingBackend) getServerDetails(context.Context, string) (types.MCPServerDetails, error) {
	return types.MCPServerDetails{}, nil
}

func (b *startupTimeoutCtxCapturingBackend) restartServer(context.Context, ServerConfig) error {
	return nil
}

func (b *startupTimeoutCtxCapturingBackend) shutdownServer(context.Context, string, bool) error {
	return nil
}

func (b *startupTimeoutCtxCapturingBackend) transformObotHostname(url string) string { return url }

func (b *startupTimeoutCtxCapturingBackend) remoteConfig(globalConfig RemoteMCPURLValidationConfig) (RemoteMCPURLValidationConfig, []string) {
	return globalConfig, nil
}

// Image acquisition can be slow (registry pull), and that time must not be
// carved out of the tight StartupTimeout budget meant for container
// creation/start/readiness. Each backend applies that bound itself, after
// image acquisition, so a deadline imposed here would undo it.
func TestEnsureDeployment_DoesNotImposeItsOwnStartupTimeout(t *testing.T) {
	backend := &startupTimeoutCtxCapturingBackend{}
	sm := &SessionManager{backend: backend}

	server := ServerConfig{
		Runtime:        types.RuntimeNPX,
		StartupTimeout: 5 * time.Millisecond,
	}

	if _, err := sm.ensureDeployment(t.Context(), server); err != nil {
		t.Fatalf("ensureDeployment() error = %v", err)
	}
	if backend.capturedCtx == nil {
		t.Fatal("backend.ensureServerDeployment was never called")
	}
	if _, ok := backend.capturedCtx.Deadline(); ok {
		t.Fatal("ensureDeployment must not impose its own StartupTimeout-derived deadline; each backend bounds startup after image acquisition")
	}
}
