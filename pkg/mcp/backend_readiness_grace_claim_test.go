package mcp

// Fork-only guarantee (VD-5283, restored by VD-6903): MCP server readiness polling tolerates nanobot's transient HTTP 500 for a bounded grace window measured from the first 500, still fails on a persistent 500, and fails on the first 500 when the grace is zero. Kept in its own file so an upstream sync cannot drop these tests by merging over a shared one.

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// outruns nanobot's own two-minute first health check, nanobot records
// "initialize failed: context deadline exceeded" and serves it as a 500 until its health
// ticker retries a minute later — by which point the package is cached and the check
// passes. The readiness poller must survive that window instead of aborting the whole
// startup budget on the first 500 (VD-5283).
func TestEnsureServerReadyToleratesTransientInternalServerError(t *testing.T) {
	var calls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/healthz" {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		calls++
		if calls < 3 {
			http.Error(w, "initialize failed: context deadline exceeded", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()

	if err := ensureServerReady(ctx, server.URL+"/", ServerConfig{HealthzPath: "healthz"}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if calls != 3 {
		t.Fatalf("expected three healthz calls, got %d", calls)
	}
}

func TestEnsureServerReadyFailsOnPersistentInternalServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "tool listing failed", http.StatusInternalServerError)
	}))
	defer server.Close()

	ctx, cancel := context.WithTimeout(t.Context(), 300*time.Millisecond)
	defer cancel()

	err := ensureServerReady(ctx, server.URL+"/", ServerConfig{HealthzPath: "healthz"})
	if !errors.Is(err, ErrHealthCheckFailed) {
		t.Fatalf("expected ErrHealthCheckFailed, got %v", err)
	}
	if !strings.Contains(err.Error(), "tool listing failed") {
		t.Fatalf("expected the nanobot body to be relayed, got %v", err)
	}
}

// analyzePodStatus probes for a permanent verdict inside a watch loop rather than polling
// for readiness, so it passes a zero grace period and must still fail on the first 500.
func TestEnsureHTTPGetOKFailsFastWhenInternalServerErrorGraceIsZero(t *testing.T) {
	var calls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		http.Error(w, "tool listing failed", http.StatusInternalServerError)
	}))
	defer server.Close()

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	if err := ensureHTTPGetOK(ctx, server.Client(), server.URL+"/healthz", 0); !errors.Is(err, ErrHealthCheckFailed) {
		t.Fatalf("expected ErrHealthCheckFailed, got %v", err)
	}
	if calls != 1 {
		t.Fatalf("expected exactly one healthz call, got %d", calls)
	}
}

func TestEnsureHTTPGetOKGivesUpAfterInternalServerErrorGrace(t *testing.T) {
	var calls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		http.Error(w, "tool listing failed", http.StatusInternalServerError)
	}))
	defer server.Close()

	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()

	start := time.Now()
	if err := ensureHTTPGetOK(ctx, server.Client(), server.URL+"/healthz", 200*time.Millisecond); !errors.Is(err, ErrHealthCheckFailed) {
		t.Fatalf("expected ErrHealthCheckFailed, got %v", err)
	}
	if ctx.Err() != nil {
		t.Fatal("expected the grace period to end the poll, not the context")
	}
	if elapsed := time.Since(start); elapsed < 200*time.Millisecond {
		t.Fatalf("gave up after %v, before the grace period elapsed", elapsed)
	}
	if calls < 2 {
		t.Fatalf("expected the poll to retry within the grace period, got %d calls", calls)
	}
}

// A server alternating 500 with any other status must not postpone the permanence verdict
// for ever: the 500 window measures how long the server has been failing to come up, so
// only a 200 clears it.
func TestEnsureHTTPGetOKInternalServerErrorGraceSurvivesInterleavedStatuses(t *testing.T) {
	var calls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		if calls%2 == 0 {
			http.Error(w, "waiting for startup", http.StatusTooEarly)
			return
		}
		http.Error(w, "tool listing failed", http.StatusInternalServerError)
	}))
	defer server.Close()

	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()

	if err := ensureHTTPGetOK(ctx, server.Client(), server.URL+"/healthz", 200*time.Millisecond); !errors.Is(err, ErrHealthCheckFailed) {
		t.Fatalf("expected ErrHealthCheckFailed, got %v", err)
	}
	if ctx.Err() != nil {
		t.Fatal("expected the grace period to end the poll, not the context")
	}
}
