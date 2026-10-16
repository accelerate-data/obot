package mcp

// Fork-only guarantee (fork #47, restored by VD-6903): the Docker backend acquires the runtime image under the caller's context and only then starts the StartupTimeout budget for create/start/readiness, and it decides whether acquisition is needed with exactly the container-reuse checks ensureDeployment applies. Kept in its own file so an upstream sync cannot drop these tests by merging over a shared one.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/network"
)

func imageAcquisitionExistingContainer(configHash, fileEnvKeysHash, networkName, image string, state container.ContainerState) *container.Summary {
	return &container.Summary{
		Image: image,
		Labels: map[string]string{
			"mcp.config.hash":        configHash,
			"mcp.file.env.keys.hash": fileEnvKeysHash,
		},
		NetworkSettings: &container.NetworkSettingsSummary{
			Networks: map[string]*network.EndpointSettings{
				networkName: {},
			},
		},
		State: state,
	}
}

// dockerContainerNeedsRecreate decides whether ensureDeployment will take the
// create-new-container path (and therefore needs to acquire the image) versus
// reusing an existing container as-is. It must mirror ensureDeployment's
// invalidation checks (config hash, file env hash, network presence,
// image match) plus its container-state switch (only StateCreated/StateRunning
// are reusable) exactly, since it replaces that inline logic.
func TestDockerContainerNeedsRecreate(t *testing.T) {
	const (
		configHash      = "config-hash"
		fileEnvKeysHash = "file-env-hash"
		networkName     = "obot"
		image           = "ghcr.io/obot-platform/nanobot:v0.0.65"
	)

	tests := []struct {
		name         string
		existing     *container.Summary
		desiredImage string
		want         bool
	}{
		{
			name:         "no existing container",
			existing:     nil,
			desiredImage: image,
			want:         true,
		},
		{
			name:         "matching config, running",
			existing:     imageAcquisitionExistingContainer(configHash, fileEnvKeysHash, networkName, image, container.StateRunning),
			desiredImage: image,
			want:         false,
		},
		{
			name:         "matching config, created",
			existing:     imageAcquisitionExistingContainer(configHash, fileEnvKeysHash, networkName, image, container.StateCreated),
			desiredImage: image,
			want:         false,
		},
		{
			name:         "matching config, exited",
			existing:     imageAcquisitionExistingContainer(configHash, fileEnvKeysHash, networkName, image, container.StateExited),
			desiredImage: image,
			want:         true,
		},
		{
			name:         "config hash mismatch",
			existing:     imageAcquisitionExistingContainer("stale-hash", fileEnvKeysHash, networkName, image, container.StateRunning),
			desiredImage: image,
			want:         true,
		},
		{
			name:         "file env keys hash mismatch",
			existing:     imageAcquisitionExistingContainer(configHash, "stale-file-hash", networkName, image, container.StateRunning),
			desiredImage: image,
			want:         true,
		},
		{
			name:         "network missing",
			existing:     imageAcquisitionExistingContainer(configHash, fileEnvKeysHash, "other-network", image, container.StateRunning),
			desiredImage: image,
			want:         true,
		},
		{
			name:         "image mismatch",
			existing:     imageAcquisitionExistingContainer(configHash, fileEnvKeysHash, networkName, "stale-image", container.StateRunning),
			desiredImage: image,
			want:         true,
		},
		{
			name:         "empty desired image never mismatches (containerized runtime tracks image via config hash instead)",
			existing:     imageAcquisitionExistingContainer(configHash, fileEnvKeysHash, networkName, "any-image", container.StateRunning),
			desiredImage: "",
			want:         false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := dockerContainerNeedsRecreate(tt.existing, configHash, fileEnvKeysHash, networkName, tt.desiredImage)
			if got != tt.want {
				t.Fatalf("dockerContainerNeedsRecreate() = %v, want %v", got, tt.want)
			}
		})
	}
}

// acquireImageThenBoundStartup decouples slow image acquisition from the
// tight StartupTimeout budget meant for container creation/start/readiness:
// pull runs under the caller's ctx (no StartupTimeout deadline imposed), and
// only createOrReuse gets a fresh StartupTimeout-derived deadline, measured
// from after acquisition completes.
func TestAcquireImageThenBoundStartup(t *testing.T) {
	wantServerConfig := ServerConfig{MCPServerName: "test-server"}

	t.Run("slow pull under generous caller deadline still completes", func(t *testing.T) {
		pullStarted := make(chan struct{})
		unblockPull := make(chan struct{})

		pull := func(context.Context) error {
			close(pullStarted)
			<-unblockPull
			return nil
		}

		var createOrReuseCalled bool
		createOrReuse := func(context.Context) (ServerConfig, error) {
			createOrReuseCalled = true
			return wantServerConfig, nil
		}

		done := make(chan struct {
			cfg ServerConfig
			err error
		}, 1)
		go func() {
			cfg, err := acquireImageThenBoundStartup(t.Context(), 50*time.Millisecond, true, pull, createOrReuse)
			done <- struct {
				cfg ServerConfig
				err error
			}{cfg, err}
		}()

		<-pullStarted
		time.Sleep(200 * time.Millisecond) // longer than startupTimeout, proving pull isn't bound by it
		close(unblockPull)

		select {
		case res := <-done:
			if res.err != nil {
				t.Fatalf("acquireImageThenBoundStartup() error = %v", res.err)
			}
			if res.cfg.MCPServerName != wantServerConfig.MCPServerName {
				t.Fatalf("acquireImageThenBoundStartup() = %+v, want %+v", res.cfg, wantServerConfig)
			}
			if !createOrReuseCalled {
				t.Fatal("createOrReuse was never called")
			}
		case <-time.After(2 * time.Second):
			t.Fatal("acquireImageThenBoundStartup did not return within 2s")
		}
	})

	t.Run("fresh StartupTimeout budget measured from post-pull time", func(t *testing.T) {
		const startupTimeout = 300 * time.Millisecond
		const pullDuration = 500 * time.Millisecond

		pull := func(context.Context) error {
			time.Sleep(pullDuration)
			return nil
		}

		var capturedCtx context.Context
		createOrReuse := func(ctx context.Context) (ServerConfig, error) {
			capturedCtx = ctx
			return wantServerConfig, nil
		}

		if _, err := acquireImageThenBoundStartup(t.Context(), startupTimeout, true, pull, createOrReuse); err != nil {
			t.Fatalf("acquireImageThenBoundStartup() error = %v", err)
		}

		deadline, ok := capturedCtx.Deadline()
		if !ok {
			t.Fatal("createOrReuse ctx has no deadline, want one derived from startupTimeout")
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			t.Fatalf("createOrReuse ctx deadline already passed (remaining = %v); startupTimeout budget was consumed by pull instead of measured fresh after it", remaining)
		}
		if remaining > startupTimeout {
			t.Fatalf("createOrReuse ctx deadline %v from now, want <= startupTimeout %v", remaining, startupTimeout)
		}
	})

	t.Run("caller cancellation during pull aborts, createOrReuse never invoked", func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())

		pull := func(ctx context.Context) error {
			cancel()
			<-ctx.Done()
			return ctx.Err()
		}

		var createOrReuseCalled bool
		createOrReuse := func(context.Context) (ServerConfig, error) {
			createOrReuseCalled = true
			return ServerConfig{}, nil
		}

		_, err := acquireImageThenBoundStartup(ctx, time.Second, true, pull, createOrReuse)
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("acquireImageThenBoundStartup() error = %v, want context.Canceled", err)
		}
		if createOrReuseCalled {
			t.Fatal("createOrReuse must not be invoked when pull is aborted by caller cancellation")
		}
	})

	t.Run("pull error returned before create/start, createOrReuse never invoked", func(t *testing.T) {
		wantErr := errors.New("pull failed: registry unavailable")
		pull := func(context.Context) error {
			return wantErr
		}

		var createOrReuseCalled bool
		createOrReuse := func(context.Context) (ServerConfig, error) {
			createOrReuseCalled = true
			return ServerConfig{}, nil
		}

		_, err := acquireImageThenBoundStartup(t.Context(), time.Second, true, pull, createOrReuse)
		if !errors.Is(err, wantErr) {
			t.Fatalf("acquireImageThenBoundStartup() error = %v, want %v", err, wantErr)
		}
		if createOrReuseCalled {
			t.Fatal("createOrReuse must not be invoked when pull fails")
		}
	})

	t.Run("needsPull false skips pull entirely", func(t *testing.T) {
		var pullCalled bool
		pull := func(context.Context) error {
			pullCalled = true
			return nil
		}

		createOrReuse := func(context.Context) (ServerConfig, error) {
			return wantServerConfig, nil
		}

		cfg, err := acquireImageThenBoundStartup(t.Context(), time.Second, false, pull, createOrReuse)
		if err != nil {
			t.Fatalf("acquireImageThenBoundStartup() error = %v", err)
		}
		if cfg.MCPServerName != wantServerConfig.MCPServerName {
			t.Fatalf("acquireImageThenBoundStartup() = %+v, want %+v", cfg, wantServerConfig)
		}
		if pullCalled {
			t.Fatal("pull must not be invoked when needsPull is false")
		}
	})
}
