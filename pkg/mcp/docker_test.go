package mcp

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/network"
)

func TestNewMCPServerHostConfigMapsHostDockerInternal(t *testing.T) {
	hc := newMCPServerHostConfig("8099/tcp", nil, container.Resources{})

	// The shim (and other MCP server containers) must be able to reach services
	// published on the host via host.docker.internal, matching how Obot's own
	// container is reached. Without this mapping, a remote MCP server whose URL
	// resolves to host.docker.internal is unreachable from the shim on native
	// Linux dockerd (Docker Desktop injects it automatically, masking the bug).
	if !slices.Contains(hc.ExtraHosts, "host.docker.internal:host-gateway") {
		t.Fatalf("ExtraHosts = %v, want it to contain host.docker.internal:host-gateway", hc.ExtraHosts)
	}
}

func TestDockerTransformObotHostnameAlwaysRewritesHost(t *testing.T) {
	d := &dockerBackend{hostBaseURLWithPort: "http://172.17.0.1:8080"}

	tests := map[string]string{
		"http://localhost:8080/oauth/token":                 "http://172.17.0.1:8080/oauth/token",
		"http://obot.example.com/oauth/token":               "http://172.17.0.1:8080/oauth/token",
		"https://obot.example.com/oauth/token?audience=mcp": "http://172.17.0.1:8080/oauth/token?audience=mcp",
		"http://obot.example.com":                           "http://172.17.0.1:8080",
		"":                                                  "",
		"not-a-url":                                         "not-a-url",
	}

	for input, expected := range tests {
		if result := d.transformObotHostname(input); result != expected {
			t.Fatalf("transformObotHostname(%q) = %q, want %q", input, result, expected)
		}
	}
}

func TestChooseMCPNetwork(t *testing.T) {
	if got := chooseMCPNetwork("vibedata-local-default", "some-autodetected"); got != "vibedata-local-default" {
		t.Fatalf("explicit option should win, got %q", got)
	}
	if got := chooseMCPNetwork("", "auto-net"); got != "auto-net" {
		t.Fatalf("auto-detected should be used when option empty, got %q", got)
	}
	if got := chooseMCPNetwork("", ""); got != "bridge" {
		t.Fatalf("default should be bridge, got %q", got)
	}
}

func TestDockerBackendNetworkConfigUsesDetectedContainerNetwork(t *testing.T) {
	localCalled := false

	containerEnv, network, host, err := dockerBackendNetworkConfig(
		func() (string, string, error) {
			return "obot_default", "172.18.0.4", nil
		},
		func() (string, error) {
			localCalled = true
			return "192.168.1.4", nil
		},
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !containerEnv {
		t.Fatalf("expected containerEnv")
	}
	if network != "obot_default" {
		t.Fatalf("expected detected network, got %q", network)
	}
	if host != "172.18.0.4" {
		t.Fatalf("expected detected host, got %q", host)
	}
	if localCalled {
		t.Fatalf("did not expect local IP detection to be called")
	}
}

func TestDockerBackendNetworkConfigFallsBackToLocalIP(t *testing.T) {
	tests := map[string]func() (string, string, error){
		"container detection errors": func() (string, string, error) {
			return "", "", errors.New("inspect failed")
		},
		"container detection has no IP": func() (string, string, error) {
			return "obot_default", "", nil
		},
	}

	for name, detectContainer := range tests {
		t.Run(name, func(t *testing.T) {
			containerEnv, network, host, err := dockerBackendNetworkConfig(
				detectContainer,
				func() (string, error) {
					return "192.168.1.4", nil
				},
			)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if containerEnv {
				t.Fatalf("did not expect containerEnv")
			}
			if network != "bridge" {
				t.Fatalf("expected default network, got %q", network)
			}
			if host != "192.168.1.4" {
				t.Fatalf("expected local host, got %q", host)
			}
		})
	}
}

func TestDockerBackendNetworkConfigReturnsLocalIPError(t *testing.T) {
	routeErr := errors.New("route failed")

	_, _, _, err := dockerBackendNetworkConfig(
		func() (string, string, error) {
			return "", "", errors.New("inspect failed")
		},
		func() (string, error) {
			return "", routeErr
		},
	)
	if err == nil {
		t.Fatalf("expected error")
	}
	if !errors.Is(err, routeErr) {
		t.Fatalf("expected wrapped route error, got %v", err)
	}
}

func TestContainerFilesStablePathsAcrossDataChanges(t *testing.T) {
	filesA := []File{{
		EnvKey: "TLS_CERT",
		Data:   "value-a",
	}, {
		EnvKey: "TLS_KEY",
		Data:   "value-b",
	}}

	filesB := []File{{
		EnvKey: "TLS_CERT",
		Data:   "new-value-a",
	}, {
		EnvKey: "TLS_KEY",
		Data:   "new-value-b",
	}}

	_, envA := containerFiles(filesA, "server")
	_, envB := containerFiles(filesB, "server")

	if envA["TLS_CERT"] != envB["TLS_CERT"] {
		t.Fatalf("expected stable path for TLS_CERT, got %q and %q", envA["TLS_CERT"], envB["TLS_CERT"])
	}

	if envA["TLS_KEY"] != envB["TLS_KEY"] {
		t.Fatalf("expected stable path for TLS_KEY, got %q and %q", envA["TLS_KEY"], envB["TLS_KEY"])
	}
}

func TestFileEnvKeysHashIgnoresData(t *testing.T) {
	filesA := []File{{
		EnvKey: "TLS_CERT",
		Data:   "a",
	}, {
		EnvKey: "TLS_KEY",
		Data:   "b",
	}}

	filesB := []File{{
		EnvKey: "TLS_CERT",
		Data:   "new-a",
	}, {
		EnvKey: "TLS_KEY",
		Data:   "new-b",
	}}

	if fileEnvKeysHash(filesA) != fileEnvKeysHash(filesB) {
		t.Fatalf("expected file env key hash to ignore file data")
	}
}

func TestFileEnvKeysHashChangesWithKeySet(t *testing.T) {
	filesA := []File{{
		EnvKey: "TLS_CERT",
		Data:   "a",
	}}

	filesB := []File{{
		EnvKey: "TLS_CERT",
		Data:   "a",
	}, {
		EnvKey: "TLS_KEY",
		Data:   "b",
	}}

	if fileEnvKeysHash(filesA) == fileEnvKeysHash(filesB) {
		t.Fatalf("expected different file env key hash when key set changes")
	}
}

func TestApplyServerConfigToContainerConfigOverridesImageAndLabels(t *testing.T) {
	config := &container.Config{
		Image:  "ghcr.io/obot-platform/nanobot:v0.0.59",
		Labels: nil,
	}

	server := ServerConfig{
		MCPServerName:  "mcp-server-abc",
		ContainerImage: "ghcr.io/obot-platform/nanobot:v0.0.65",
		Runtime:        "containerized",
		Files: []File{{
			EnvKey:  "NANOBOT_ENV_FILE",
			Data:    "value",
			Dynamic: true,
		}},
	}

	applyServerConfigToContainerConfig(config, server)

	if config.Image != server.ContainerImage {
		t.Fatalf("expected image %q, got %q", server.ContainerImage, config.Image)
	}

	if got, ok := config.Labels["mcp.config.hash"]; !ok || got != serverID(server) {
		t.Fatalf("expected mcp.config.hash %q, got %q", serverID(server), got)
	}

	if got, ok := config.Labels["mcp.file.env.keys.hash"]; !ok || got != fileEnvKeysHash(server.Files) {
		t.Fatalf("expected mcp.file.env.keys.hash %q, got %q", fileEnvKeysHash(server.Files), got)
	}
}

func TestApplyServerConfigToContainerConfigNoImageNoChanges(t *testing.T) {
	config := &container.Config{
		Image: "ghcr.io/obot-platform/nanobot:v0.0.65",
		Labels: map[string]string{
			"existing": "label",
		},
	}

	originalImage := config.Image
	originalExistingLabel := config.Labels["existing"]

	server := ServerConfig{
		MCPServerName: "mcp-server-abc",
	}

	applyServerConfigToContainerConfig(config, server)

	if config.Image != originalImage {
		t.Fatalf("expected image to remain %q, got %q", originalImage, config.Image)
	}

	if config.Labels["existing"] != originalExistingLabel {
		t.Fatalf("expected existing label to remain %q, got %q", originalExistingLabel, config.Labels["existing"])
	}

	if _, ok := config.Labels["mcp.config.hash"]; ok {
		t.Fatalf("did not expect mcp.config.hash label to be set")
	}

	if _, ok := config.Labels["mcp.file.env.keys.hash"]; ok {
		t.Fatalf("did not expect mcp.file.env.keys.hash label to be set")
	}
}

func matchingExistingContainer(configHash, fileEnvKeysHash, networkName, image string, state container.ContainerState) *container.Summary {
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
// current invalidation checks (config hash, file env hash, network presence,
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
			existing:     matchingExistingContainer(configHash, fileEnvKeysHash, networkName, image, container.StateRunning),
			desiredImage: image,
			want:         false,
		},
		{
			name:         "matching config, created",
			existing:     matchingExistingContainer(configHash, fileEnvKeysHash, networkName, image, container.StateCreated),
			desiredImage: image,
			want:         false,
		},
		{
			name:         "matching config, exited",
			existing:     matchingExistingContainer(configHash, fileEnvKeysHash, networkName, image, container.StateExited),
			desiredImage: image,
			want:         true,
		},
		{
			name:         "config hash mismatch",
			existing:     matchingExistingContainer("stale-hash", fileEnvKeysHash, networkName, image, container.StateRunning),
			desiredImage: image,
			want:         true,
		},
		{
			name:         "file env keys hash mismatch",
			existing:     matchingExistingContainer(configHash, "stale-file-hash", networkName, image, container.StateRunning),
			desiredImage: image,
			want:         true,
		},
		{
			name:         "network missing",
			existing:     matchingExistingContainer(configHash, fileEnvKeysHash, "other-network", image, container.StateRunning),
			desiredImage: image,
			want:         true,
		},
		{
			name:         "image mismatch",
			existing:     matchingExistingContainer(configHash, fileEnvKeysHash, networkName, "stale-image", container.StateRunning),
			desiredImage: image,
			want:         true,
		},
		{
			name:         "empty desired image never mismatches (containerized runtime tracks image via config hash instead)",
			existing:     matchingExistingContainer(configHash, fileEnvKeysHash, networkName, "any-image", container.StateRunning),
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
			cfg, err := acquireImageThenBoundStartup(context.Background(), 50*time.Millisecond, true, pull, createOrReuse)
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

		if _, err := acquireImageThenBoundStartup(context.Background(), startupTimeout, true, pull, createOrReuse); err != nil {
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
		ctx, cancel := context.WithCancel(context.Background())

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

		_, err := acquireImageThenBoundStartup(context.Background(), time.Second, true, pull, createOrReuse)
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

		cfg, err := acquireImageThenBoundStartup(context.Background(), time.Second, false, pull, createOrReuse)
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

func TestMCPDockerResourcesParsesLimits(t *testing.T) {
	res, err := mcpDockerResources("1g", "1", "512")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Memory != 1024*1024*1024 {
		t.Fatalf("expected 1GiB memory, got %d", res.Memory)
	}
	if res.NanoCPUs != 1_000_000_000 {
		t.Fatalf("expected 1 CPU in nanocpus, got %d", res.NanoCPUs)
	}
	if res.PidsLimit == nil || *res.PidsLimit != 512 {
		t.Fatalf("expected pids limit 512, got %v", res.PidsLimit)
	}
}

func TestMCPDockerResourcesEmptyLeavesUncapped(t *testing.T) {
	res, err := mcpDockerResources("", "  ", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Memory != 0 || res.NanoCPUs != 0 || res.PidsLimit != nil {
		t.Fatalf("expected an uncapped block, got %+v", res)
	}
}

func TestMCPDockerResourcesRejectsGarbage(t *testing.T) {
	for _, tc := range []struct {
		name                    string
		memory, cpus, pidsLimit string
	}{
		{name: "memory", memory: "banana", cpus: "1", pidsLimit: "512"},
		{name: "cpus", memory: "1g", cpus: "banana", pidsLimit: "512"},
		{name: "pids", memory: "1g", cpus: "1", pidsLimit: "banana"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := mcpDockerResources(tc.memory, tc.cpus, tc.pidsLimit); err == nil {
				t.Fatal("expected an error, got nil")
			}
		})
	}
}

func TestNewMCPServerHostConfigAppliesResourceCeiling(t *testing.T) {
	pids := int64(512)
	hc := newMCPServerHostConfig("8099/tcp", nil, container.Resources{
		Memory:    1024 * 1024 * 1024,
		NanoCPUs:  1_000_000_000,
		PidsLimit: &pids,
	})

	if hc.Memory != 1024*1024*1024 {
		t.Fatalf("expected the memory ceiling on the host config, got %d", hc.Memory)
	}
	if hc.NanoCPUs != 1_000_000_000 {
		t.Fatalf("expected the CPU ceiling on the host config, got %d", hc.NanoCPUs)
	}
	if hc.PidsLimit == nil || *hc.PidsLimit != 512 {
		t.Fatalf("expected the pids ceiling on the host config, got %v", hc.PidsLimit)
	}
	if hc.RestartPolicy.Name != "unless-stopped" {
		t.Fatalf("resource ceiling must not disturb the restart policy, got %q", hc.RestartPolicy.Name)
	}
}
