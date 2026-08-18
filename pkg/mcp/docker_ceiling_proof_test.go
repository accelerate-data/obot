package mcp

// TEMPORARY proof harness. Delete this file, and the workflow that runs it,
// once the acceptance evidence is recorded. It exists to prove against a real
// Docker daemon that the configured ceiling actually reaches the container —
// the one claim no unit test can make, because only the daemon can confirm it
// accepted and applied the HostConfig.

import (
	"context"
	"fmt"
	"io"
	"testing"

	"github.com/docker/go-connections/nat"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/image"
	"github.com/moby/moby/client"
)

const ceilingProofImage = "alpine:3.20"

func TestDockerCeilingLandsOnRealContainer(t *testing.T) {
	ctx := context.Background()

	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		t.Skipf("no Docker client: %v", err)
	}
	defer func() { _ = cli.Close() }()

	if _, err := cli.Ping(ctx); err != nil {
		t.Skipf("no Docker daemon reachable: %v", err)
	}

	pull, err := cli.ImagePull(ctx, ceilingProofImage, image.PullOptions{})
	if err != nil {
		t.Fatalf("failed to pull %s: %v", ceilingProofImage, err)
	}
	if _, err := io.Copy(io.Discard, pull); err != nil {
		t.Fatalf("failed to drain image pull: %v", err)
	}
	_ = pull.Close()

	for _, tc := range []struct {
		name                    string
		memory, cpus, pidsLimit string
		wantMemory              int64
		wantNanoCPUs            int64
		wantPidsLimit           int64
	}{
		{
			name: "shipped defaults", memory: "1g", cpus: "1", pidsLimit: "512",
			wantMemory: 1024 * 1024 * 1024, wantNanoCPUs: 1_000_000_000, wantPidsLimit: 512,
		},
		{
			name: "empty escape hatch", memory: "", cpus: "", pidsLimit: "",
			wantMemory: 0, wantNanoCPUs: 0, wantPidsLimit: 0,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resources, err := mcpDockerResources(tc.memory, tc.cpus, tc.pidsLimit)
			if err != nil {
				t.Fatalf("failed to parse ceilings: %v", err)
			}

			hostConfig := newMCPServerHostConfig("8099/tcp", nil, resources)
			config := &container.Config{
				Image:        ceilingProofImage,
				Cmd:          []string{"sleep", "30"},
				ExposedPorts: nat.PortSet{"8099/tcp": struct{}{}},
			}

			name := fmt.Sprintf("vd4348-ceiling-proof-%d", len(tc.memory))
			_ = cli.ContainerRemove(ctx, name, container.RemoveOptions{Force: true})

			resp, err := cli.ContainerCreate(ctx, config, hostConfig, nil, nil, name)
			if err != nil {
				t.Fatalf("failed to create container: %v", err)
			}
			defer func() {
				_ = cli.ContainerRemove(ctx, resp.ID, container.RemoveOptions{Force: true})
			}()

			// Starting it matters: create alone can accept a value the daemon
			// later rejects when it applies the cgroup.
			if err := cli.ContainerStart(ctx, resp.ID, container.StartOptions{}); err != nil {
				t.Fatalf("failed to start container: %v", err)
			}

			inspect, err := cli.ContainerInspect(ctx, resp.ID)
			if err != nil {
				t.Fatalf("failed to inspect container: %v", err)
			}

			gotPids := int64(0)
			if inspect.HostConfig.PidsLimit != nil {
				gotPids = *inspect.HostConfig.PidsLimit
			}
			t.Logf(
				"docker inspect %s -> mem=%d nanocpus=%d pids=%d",
				name, inspect.HostConfig.Memory, inspect.HostConfig.NanoCPUs, gotPids,
			)

			if inspect.HostConfig.Memory != tc.wantMemory {
				t.Fatalf("memory: want %d, got %d", tc.wantMemory, inspect.HostConfig.Memory)
			}
			if inspect.HostConfig.NanoCPUs != tc.wantNanoCPUs {
				t.Fatalf("nanocpus: want %d, got %d", tc.wantNanoCPUs, inspect.HostConfig.NanoCPUs)
			}
			if gotPids != tc.wantPidsLimit {
				t.Fatalf("pids limit: want %d, got %d", tc.wantPidsLimit, gotPids)
			}
		})
	}
}
