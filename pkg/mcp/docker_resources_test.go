package mcp

import (
	"testing"

	"github.com/moby/moby/api/types/container"
)

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
		{name: "malformed memory", memory: "banana", cpus: "1", pidsLimit: "512"},
		{name: "malformed cpus", memory: "1g", cpus: "banana", pidsLimit: "512"},
		{name: "malformed pids", memory: "1g", cpus: "1", pidsLimit: "banana"},
		{name: "memory under Docker's floor", memory: "4m", cpus: "1", pidsLimit: "512"},
		{name: "zero cpus", memory: "1g", cpus: "0", pidsLimit: "512"},
		{name: "negative cpus", memory: "1g", cpus: "-1", pidsLimit: "512"},
		{name: "zero pids", memory: "1g", cpus: "1", pidsLimit: "0"},
		{name: "negative pids", memory: "1g", cpus: "1", pidsLimit: "-5"},
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
