package vmcp

import (
	"encoding/json"
	"slices"
	"testing"

	"github.com/obot-platform/obot/apiclient/types"
	v1 "github.com/obot-platform/obot/pkg/storage/apis/obot.obot.ai/v1"
)

func TestMissingRequiredConfiguration(t *testing.T) {
	component := types.VMCPComponent{
		ID: "one",
		Configuration: []types.VMCPConfigurationPolicy{
			{Key: "FIXED", Policy: types.VMCPConfigurationPolicyFixed},
			{Key: "USER", Policy: types.VMCPConfigurationPolicyUserAllowed},
			{Key: "HEADER", Policy: types.VMCPConfigurationPolicyUserAllowed},
		},
		CatalogEntry: types.MCPServerCatalogEntrySnapshot{Manifest: types.MCPServerCatalogEntryManifest{
			Config: []types.MCPConfig{
				{Key: "FIXED", Required: true, Usage: types.Env},
				{Key: "USER", Required: true, Usage: types.File},
				{Key: "PROHIBITED", Required: true, Usage: types.Env},
				{Key: "STATIC", Required: true, Static: true, Usage: types.Env},
				{Key: "OPTIONAL", Usage: types.Env},
				{Key: "HEADER", Required: true, Usage: types.Header},
			},
		}},
	}
	values := map[string]string{ConfigurationKey(component.ID, "FIXED"): "secret", ConfigurationKey(component.ID, "PROHIBITED"): "stale"}
	if got := MissingRequiredConfiguration(component, values, false); !slices.Equal(got, []string{ConfigurationKey("one", "PROHIBITED")}) {
		t.Fatalf("administrator missing = %v", got)
	}
	if got := MissingRequiredConfiguration(component, values, true); !slices.Equal(got, []string{ConfigurationKey("one", "HEADER"), ConfigurationKey("one", "USER")}) {
		t.Fatalf("user missing = %v", got)
	}
	values[ConfigurationKey("one", "USER")] = "file contents"
	values[ConfigurationKey("one", "HEADER")] = "header secret"
	if got := MissingRequiredConfiguration(component, values, true); len(got) != 0 {
		t.Fatalf("configured inputs reported missing: %v", got)
	}
}

func TestConfiguredComponents(t *testing.T) {
	// Both components declare the same key name, so only the component-scoped
	// keys distinguish them.
	needsUserInput := func(id string) types.VMCPComponent {
		return types.VMCPComponent{
			ID:            id,
			Configuration: []types.VMCPConfigurationPolicy{{Key: "USER", Policy: types.VMCPConfigurationPolicyUserAllowed}},
			CatalogEntry: types.MCPServerCatalogEntrySnapshot{Manifest: types.MCPServerCatalogEntryManifest{
				Config: []types.MCPConfig{{Key: "USER", Required: true, Usage: types.File}},
			}},
		}
	}
	adminConfigured := types.VMCPComponent{
		ID:            "admin",
		Configuration: []types.VMCPConfigurationPolicy{{Key: "FIXED", Policy: types.VMCPConfigurationPolicyFixed}},
		CatalogEntry: types.MCPServerCatalogEntrySnapshot{Manifest: types.MCPServerCatalogEntryManifest{
			Config: []types.MCPConfig{{Key: "FIXED", Required: true, Usage: types.Env}},
		}},
	}

	for _, tc := range []struct {
		name       string
		components []types.VMCPComponent
		missing    []string
		want       []string
	}{
		{
			name:       "own required input missing",
			components: []types.VMCPComponent{needsUserInput("one"), needsUserInput("two")},
			missing:    []string{ConfigurationKey("one", "USER")},
			want:       []string{"two"},
		},
		{
			name:       "own required input supplied",
			components: []types.VMCPComponent{needsUserInput("one"), needsUserInput("two")},
			missing:    []string{ConfigurationKey("one", "OTHER")},
			want:       []string{"one", "two"},
		},
		{
			name:       "only another component's key missing",
			components: []types.VMCPComponent{needsUserInput("one"), needsUserInput("two")},
			missing:    []string{ConfigurationKey("two", "USER")},
			want:       []string{"one"},
		},
		{
			name:       "no required userAllowed input",
			components: []types.VMCPComponent{adminConfigured},
			missing:    []string{ConfigurationKey("admin", "FIXED")},
			want:       []string{"admin"},
		},
		{
			name:       "nothing missing keeps every component",
			components: []types.VMCPComponent{needsUserInput("one"), adminConfigured},
			want:       []string{"one", "admin"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var got []string
			for _, component := range ConfiguredComponents(tc.components, tc.missing) {
				got = append(got, component.ID)
			}
			if !slices.Equal(got, tc.want) {
				t.Fatalf("configured components = %v, want %v", got, tc.want)
			}
		})
	}

	// Callers pass slices derived from other structures, so the input must not
	// be reordered or truncated in place.
	backing := []types.VMCPComponent{needsUserInput("one"), adminConfigured, needsUserInput("two")}
	got := ConfiguredComponents(backing[:2], []string{ConfigurationKey("one", "USER")})
	if len(got) != 1 || got[0].ID != "admin" {
		t.Fatalf("configured components = %+v", got)
	}
	if backing[0].ID != "one" || backing[1].ID != "admin" || backing[2].ID != "two" {
		t.Fatalf("mutated the caller's backing array: %+v", backing)
	}
}

func TestMissingRequiredConfigurationFixedSecretBinding(t *testing.T) {
	component := types.VMCPComponent{
		ID: "gitlab",
		Configuration: []types.VMCPConfigurationPolicy{{
			Key:           "GITLAB_PERSONAL_ACCESS_TOKEN",
			Policy:        types.VMCPConfigurationPolicyFixed,
			SecretBinding: &types.MCPSecretBinding{Name: "gitlab-secret", Key: "gitlab_key"},
		}},
		CatalogEntry: types.MCPServerCatalogEntrySnapshot{Manifest: types.MCPServerCatalogEntryManifest{
			Config: []types.MCPConfig{{Key: "GITLAB_PERSONAL_ACCESS_TOKEN", Required: true, Sensitive: true, Usage: types.Env}},
		}},
	}

	if got := MissingRequiredConfiguration(component, nil, false); len(got) != 0 {
		t.Fatalf("secret-bound configuration reported missing: %v", got)
	}

	config := ComponentConfig(component)
	if len(config) != 1 || config[0].SecretBinding == nil || *config[0].SecretBinding != *component.Configuration[0].SecretBinding {
		t.Fatalf("ComponentConfig() did not apply secret binding: %+v", config)
	}
	if component.CatalogEntry.Manifest.Config[0].SecretBinding != nil {
		t.Fatal("ComponentConfig() mutated the catalog entry snapshot")
	}
}

// A connection must still read as synced after storage drops its empty Config.
func TestConnectionConfigurationSyncedSurvivesStorageRoundTrip(t *testing.T) {
	instance := v1.VMCPInstance{Status: v1.VMCPInstanceStatus{UserConfigurationHash: "saved"}}
	for _, tc := range []struct {
		name      string
		component types.VMCPComponent
	}{
		{
			name:      "no configuration",
			component: types.VMCPComponent{ID: "one"},
		},
		{
			name: "only fixed configuration",
			component: types.VMCPComponent{
				ID:            "one",
				Configuration: []types.VMCPConfigurationPolicy{{Key: "FIXED", Policy: types.VMCPConfigurationPolicyFixed}},
				CatalogEntry: types.MCPServerCatalogEntrySnapshot{Manifest: types.MCPServerCatalogEntryManifest{
					Config: []types.MCPConfig{{Key: "FIXED", Required: true, Usage: types.Header}},
				}},
			},
		},
		{
			name: "user configuration with empty options",
			component: types.VMCPComponent{
				ID:            "one",
				Configuration: []types.VMCPConfigurationPolicy{{Key: "TOKEN", Policy: types.VMCPConfigurationPolicyUserAllowed}},
				CatalogEntry: types.MCPServerCatalogEntrySnapshot{Manifest: types.MCPServerCatalogEntryManifest{
					Config: []types.MCPConfig{{Key: "TOKEN", Required: true, Usage: types.Header, Options: []types.MCPConfigurationOption{}}},
				}},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Record the sync the way the MCPServerInstance controller does.
			config := ConnectionConfiguration(tc.component)
			connection := v1.MCPServerInstance{
				Spec:   v1.MCPServerInstanceSpec{Config: config},
				Status: v1.MCPServerInstanceStatus{VMCPConfigurationHash: ConnectionConfigurationHash(config, instance)},
			}

			stored, err := json.Marshal(connection)
			if err != nil {
				t.Fatal(err)
			}
			var loaded v1.MCPServerInstance
			if err := json.Unmarshal(stored, &loaded); err != nil {
				t.Fatal(err)
			}

			if !ConnectionConfigurationSynced(loaded, tc.component, instance) {
				t.Fatalf("stored connection %s is not synced", stored)
			}
		})
	}
}
