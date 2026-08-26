package mcp

import (
	"fmt"
	"strings"

	"github.com/obot-platform/obot/apiclient/types"
)

// Manifest-time validation of catalog-owned configuration options.
//
// A configuration field carrying options offers the user a fixed set of values
// instead of free text. Enforcement of a selection against those options is not
// implemented here: the upstream catalog entries that declare options describe
// the valid values in the field description as well, so a field whose options
// are not rendered degrades to the free-text field it was before options
// existed. This file validates that a declaration is well formed, so a
// malformed one fails catalog validation rather than being silently dropped.

func remoteHeaders(config *types.RemoteRuntimeConfig) []types.MCPHeader {
	if config == nil {
		return nil
	}
	return config.Headers
}

func remoteCatalogHeaders(config *types.RemoteCatalogConfig) []types.MCPHeader {
	if config == nil {
		return nil
	}
	return config.Headers
}

func multiUserHeaders(config *types.MultiUserConfig) []types.MCPHeader {
	if config == nil {
		return nil
	}
	return config.UserDefinedHeaders
}

func validateServerConfigurationOptions(manifest types.MCPServerManifest) error {
	if err := validateConfigurationOptions(manifest.Env, remoteHeaders(manifest.RemoteConfig), multiUserHeaders(manifest.MultiUserConfig), ""); err != nil {
		return err
	}
	if manifest.CompositeConfig != nil {
		for i, component := range manifest.CompositeConfig.ComponentServers {
			if err := validateServerConfigurationOptions(component.Manifest); err != nil {
				return fmt.Errorf("compositeConfig.componentServers[%d].manifest: %w", i, err)
			}
		}
	}
	return nil
}

func validateCatalogConfigurationOptions(manifest types.MCPServerCatalogEntryManifest, prefix string) error {
	if err := validateConfigurationOptions(manifest.Env, remoteCatalogHeaders(manifest.RemoteConfig), multiUserHeaders(manifest.MultiUserConfig), prefix); err != nil {
		return err
	}
	if manifest.CompositeConfig != nil {
		for i, component := range manifest.CompositeConfig.ComponentServers {
			componentPrefix := fmt.Sprintf("%scompositeConfig.componentServers[%d].manifest.", prefix, i)
			if err := validateCatalogConfigurationOptions(component.Manifest, componentPrefix); err != nil {
				return err
			}
		}
	}
	return nil
}

func validateConfigurationOptions(envs []types.MCPEnv, remote, multiUser []types.MCPHeader, prefix string) error {
	for i, env := range envs {
		if err := validateConfigurationFieldOptions(fmt.Sprintf("%senv[%d]", prefix, i), env.MCPHeader); err != nil {
			return err
		}
	}
	for i, header := range remote {
		if err := validateConfigurationFieldOptions(fmt.Sprintf("%sremoteConfig.headers[%d]", prefix, i), header); err != nil {
			return err
		}
	}
	for i, header := range multiUser {
		if err := validateConfigurationFieldOptions(fmt.Sprintf("%smultiUserConfig.userDefinedHeaders[%d]", prefix, i), header); err != nil {
			return err
		}
	}
	return nil
}

func validateConfigurationFieldOptions(field string, config types.MCPHeader) error {
	if len(config.Options) == 0 {
		return nil
	}
	if config.Value != "" {
		return fmt.Errorf("%s.value and options are mutually exclusive", field)
	}
	if config.SecretBinding != nil {
		return fmt.Errorf("%s.secretBinding and options are mutually exclusive", field)
	}

	values := make(map[string]struct{}, len(config.Options))
	for i, option := range config.Options {
		if strings.TrimSpace(option.Name) == "" {
			return fmt.Errorf("%s.options[%d].name cannot be empty", field, i)
		}
		if strings.TrimSpace(option.Value) == "" {
			return fmt.Errorf("%s.options[%d].value cannot be empty", field, i)
		}
		if _, exists := values[option.Value]; exists {
			return fmt.Errorf("%s.options contains duplicate value %q", field, option.Value)
		}
		values[option.Value] = struct{}{}
	}
	return nil
}
