package oidcjwt

import (
	"strings"
)

const (
	defaultEligibilityClaimName = "eligible"
	defaultRolesClaimName       = "roles"
)

var (
	defaultAdminRoles = []string{"admin"}
	defaultOwnerRoles = []string{"owner"}
)

type Config struct {
	IssuerURL            string
	Audience             string
	EligibilityClaimName string
	RolesClaimName       string
	AdminRoles           []string
	OwnerRoles           []string
}

func NormalizeIssuer(s string) string {
	return strings.TrimRight(strings.TrimSpace(s), "/")
}

func (c Config) Enabled() bool {
	return c.IssuerURL != "" && c.Audience != ""
}

func LoadConfigFromEnv(getenv func(string) string) Config {
	issuer := getenv("OBOT_GENERIC_OAUTH_AUTH_PROVIDER_ISSUER")
	cfg := Config{
		IssuerURL:            NormalizeIssuer(issuer),
		Audience:             getenv("OBOT_GENERIC_OAUTH_AUTH_PROVIDER_AUDIENCE"),
		EligibilityClaimName: getenv("OBOT_GENERIC_OAUTH_AUTH_PROVIDER_ELIGIBILITY_CLAIM_NAME"),
		RolesClaimName:       getenv("OBOT_GENERIC_OAUTH_AUTH_PROVIDER_ROLES_CLAIM_NAME"),
	}
	if cfg.EligibilityClaimName == "" {
		cfg.EligibilityClaimName = defaultEligibilityClaimName
	}
	if cfg.RolesClaimName == "" {
		cfg.RolesClaimName = defaultRolesClaimName
	}

	cfg.AdminRoles = configuredRoles(getenv("OBOT_GENERIC_OAUTH_AUTH_PROVIDER_ADMIN_ROLES"), defaultAdminRoles)
	cfg.OwnerRoles = configuredRoles(getenv("OBOT_GENERIC_OAUTH_AUTH_PROVIDER_OWNER_ROLES"), defaultOwnerRoles)
	return cfg
}

func configuredRoles(value string, defaults []string) []string {
	if value == "" {
		return defaults
	}
	var roles []string
	for role := range strings.SplitSeq(value, ",") {
		if trimmed := strings.TrimSpace(role); trimmed != "" {
			roles = append(roles, trimmed)
		}
	}
	return roles
}
