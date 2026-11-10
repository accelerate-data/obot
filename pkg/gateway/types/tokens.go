//nolint:revive
package types

import (
	"time"

	apitypes "github.com/obot-platform/obot/apiclient/types"
	v1 "github.com/obot-platform/obot/pkg/storage/apis/obot.obot.ai/v1"
	"golang.org/x/oauth2"
)

const (
	TokenRequestPurposeDeviceLogin = "device-login"
	TokenRequestPurposeSetup       = "setup"

	// TokenRequestPurposeAuthProviderVerify backs the one-time login used to prove a staged
	// replacement auth provider works before it is activated.
	TokenRequestPurposeAuthProviderVerify = "auth-provider-verify"
)

type AuthToken struct {
	ID                    string    `json:"id" gorm:"index:idx_id_hashed_token"`
	UserID                uint      `json:"-" gorm:"index"`
	AuthProviderNamespace string    `json:"-" gorm:"index"`
	AuthProviderName      string    `json:"-" gorm:"index"`
	AuthProviderUserID    string    `json:"-"`
	HashedToken           string    `json:"-" gorm:"index:idx_id_hashed_token"`
	CreatedAt             time.Time `json:"createdAt"`
	ExpiresAt             time.Time `json:"expiresAt,omitzero"`
	NoExpiration          bool      `json:"noExpiration"`
}

type TokenRequest struct {
	ID                    string `gorm:"primaryKey"`
	CreatedAt             time.Time
	UpdatedAt             time.Time
	Purpose               string    `gorm:"index"`
	DeviceCodeDigest      *string   `gorm:"uniqueIndex"`
	RequestExpiresAt      time.Time `gorm:"index"`
	DeviceCodeVerifiedAt  *time.Time
	State                 string `gorm:"index"`
	Name                  string
	Description           string
	Scopes                APIKeyScopes `gorm:"embedded"`
	Token                 string
	NoExpiration          bool
	ExpiresAt             time.Time
	CompletionRedirectURL string
	Error                 string
	TokenRetrieved        bool

	// OwnerUserID is the user who started a staged auth provider verification. Only they may open
	// the resulting login, so a verification cannot be picked up by another signed-in user.
	OwnerUserID *uint
}

type MCPOAuthToken struct {
	oauth2.Endpoint
	ClientID     string
	ClientSecret string
	RedirectURL  string
	Scopes       string

	MCPID                       string `gorm:"primaryKey"`
	UserID                      string `gorm:"primaryKey"`
	URL                         string
	CatalogEntryName            string `gorm:"index:idx_mcp_oauth_token_catalog_entry"`
	CatalogCredentialGeneration string
	OAuthAuthRequestID          string `gorm:"index"`
	GrantID                     string
	UpstreamChallenge           string
	AccessToken                 string
	TokenType                   string
	RefreshToken                string
	Expiry                      time.Time
	ExpiresIn                   int64

	Encrypted bool
}

// MCPOAuthRevokedConnection fences late OAuth callbacks for a connection
// revoked during user offboarding. A new authorization must use a new connection ID.
type MCPOAuthRevokedConnection struct {
	UserID string `gorm:"primaryKey"`
	MCPID  string `gorm:"primaryKey"`
}

type MCPOAuthPendingState struct {
	UpstreamChallenge string
	HashedState       string `gorm:"primaryKey"`
	State             string
	Verifier          string
	UserID            string `gorm:"index:idx_pending_user_mcp"`
	MCPID             string `gorm:"index:idx_pending_user_mcp;index:idx_pending_mcp_static_test,priority:1"`
	URL               string

	// TunnelName is the MCPTunnel the server is reached through, if any. The callback's
	// code exchange goes through the same tunnel, since the token endpoint may be private.
	TunnelName                     string
	ResourceURL                    string
	CatalogEntryName               string
	CatalogCredentialGeneration    string
	OAuthAuthRequestID             string
	ClientID                       string
	ClientSecret                   string
	AuthURL                        string
	TokenURL                       string
	AuthStyle                      oauth2.AuthStyle
	RedirectURL                    string
	Scopes                         string
	StaticOAuthTest                bool   `gorm:"index:idx_pending_mcp_static_test,priority:2"`
	StaticOAuthTestStateHash       string `gorm:"index"`
	StaticOAuthTestStatus          apitypes.MCPStaticOAuthTestStatus
	StaticOAuthTestFailureCategory apitypes.MCPStaticOAuthTestFailureCategory
	StaticOAuthTestCompletedAt     time.Time
	// StaticOAuthTestClaimedAt bounds how long an admitted callback may hold the
	// test. Nil only on a row claimed before this column existed, which is treated
	// as abandoned; claiming stamps the status and this column in one statement.
	StaticOAuthTestClaimedAt *time.Time
	StaticOAuthSaveProofHash string `gorm:"index"`
	StaticOAuthSaveProof     string
	Encrypted                bool
	CreatedAt                time.Time
	// ClaimedAt is nil until a callback claims the row for exchange. A claim is
	// terminal: the row can never be claimed again, whatever the outcome.
	ClaimedAt *time.Time
}

// MCPOAuthChallenge is a short-lived, single-transaction handoff, never a grant.
type MCPOAuthChallenge struct {
	ID            string `gorm:"primaryKey"`
	CreatedAt     time.Time
	ExpiresAt     time.Time `gorm:"index"`
	UserID        string
	Namespace     string
	MCPID         string
	ClientID      string
	Resource      string
	AuthRequestID string
	Requirements  []v1.UpstreamOAuthRequirement `gorm:"serializer:json"`
}

// MCPOAuthAttemptBudget bounds repeated challenge/OAuth cycles independently of random tickets.
type MCPOAuthAttemptBudget struct {
	ID        string    `gorm:"primaryKey"`
	ExpiresAt time.Time `gorm:"index"`
	Starts    int
}
