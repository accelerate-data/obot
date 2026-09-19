package types

const (
	SystemMCPServerTypeFilter SystemMCPServerType = "filter"
)

type SystemMCPCatalogManifest struct {
	DisplayName               string            `json:"displayName"`
	SourceURLs                []string          `json:"sourceURLs"`
	SourceURLCredentials      map[string]string `json:"sourceURLCredentials,omitempty"`
	SourceURLGitCredentialIDs map[string]string `json:"sourceURLGitCredentialIDs,omitempty"`
}

type SystemMCPServerType string

type SystemMCPCatalog struct {
	Metadata
	SystemMCPCatalogManifest
	LastSynced Time              `json:"lastSynced,omitzero"`
	SyncErrors map[string]string `json:"syncErrors,omitempty"`
	IsSyncing  bool              `json:"isSyncing,omitempty"`
}

type SystemMCPCatalogList List[SystemMCPCatalog]

type SystemMCPServerCatalogEntry struct {
	Metadata
	Manifest                  SystemMCPServerCatalogEntryManifest `json:"manifest"`
	Editable                  bool                                `json:"editable,omitempty"`
	CatalogName               string                              `json:"catalogName,omitempty"`
	SourceURL                 string                              `json:"sourceURL,omitempty"`
	LastUpdated               *Time                               `json:"lastUpdated,omitempty"`
	ToolPreviewsLastGenerated *Time                               `json:"toolPreviewsLastGenerated,omitempty"`
	NeedsUpdate               bool                                `json:"needsUpdate,omitempty"`
	OAuthCredentialConfigured bool                                `json:"oauthCredentialConfigured,omitempty"`
}

type SystemMCPServerCatalogEntryManifest struct {
	Metadata         map[string]string `json:"metadata,omitempty"`
	Name             string            `json:"name"`
	ShortDescription string            `json:"shortDescription"`
	Description      string            `json:"description"`
	Icon             string            `json:"icon"`
	RepoURL          string            `json:"repoURL,omitempty"`
	ToolPreview      []MCPServerTool   `json:"toolPreview,omitempty"`

	SystemMCPServerType SystemMCPServerType `json:"systemMCPServerType,omitempty"`

	FilterConfig *FilterConfig `json:"filterConfig,omitempty"`

	Runtime Runtime `json:"runtime"`

	UVXConfig           *UVXRuntimeConfig           `json:"uvxConfig,omitempty"`
	NPXConfig           *NPXRuntimeConfig           `json:"npxConfig,omitempty"`
	ContainerizedConfig *ContainerizedRuntimeConfig `json:"containerizedConfig,omitempty"`
	RemoteConfig        *RemoteCatalogConfig        `json:"remoteConfig,omitempty"`

	Config []MCPConfig `json:"config,omitempty"`

	Resources *MCPResourceRequirements `json:"resources,omitempty"`

	// Deprecated: retained to decode catalog source files still using the pre-vMCP schema; migrated into Config on load.
	DeprecatedServerUserType  ServerUserType   `json:"serverUserType,omitempty"`
	DeprecatedMultiUserConfig *MultiUserConfig `json:"multiUserConfig,omitempty"`
	DeprecatedEnv             []MCPEnv         `json:"env,omitempty"`
}

// MigrateDeprecatedCatalogFields folds the pre-vMCP catalog fields into the
// unified Config list, matching MCPServerCatalogEntryManifest. It is called
// once per decode.
func (m *SystemMCPServerCatalogEntryManifest) MigrateDeprecatedCatalogFields() {
	m.Config = append(m.Config, deprecatedCatalogConfig(m.DeprecatedEnv, m.RemoteConfig, m.DeprecatedMultiUserConfig)...)
}

func (m SystemMCPServerCatalogEntryManifest) ValidateConfig() error {
	return (MCPServerCatalogEntryManifest{Config: m.Config}).ValidateConfig()
}

type FilterConfig struct {
	ToolName string `json:"toolName"`
}

type SystemMCPServerCatalogEntryList List[SystemMCPServerCatalogEntry]
