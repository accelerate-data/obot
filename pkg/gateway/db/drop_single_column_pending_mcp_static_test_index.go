package db

import (
	"github.com/obot-platform/obot/pkg/gateway/types"
	"gorm.io/gorm"
)

const (
	pendingMCPStaticTestIndexMigrationName = "recreate_idx_pending_mcp_static_test_with_mcp_id"
	pendingMCPStaticTestIndexName          = "idx_pending_mcp_static_test"
)

// dropSingleColumnPendingMCPStaticTestIndex drops the idx_pending_mcp_static_test
// that a v0.26.0 sync image created on static_o_auth_test alone. AutoMigrate never
// alters an index that already exists by name, so it only gains its leading mcp_id
// column (VD-6903) once dropped here and recreated by the AutoMigrate that follows.
func dropSingleColumnPendingMCPStaticTestIndex(tx *gorm.DB) error {
	migrator := tx.Migrator()
	if !migrator.HasTable(&types.MCPOAuthPendingState{}) || !migrator.HasIndex(&types.MCPOAuthPendingState{}, pendingMCPStaticTestIndexName) {
		return nil
	}
	return migrator.DropIndex(&types.MCPOAuthPendingState{}, pendingMCPStaticTestIndexName)
}
