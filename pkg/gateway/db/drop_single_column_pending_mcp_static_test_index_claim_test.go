package db

// Fork-only guarantee (VD-4890, restored by VD-6903): the pending static OAuth test
// index leads with mcp_id, including on a database a v0.26.0 sync image already
// created it on static_o_auth_test alone. Kept in its own file so an upstream sync
// cannot drop these tests by merging over a shared one.

import (
	"slices"
	"testing"

	"gorm.io/gorm"
)

func pendingMCPStaticTestIndexColumns(t *testing.T, sql *gorm.DB) []string {
	t.Helper()
	var columns []string
	if err := sql.Raw("SELECT name FROM pragma_index_info(?) ORDER BY seqno", pendingMCPStaticTestIndexName).Scan(&columns).Error; err != nil {
		t.Fatalf("read %s columns: %v", pendingMCPStaticTestIndexName, err)
	}
	return columns
}

func TestAutoMigrateLeadsPendingMCPStaticTestIndexWithMCPID(t *testing.T) {
	tests := []struct {
		name  string
		setup []string
	}{
		{
			name: "fresh database",
		},
		{
			name: "single-column index left by a v0.26.0 sync image",
			setup: []string{
				"CREATE TABLE mcpo_auth_pending_states (hashed_state TEXT PRIMARY KEY, mcp_id TEXT, static_o_auth_test NUMERIC)",
				"CREATE INDEX " + pendingMCPStaticTestIndexName + " ON mcpo_auth_pending_states (static_o_auth_test)",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, sql := newCatalogConfigMigrationDB(t)
			for _, statement := range tt.setup {
				if err := sql.Exec(statement).Error; err != nil {
					t.Fatalf("seed legacy schema: %v", err)
				}
			}

			if err := db.AutoMigrate(); err != nil {
				t.Fatalf("auto migrate: %v", err)
			}

			if got, want := pendingMCPStaticTestIndexColumns(t, sql), []string{"mcp_id", "static_o_auth_test"}; !slices.Equal(got, want) {
				t.Fatalf("%s columns = %v, want %v", pendingMCPStaticTestIndexName, got, want)
			}
		})
	}
}
