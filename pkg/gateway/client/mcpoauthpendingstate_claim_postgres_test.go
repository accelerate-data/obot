package client

// Fork-only guarantee (VD-4888, restored by VD-6886), proven on PostgreSQL:
// production Obot runs on PostgreSQL, where concurrent callbacks can arrive on
// different backend replicas, each with its own connection pool. The SQLite
// variant in mcpoauthpendingstate_claim_test.go cannot exercise that.

import (
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"uuid"

	gatewaydb "github.com/obot-platform/obot/pkg/gateway/db"
	storageservices "github.com/obot-platform/obot/pkg/storage/services"
)

func TestClaimMCPOAuthPendingStateExactlyOnceAcrossPostgresClients(t *testing.T) {
	postgresDSN := os.Getenv(postgresUserLimitTestDSNEnv)
	if postgresDSN == "" {
		t.Skipf("set %s to a PostgreSQL URL whose user can create schemas", postgresUserLimitTestDSNEnv)
	}

	adminServices, err := storageservices.New(storageservices.Config{DSN: postgresDSN})
	if err != nil {
		t.Fatalf("opening PostgreSQL admin connection: %v", err)
	}
	schema := "obot_oauth_claim_" + strings.ReplaceAll(uuid.New().String(), "-", "")
	if err := adminServices.DB.DB.Exec("CREATE SCHEMA " + schema).Error; err != nil {
		_ = adminServices.DB.SQLDB.Close()
		t.Fatalf("creating isolated PostgreSQL schema: %v", err)
	}
	t.Cleanup(func() {
		if err := adminServices.DB.DB.Exec("DROP SCHEMA " + schema + " CASCADE").Error; err != nil {
			t.Errorf("dropping isolated PostgreSQL schema: %v", err)
		}
		if err := adminServices.DB.SQLDB.Close(); err != nil {
			t.Errorf("closing PostgreSQL admin connection: %v", err)
		}
	})

	// Each client owns a separate connection pool, as separate replicas would.
	const replicas = 4
	scopedDSN := postgresUserLimitTestDSN(t, postgresDSN, schema)
	clients := make([]*Client, replicas)
	for i := range clients {
		clients[i] = &Client{db: newPostgresUserLimitTestDB(t, scopedDSN)}
	}
	// Run the production migrations, including the claimed_at column this
	// guarantee depends on, rather than migrating only the pending-state table.
	migrator, err := storageservices.New(storageservices.Config{DSN: scopedDSN})
	if err != nil {
		t.Fatalf("opening PostgreSQL migration connection: %v", err)
	}
	migratingDB, err := gatewaydb.New(migrator.DB.DB, migrator.DB.SQLDB, true)
	if err != nil {
		t.Fatalf("creating migrating gateway database: %v", err)
	}
	if err := migratingDB.AutoMigrate(); err != nil {
		t.Fatalf("migrating PostgreSQL gateway tables: %v", err)
	}
	if err := migrator.DB.SQLDB.Close(); err != nil {
		t.Fatalf("closing PostgreSQL migration connection: %v", err)
	}

	for _, tc := range []struct {
		name   string
		mcpURL string
	}{
		{name: "dynamic", mcpURL: "https://mcp.example/api"},
		{name: "container", mcpURL: ContainerOAuthResourcePrefix + "deployment-1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			state := "callback-state-" + tc.name
			createDynamicOAuthPendingState(t, clients[0], tc.mcpURL, state)

			const attemptsPerReplica = 4
			start := make(chan struct{})
			results := make(chan error, replicas*attemptsPerReplica)
			var wg sync.WaitGroup
			for _, c := range clients {
				for range attemptsPerReplica {
					wg.Go(func() {
						<-start
						_, err := c.ClaimMCPOAuthPendingState(t.Context(), state)
						results <- err
					})
				}
			}
			close(start)
			wg.Wait()
			close(results)

			var claimed int
			for err := range results {
				if err == nil {
					claimed++
				} else if !errors.Is(err, ErrMCPOAuthPendingStateInvalid) {
					t.Fatalf("claim pending state: %v", err)
				}
			}
			if claimed != 1 {
				t.Fatalf("successful claims = %d, want exactly 1", claimed)
			}
		})
	}
}
