package client

import (
	"context"
	"fmt"
	"net/url"
	"testing"
	"time"

	apitypes "github.com/obot-platform/obot/apiclient/types"
	gatewaydb "github.com/obot-platform/obot/pkg/gateway/db"
	gatewaytypes "github.com/obot-platform/obot/pkg/gateway/types"
	v1 "github.com/obot-platform/obot/pkg/storage/apis/obot.obot.ai/v1"
	storagescheme "github.com/obot-platform/obot/pkg/storage/scheme"
	"github.com/obot-platform/obot/pkg/system"
	"gorm.io/gorm"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestEnsureIdentityGenericOAuthConcurrentlyAcrossPostgresClients(t *testing.T) {
	scopedDSN, adminDB := newCredentialLockPostgresTest(t)
	schema := postgresSearchPath(t, scopedDSN)

	dbA := newPostgresUserLimitTestDB(t, scopedDSN)
	dbB := newPostgresUserLimitTestDB(t, scopedDSN)
	if err := dbA.WithContext(t.Context()).AutoMigrate(
		&gatewaytypes.Migration{},
		&gatewaytypes.User{},
		&gatewaytypes.Identity{},
		&gatewaytypes.Credential{},
		&gatewaytypes.Group{},
		&gatewaytypes.GroupMemberships{},
		&gatewaytypes.GroupRoleAssignment{},
	); err != nil {
		t.Fatalf("migrating PostgreSQL gateway tables for generic OAuth identities: %v", err)
	}

	clientA := newPostgresGenericOAuthTestClient(t, dbA, "https://issuer.example.com/", "true")
	clientB := newPostgresGenericOAuthTestClient(t, dbB, "https://issuer.example.com/", "true")

	lockTx := adminDB.WithContext(t.Context()).Begin()
	if lockTx.Error != nil {
		t.Fatalf("starting identities table lock transaction: %v", lockTx.Error)
	}
	lockHeld := true
	defer func() {
		if lockHeld {
			_ = lockTx.Rollback().Error
		}
	}()
	if err := lockTx.Exec(fmt.Sprintf("LOCK TABLE %s.identities IN SHARE MODE", schema)).Error; err != nil {
		t.Fatalf("holding identities table lock: %v", err)
	}

	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()

	type ensureResult struct {
		user *gatewaytypes.User
		err  error
	}

	start := make(chan struct{})
	results := make(chan ensureResult, 2)
	for _, c := range []*Client{clientA, clientB} {
		go func(c *Client) {
			<-start
			user, err := c.EnsureIdentity(ctx, newGenericOAuthConcurrentTestIdentity(), "", UserLimit{Unlimited: true})
			results <- ensureResult{user: user, err: err}
		}(c)
	}
	close(start)

	if err := waitForPostgresRelationLockWaiters(ctx, adminDB, fmt.Sprintf("%s.identities", schema), 2); err != nil {
		t.Fatalf("waiting for concurrent generic OAuth inserts to block on identities table: %v", err)
	}

	if err := lockTx.Commit().Error; err != nil {
		t.Fatalf("releasing identities table lock: %v", err)
	}
	lockHeld = false

	var users []*gatewaytypes.User
	for range 2 {
		select {
		case result := <-results:
			if result.err != nil {
				t.Fatalf("concurrent generic OAuth EnsureIdentity returned error: %v", result.err)
			}
			users = append(users, result.user)
		case <-ctx.Done():
			t.Fatalf("concurrent generic OAuth EnsureIdentity did not finish: %v", ctx.Err())
		}
	}

	if len(users) != 2 {
		t.Fatalf("concurrent generic OAuth EnsureIdentity results = %d, want 2", len(users))
	}
	if users[0].ID == 0 {
		t.Fatal("first concurrent generic OAuth EnsureIdentity returned user ID 0")
	}
	if users[1].ID != users[0].ID {
		t.Fatalf("concurrent generic OAuth EnsureIdentity returned user IDs %d and %d, want one shared user", users[0].ID, users[1].ID)
	}
	if got := countIdentityUserLimitTestUsers(t, clientA, false); got != 1 {
		t.Fatalf("users = %d, want 1", got)
	}
	if got := countIdentityUserLimitTestIdentities(t, clientA); got != 1 {
		t.Fatalf("identities = %d, want 1", got)
	}
}

func newPostgresGenericOAuthTestClient(t *testing.T, database *gatewaydb.DB, issuer, trust string) *Client {
	t.Helper()

	client := &Client{
		db: database,
		storageClient: fake.NewClientBuilder().
			WithScheme(storagescheme.Scheme).
			WithObjects(
				&v1.AuthProvider{
					ObjectMeta: metav1.ObjectMeta{
						Name:      genericOAuthAuthProviderName,
						Namespace: system.DefaultNamespace,
					},
				},
				&v1.UserDefaultRoleSetting{
					ObjectMeta: metav1.ObjectMeta{
						Name:      system.DefaultRoleSettingName,
						Namespace: system.DefaultNamespace,
					},
					Spec: v1.UserDefaultRoleSettingSpec{
						Role: apitypes.RoleBasic,
					},
				},
			).
			Build(),
	}
	if err := client.UpsertCredential(t.Context(), gatewaytypes.Credential{
		Context: genericOAuthAuthProviderName,
		Name:    genericOAuthAuthProviderName,
		Secrets: map[string]string{
			genericOAuthIssuerEnvVar:         issuer,
			genericOAuthTrustEmailLinkingVar: trust,
		},
	}); err != nil {
		t.Fatalf("seeding generic OAuth credential: %v", err)
	}
	return client
}

func newGenericOAuthConcurrentTestIdentity() *gatewaytypes.Identity {
	emailVerified := true
	return &gatewaytypes.Identity{
		Email:                 "alice@example.com",
		AuthProviderName:      genericOAuthAuthProviderName,
		AuthProviderNamespace: system.DefaultNamespace,
		ProviderUsername:      "alice@example.com",
		ProviderUserID:        "iss:https://issuer.example.com/|sub:alice",
		ProviderIssuer:        "https://issuer.example.com/",
		ProviderEmailVerified: &emailVerified,
	}
}

func postgresSearchPath(t *testing.T, dsn string) string {
	t.Helper()

	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatalf("parsing scoped PostgreSQL DSN: %v", err)
	}
	schema := u.Query().Get("search_path")
	if schema == "" {
		t.Fatal("scoped PostgreSQL DSN missing search_path")
	}
	return schema
}

func waitForPostgresRelationLockWaiters(ctx context.Context, db *gorm.DB, relation string, want int64) error {
	const pollInterval = 10 * time.Millisecond

	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	for {
		var waiters int64
		if err := db.WithContext(ctx).Raw(`
			SELECT COUNT(*)
			FROM pg_locks
			WHERE locktype = 'relation'
			  AND relation = CAST(? AS regclass)
			  AND mode = 'RowExclusiveLock'
			  AND NOT granted
		`, relation).Scan(&waiters).Error; err != nil {
			return err
		}
		if waiters == want {
			return nil
		}

		select {
		case <-ctx.Done():
			return fmt.Errorf("found %d of %d relation lock waiters: %w", waiters, want, ctx.Err())
		case <-ticker.C:
		}
	}
}
