package client

import (
	"errors"
	"testing"

	apitypes "github.com/obot-platform/obot/apiclient/types"
	gatewaytypes "github.com/obot-platform/obot/pkg/gateway/types"
	"github.com/obot-platform/obot/pkg/hash"
	v1 "github.com/obot-platform/obot/pkg/storage/apis/obot.obot.ai/v1"
	storagescheme "github.com/obot-platform/obot/pkg/storage/scheme"
	"github.com/obot-platform/obot/pkg/system"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"k8s.io/apiserver/pkg/authentication/user"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

const (
	issuerA = "https://a.example.com/"
	issuerB = "https://b.example.com/"
)

func newIssuerBindingTestClient(t *testing.T) *Client {
	t.Helper()

	c := newTestClient(t)
	c.storageClient = fake.NewClientBuilder().
		WithScheme(storagescheme.Scheme).
		WithObjects(
			&v1.AuthProvider{Name: genericOAuthTestProviderName, Namespace: system.DefaultNamespace},
			&v1.UserDefaultRoleSetting{
				Name:      system.DefaultRoleSettingName,
				Namespace: system.DefaultNamespace,
				Spec:      v1.UserDefaultRoleSettingSpec{Role: apitypes.RoleBasic},
			},
		).
		Build()
	encryptResources(t, c, identityGroupResource, credentialGroupResource)
	return c
}

func genericOAuthSignIn(providerUserID string) *gatewaytypes.Identity {
	return &gatewaytypes.Identity{
		AuthProviderName:      genericOAuthTestProviderName,
		AuthProviderNamespace: system.DefaultNamespace,
		// Each sign-in is a distinct person, and usernames and emails are unique.
		ProviderUsername: "user-" + hash.String(providerUserID)[:12],
		ProviderUserID:   providerUserID,
		Email:            hash.String(providerUserID)[:12] + "@example.com",
	}
}

func signInGenericOAuth(t *testing.T, c *Client, providerUserID string) *gatewaytypes.User {
	t.Helper()

	u, err := c.EnsureIdentity(t.Context(), genericOAuthSignIn(providerUserID), "", UserLimit{Unlimited: true})
	require.NoError(t, err)
	return u
}

// insertLegacyGenericOAuthIdentity stores a generic OAuth identity keyed on the bare subject, as a sign-in did before
// issuer binding, and returns its user ID.
func insertLegacyGenericOAuthIdentity(t *testing.T, c *Client, subject string) uint {
	t.Helper()

	u := signInGenericOAuth(t, c, subject)
	var stored gatewaytypes.Identity
	require.NoError(t, c.db.WithContext(t.Context()).
		Where("auth_provider_name = ? AND hashed_provider_user_id = ?", genericOAuthTestProviderName, hash.String(subject)).
		First(&stored).Error)
	return u.ID
}

func configureGenericOAuthIssuer(t *testing.T, c *Client, issuer string) {
	t.Helper()

	require.NoError(t, c.UpsertCredential(t.Context(), gatewaytypes.Credential{
		Context: genericOAuthTestProviderName,
		Name:    genericOAuthTestProviderName,
		Secrets: map[string]string{genericOAuthIssuerSecret: issuer},
	}))
}

// storedProviderUserIDs returns the decrypted provider user ID of every stored generic OAuth identity.
func storedProviderUserIDs(t *testing.T, c *Client) map[string]uint {
	t.Helper()

	var identities []gatewaytypes.Identity
	require.NoError(t, c.db.WithContext(t.Context()).Where("auth_provider_name = ?", genericOAuthTestProviderName).Find(&identities).Error)
	ids := make(map[string]uint, len(identities))
	for _, id := range identities {
		require.NoError(t, c.decryptStoredIdentity(t.Context(), &id))
		require.Equal(t, hash.String(id.ProviderUserID), id.HashedProviderUserID, "the key must hash the stored provider user ID")
		ids[id.ProviderUserID] = id.UserID
	}
	return ids
}

func recordIssuerBinding(t *testing.T, c *Client) {
	t.Helper()

	require.NoError(t, c.db.WithContext(t.Context()).Create(&gatewaytypes.Migration{Name: identityIssuerBindingMigrationName}).Error)
}

func TestSignInUnderTheSameIssuerResolvesTheSameUser(t *testing.T) {
	c := newIssuerBindingTestClient(t)

	first := signInGenericOAuth(t, c, gatewaytypes.QualifyProviderUserID(issuerA, "alice"))
	second := signInGenericOAuth(t, c, gatewaytypes.QualifyProviderUserID(issuerA, "alice"))

	require.Equal(t, first.ID, second.ID)
}

func TestSignInUnderAnotherIssuerWithACollidingSubjectIsASeparateUser(t *testing.T) {
	c := newIssuerBindingTestClient(t)

	original := signInGenericOAuth(t, c, gatewaytypes.QualifyProviderUserID(issuerA, "alice"))
	colliding := signInGenericOAuth(t, c, gatewaytypes.QualifyProviderUserID(issuerB, "alice"))

	require.NotEqual(t, original.ID, colliding.ID, "a colliding subject from another issuer must not resolve to the existing user")
	require.Equal(t, map[string]uint{
		gatewaytypes.QualifyProviderUserID(issuerA, "alice"): original.ID,
		gatewaytypes.QualifyProviderUserID(issuerB, "alice"): colliding.ID,
	}, storedProviderUserIDs(t, c))
}

func TestSignInBeforeTheBackfillClaimsTheSubjectKeyedIdentity(t *testing.T) {
	c := newIssuerBindingTestClient(t)
	legacyUserID := insertLegacyGenericOAuthIdentity(t, c, "alice")

	u := signInGenericOAuth(t, c, gatewaytypes.QualifyProviderUserID(issuerA, "alice"))

	require.Equal(t, legacyUserID, u.ID, "an existing user keeps their account across the upgrade")
	require.Equal(t, map[string]uint{gatewaytypes.QualifyProviderUserID(issuerA, "alice"): legacyUserID}, storedProviderUserIDs(t, c),
		"the claimed identity is re-keyed and re-encrypted under the issuer-bound ID")
}

func TestSignInAfterTheBackfillNeverClaimsASubjectKeyedIdentity(t *testing.T) {
	c := newIssuerBindingTestClient(t)
	legacyUserID := insertLegacyGenericOAuthIdentity(t, c, "alice")
	recordIssuerBinding(t, c)

	u := signInGenericOAuth(t, c, gatewaytypes.QualifyProviderUserID(issuerB, "alice"))

	require.NotEqual(t, legacyUserID, u.ID, "a subject-keyed identity the backfill left behind must not be claimed by another issuer")
	require.Equal(t, map[string]uint{
		"alice": legacyUserID,
		gatewaytypes.QualifyProviderUserID(issuerB, "alice"): u.ID,
	}, storedProviderUserIDs(t, c))
}

func TestBackfillBindsSubjectKeyedIdentitiesToTheConfiguredIssuer(t *testing.T) {
	c := newIssuerBindingTestClient(t)
	aliceID := insertLegacyGenericOAuthIdentity(t, c, "alice")
	bobID := insertLegacyGenericOAuthIdentity(t, c, "bob")
	carol := signInGenericOAuth(t, c, gatewaytypes.QualifyProviderUserID(issuerB, "carol"))
	configureGenericOAuthIssuer(t, c, issuerA)

	require.NoError(t, c.BackfillIdentityIssuerBinding(t.Context()))

	require.Equal(t, map[string]uint{
		gatewaytypes.QualifyProviderUserID(issuerA, "alice"): aliceID,
		gatewaytypes.QualifyProviderUserID(issuerA, "bob"):   bobID,
		gatewaytypes.QualifyProviderUserID(issuerB, "carol"): carol.ID,
	}, storedProviderUserIDs(t, c), "an identity already bound to an issuer is left as it is")
	done, err := c.identityIssuerBindingDone(c.db.WithContext(t.Context()))
	require.NoError(t, err)
	require.True(t, done)
}

func TestBackfillWithNoConfiguredIssuerWaitsForOne(t *testing.T) {
	c := newIssuerBindingTestClient(t)
	legacyUserID := insertLegacyGenericOAuthIdentity(t, c, "alice")

	require.NoError(t, c.BackfillIdentityIssuerBinding(t.Context()))

	require.Equal(t, map[string]uint{"alice": legacyUserID}, storedProviderUserIDs(t, c))
	done, err := c.identityIssuerBindingDone(c.db.WithContext(t.Context()))
	require.NoError(t, err)
	require.False(t, done, "the backfill must run again once an issuer is configured")
}

func TestBackfillLeavesAnIdentityWhoseIssuerBoundKeyIsTaken(t *testing.T) {
	c := newIssuerBindingTestClient(t)
	bound := signInGenericOAuth(t, c, gatewaytypes.QualifyProviderUserID(issuerA, "alice"))
	legacyUserID := insertLegacyGenericOAuthIdentity(t, c, "alice")
	configureGenericOAuthIssuer(t, c, issuerA)

	require.NoError(t, c.BackfillIdentityIssuerBinding(t.Context()))

	require.Equal(t, map[string]uint{
		gatewaytypes.QualifyProviderUserID(issuerA, "alice"): bound.ID,
		"alice": legacyUserID,
	}, storedProviderUserIDs(t, c))
}

func TestBackfillRunsOnce(t *testing.T) {
	c := newIssuerBindingTestClient(t)
	configureGenericOAuthIssuer(t, c, issuerA)
	require.NoError(t, c.BackfillIdentityIssuerBinding(t.Context()))

	legacyUserID := insertLegacyGenericOAuthIdentity(t, c, "alice")
	configureGenericOAuthIssuer(t, c, issuerB)
	require.NoError(t, c.BackfillIdentityIssuerBinding(t.Context()))

	require.Equal(t, map[string]uint{"alice": legacyUserID}, storedProviderUserIDs(t, c),
		"a later issuer must not re-bind identities once the backfill has run")
}

func TestUserFromProviderUserIDFallsBackToTheSubjectKeyedIdentityOnlyBeforeTheBackfill(t *testing.T) {
	c := newIssuerBindingTestClient(t)
	legacyUserID := insertLegacyGenericOAuthIdentity(t, c, "alice")
	qualified := gatewaytypes.QualifyProviderUserID(issuerA, "alice")

	u, err := c.UserFromProviderUserID(t.Context(), system.DefaultNamespace, genericOAuthTestProviderName, qualified)
	require.NoError(t, err)
	require.Equal(t, legacyUserID, u.ID)

	recordIssuerBinding(t, c)
	_, err = c.UserFromProviderUserID(t.Context(), system.DefaultNamespace, genericOAuthTestProviderName, qualified)
	require.True(t, errors.Is(err, gorm.ErrRecordNotFound), "error = %v, want record not found", err)
}

func TestUserFromProviderUserIDResolvesTheIssuerBoundIdentity(t *testing.T) {
	c := newIssuerBindingTestClient(t)
	recordIssuerBinding(t, c)
	alice := signInGenericOAuth(t, c, gatewaytypes.QualifyProviderUserID(issuerA, "alice"))

	u, err := c.UserFromProviderUserID(t.Context(), system.DefaultNamespace, genericOAuthTestProviderName, gatewaytypes.QualifyProviderUserID(issuerA, "alice"))
	require.NoError(t, err)
	require.Equal(t, alice.ID, u.ID)

	_, err = c.UserFromProviderUserID(t.Context(), system.DefaultNamespace, genericOAuthTestProviderName, gatewaytypes.QualifyProviderUserID(issuerB, "alice"))
	require.True(t, errors.Is(err, gorm.ErrRecordNotFound), "error = %v, want record not found", err)
}

func TestSignInProviderUserID(t *testing.T) {
	withIssuer := &user.DefaultInfo{UID: "alice", Extra: map[string][]string{"auth_provider_issuer": {issuerA}}}
	withoutIssuer := &user.DefaultInfo{UID: "alice"}

	tests := []struct {
		name         string
		authProvider string
		info         user.Info
		want         string
	}{
		{name: "another auth provider keys on the subject", authProvider: "github-auth-provider", info: withIssuer, want: "alice"},
		{name: "generic OAuth binds the issuer", authProvider: genericOAuthTestProviderName, info: withIssuer, want: gatewaytypes.QualifyProviderUserID(issuerA, "alice")},
		{name: "generic OAuth with no issuer keys on the subject", authProvider: genericOAuthTestProviderName, info: withoutIssuer, want: "alice"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, signInProviderUserID(tt.authProvider, tt.info))
		})
	}
}
