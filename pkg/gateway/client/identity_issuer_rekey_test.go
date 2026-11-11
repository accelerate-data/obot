package client

import (
	"errors"
	"net/http"
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

	return signInGenericOAuth(t, c, subject).ID
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
	configureGenericOAuthIssuer(t, c, issuerA)

	u := signInGenericOAuth(t, c, gatewaytypes.QualifyProviderUserID(issuerA, "alice"))

	require.Equal(t, legacyUserID, u.ID, "an existing user keeps their account across the upgrade")
	require.Equal(t, map[string]uint{gatewaytypes.QualifyProviderUserID(issuerA, "alice"): legacyUserID}, storedProviderUserIDs(t, c),
		"the claimed identity is re-keyed and re-encrypted under the issuer-bound ID")
}

func TestSignInBeforeTheBackfillUnderAnotherIssuerNeverClaimsTheSubjectKeyedIdentity(t *testing.T) {
	c := newIssuerBindingTestClient(t)
	legacyUserID := insertLegacyGenericOAuthIdentity(t, c, "alice")
	configureGenericOAuthIssuer(t, c, issuerA)

	u := signInGenericOAuth(t, c, gatewaytypes.QualifyProviderUserID(issuerB, "alice"))

	require.NotEqual(t, legacyUserID, u.ID, "only the configured issuer, which the backfill binds it to, may claim a subject-keyed identity")
	require.Equal(t, map[string]uint{
		"alice": legacyUserID,
		gatewaytypes.QualifyProviderUserID(issuerB, "alice"): u.ID,
	}, storedProviderUserIDs(t, c))
}

func TestSignInBeforeTheBackfillWithNoConfiguredIssuerNeverClaimsTheSubjectKeyedIdentity(t *testing.T) {
	c := newIssuerBindingTestClient(t)
	legacyUserID := insertLegacyGenericOAuthIdentity(t, c, "alice")

	u := signInGenericOAuth(t, c, gatewaytypes.QualifyProviderUserID(issuerA, "alice"))

	require.NotEqual(t, legacyUserID, u.ID)
}

func TestClaimingTheSubjectKeyedIdentityKeepsTheSignInGroups(t *testing.T) {
	c := newIssuerBindingTestClient(t)
	insertLegacyGenericOAuthIdentity(t, c, "alice")
	configureGenericOAuthIssuer(t, c, issuerA)

	id := genericOAuthSignIn(gatewaytypes.QualifyProviderUserID(issuerA, "alice"))
	id.HashedProviderUserID = hash.String(id.ProviderUserID)
	id.AuthProviderGroups = []gatewaytypes.Group{{ID: "group-1", Name: "Group 1"}}
	var claimed bool
	require.NoError(t, c.db.WithContext(t.Context()).Transaction(func(tx *gorm.DB) error {
		var err error
		claimed, err = c.claimLegacyIssuerIdentityTx(t.Context(), tx, id)
		return err
	}))

	require.True(t, claimed)
	require.Equal(t, []gatewaytypes.Group{{ID: "group-1", Name: "Group 1"}}, id.AuthProviderGroups,
		"the groups of this sign-in are not stored on the identity, so reading it back must not drop them")
}

func TestClaimAfterAConcurrentRekeyResolvesTheRekeyedIdentity(t *testing.T) {
	c := newIssuerBindingTestClient(t)
	legacyUserID := insertLegacyGenericOAuthIdentity(t, c, "alice")
	configureGenericOAuthIssuer(t, c, issuerA)
	qualified := gatewaytypes.QualifyProviderUserID(issuerA, "alice")

	id := genericOAuthSignIn(qualified)
	id.HashedProviderUserID = hash.String(qualified)
	id.AuthProviderGroups = []gatewaytypes.Group{{ID: "group-1", Name: "Group 1"}}
	var claimed bool
	require.NoError(t, c.db.WithContext(t.Context()).Transaction(func(tx *gorm.DB) error {
		// The backfill, or another sign-in, re-keys the legacy identity after this sign-in found no issuer-bound key.
		var legacy gatewaytypes.Identity
		if err := tx.Where("auth_provider_name = ? AND hashed_provider_user_id = ?", genericOAuthTestProviderName, hash.String("alice")).First(&legacy).Error; err != nil {
			return err
		}
		if moved, _, err := c.rekeyIdentityTx(t.Context(), tx, legacy, qualified); err != nil || !moved {
			return errors.Join(err, errors.New("the concurrent re-key did not apply"))
		}
		var err error
		claimed, err = c.claimLegacyIssuerIdentityTx(t.Context(), tx, id)
		return err
	}))

	require.True(t, claimed, "the sign-in resolves to the re-keyed identity rather than creating a duplicate user")
	require.Equal(t, legacyUserID, id.UserID)
	require.Equal(t, []gatewaytypes.Group{{ID: "group-1", Name: "Group 1"}}, id.AuthProviderGroups)
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

	require.ErrorIs(t, c.BackfillIdentityIssuerBinding(t.Context()), ErrGenericOAuthIssuerNotConfigured,
		"the caller must keep retrying, or the claim stays open to whichever issuer is configured later")

	require.Equal(t, map[string]uint{"alice": legacyUserID}, storedProviderUserIDs(t, c))
	done, err := c.identityIssuerBindingDone(c.db.WithContext(t.Context()))
	require.NoError(t, err)
	require.False(t, done, "the backfill must run again once an issuer is configured")
}

func TestBackfillRetriedAfterAnIssuerIsConfiguredBindsToThatIssuer(t *testing.T) {
	c := newIssuerBindingTestClient(t)
	legacyUserID := insertLegacyGenericOAuthIdentity(t, c, "alice")
	require.ErrorIs(t, c.BackfillIdentityIssuerBinding(t.Context()), ErrGenericOAuthIssuerNotConfigured)
	configureGenericOAuthIssuer(t, c, issuerA)

	require.NoError(t, c.BackfillIdentityIssuerBinding(t.Context()))

	require.Equal(t, map[string]uint{gatewaytypes.QualifyProviderUserID(issuerA, "alice"): legacyUserID}, storedProviderUserIDs(t, c))
	done, err := c.identityIssuerBindingDone(c.db.WithContext(t.Context()))
	require.NoError(t, err)
	require.True(t, done, "once recorded, a later issuer can no longer claim the legacy identities")
}

func TestBackfillWithNoConfiguredIssuerAfterItRanSucceeds(t *testing.T) {
	c := newIssuerBindingTestClient(t)
	recordIssuerBinding(t, c)

	require.NoError(t, c.BackfillIdentityIssuerBinding(t.Context()))
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

func TestRekeyOfAnIdentityAlreadyMovedIsNotATakenKey(t *testing.T) {
	c := newIssuerBindingTestClient(t)
	legacyUserID := insertLegacyGenericOAuthIdentity(t, c, "alice")
	configureGenericOAuthIssuer(t, c, issuerA)
	qualified := gatewaytypes.QualifyProviderUserID(issuerA, "alice")

	// The backfill read this row, then a sign-in claimed and re-keyed it before the backfill's re-key ran.
	var stale gatewaytypes.Identity
	require.NoError(t, c.db.WithContext(t.Context()).
		Where("auth_provider_name = ? AND hashed_provider_user_id = ?", genericOAuthTestProviderName, hash.String("alice")).
		First(&stale).Error)
	signInGenericOAuth(t, c, qualified)

	var moved, keyTaken bool
	require.NoError(t, c.db.WithContext(t.Context()).Transaction(func(tx *gorm.DB) error {
		var err error
		moved, keyTaken, err = c.rekeyIdentityTx(t.Context(), tx, stale, qualified)
		return err
	}))

	require.False(t, moved)
	require.False(t, keyTaken, "the identity was moved by the claim, so no other identity owns its issuer-bound key")
	require.Equal(t, map[string]uint{qualified: legacyUserID}, storedProviderUserIDs(t, c))
}

func TestRekeyOntoAnotherIdentitysKeyIsATakenKey(t *testing.T) {
	c := newIssuerBindingTestClient(t)
	qualified := gatewaytypes.QualifyProviderUserID(issuerA, "alice")
	bound := signInGenericOAuth(t, c, qualified)
	legacyUserID := insertLegacyGenericOAuthIdentity(t, c, "alice")

	var legacy gatewaytypes.Identity
	require.NoError(t, c.db.WithContext(t.Context()).
		Where("auth_provider_name = ? AND hashed_provider_user_id = ?", genericOAuthTestProviderName, hash.String("alice")).
		First(&legacy).Error)

	var moved, keyTaken bool
	require.NoError(t, c.db.WithContext(t.Context()).Transaction(func(tx *gorm.DB) error {
		var err error
		moved, keyTaken, err = c.rekeyIdentityTx(t.Context(), tx, legacy, qualified)
		return err
	}))

	require.False(t, moved)
	require.True(t, keyTaken, "another identity owns the issuer-bound key while this one still has its old key")
	require.Equal(t, map[string]uint{qualified: bound.ID, "alice": legacyUserID}, storedProviderUserIDs(t, c))
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
	configureGenericOAuthIssuer(t, c, issuerA)
	qualified := gatewaytypes.QualifyProviderUserID(issuerA, "alice")

	_, err := c.UserFromProviderUserID(t.Context(), system.DefaultNamespace, genericOAuthTestProviderName, gatewaytypes.QualifyProviderUserID(issuerB, "alice"))
	require.True(t, errors.Is(err, gorm.ErrRecordNotFound), "another issuer must not resolve the subject-keyed identity; error = %v", err)

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
		wantRefused  bool
	}{
		{name: "another auth provider keys on the subject", authProvider: "github-auth-provider", info: withIssuer, want: "alice"},
		{name: "another auth provider with no issuer keys on the subject", authProvider: "github-auth-provider", info: withoutIssuer, want: "alice"},
		{name: "generic OAuth binds the issuer", authProvider: genericOAuthTestProviderName, info: withIssuer, want: gatewaytypes.QualifyProviderUserID(issuerA, "alice")},
		{name: "generic OAuth with no issuer is refused", authProvider: genericOAuthTestProviderName, info: withoutIssuer, wantRefused: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := signInProviderUserID(tt.authProvider, tt.info)
			if tt.wantRefused {
				var httpErr *apitypes.ErrHTTP
				require.ErrorAs(t, err, &httpErr)
				require.Equal(t, http.StatusUnauthorized, httpErr.Code)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}
