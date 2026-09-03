package oauth

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/obot-platform/obot/apiclient/types"
	"github.com/obot-platform/obot/pkg/api"
	gatewayclient "github.com/obot-platform/obot/pkg/gateway/client"
	gatewaydb "github.com/obot-platform/obot/pkg/gateway/db"
	gatewaytypes "github.com/obot-platform/obot/pkg/gateway/types"
	"github.com/obot-platform/obot/pkg/jwt/persistent"
	"github.com/obot-platform/obot/pkg/mcp"
	"github.com/obot-platform/obot/pkg/safehttp"
	"github.com/obot-platform/obot/pkg/storage"
	v1 "github.com/obot-platform/obot/pkg/storage/apis/obot.obot.ai/v1"
	"github.com/obot-platform/obot/pkg/storage/scheme"
	sservices "github.com/obot-platform/obot/pkg/storage/services"
	"github.com/obot-platform/obot/pkg/system"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	kclient "sigs.k8s.io/controller-runtime/pkg/client"
	clientfake "sigs.k8s.io/controller-runtime/pkg/client/fake"
)

type consumeOAuthTokenAfterGetStorage struct {
	storage.Client
}

func (s *consumeOAuthTokenAfterGetStorage) Get(ctx context.Context, key kclient.ObjectKey, obj kclient.Object, opts ...kclient.GetOption) error {
	if err := s.Client.Get(ctx, key, obj, opts...); err != nil {
		return err
	}
	if _, ok := obj.(*v1.OAuthToken); ok {
		return s.Delete(ctx, obj)
	}
	return nil
}

func TestRefreshOAuthTokenUsesRestrictedHTTPClient(t *testing.T) {
	var requests atomic.Int32
	tokenEndpoint := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		requests.Add(1)
	}))
	t.Cleanup(tokenEndpoint.Close)

	config := &oauth2.Config{
		ClientID:     "client-id",
		ClientSecret: "client-secret",
		Endpoint:     oauth2.Endpoint{TokenURL: tokenEndpoint.URL},
	}
	token := &oauth2.Token{RefreshToken: "refresh-token", Expiry: time.Now().Add(-time.Hour)}

	_, err := refreshOAuthToken(
		context.Background(),
		safehttp.NewClient(safehttp.ClientOptions{
			BlockLoopback:  true,
			BlockPrivateIP: true,
			BlockLinkLocal: true,
		}),
		config,
		token,
	)
	require.Error(t, err)
	require.Zero(t, requests.Load())
}

func TestTokenExchangeUsesUserSpecificOAuthForMCPServerInstance(t *testing.T) {
	const (
		baseURL         = "https://obot.example.test"
		userID          = "42"
		serverID        = "ms1server"
		instanceID      = "msi1user-server"
		otherInstanceID = "msi1user-other"
		resource        = "https://linear.example.test/mcp"
		accessToken     = "linear-user-token"
	)

	storage := clientfake.NewClientBuilder().
		WithScheme(scheme.Scheme).
		WithObjects(
			&v1.MCPServerInstance{
				Namespace: system.DefaultNamespace,
				Name:      instanceID,
				Spec: v1.MCPServerInstanceSpec{
					UserID:        userID,
					MCPServerName: serverID,
				},
			},
			&v1.MCPServerInstance{
				Namespace: system.DefaultNamespace,
				Name:      otherInstanceID,
				Spec: v1.MCPServerInstanceSpec{
					UserID:        userID,
					MCPServerName: "ms1other",
				},
			},
		).
		Build()

	services, err := sservices.New(sservices.Config{DSN: "sqlite://:memory:"})
	require.NoError(t, err)
	db, err := gatewaydb.New(services.DB.DB, services.DB.SQLDB, true)
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate())

	gatewayClient := gatewayclient.New(t.Context(), db, storage, nil, nil, nil, nil, time.Hour, 10, 90, 90, 90, true)
	t.Cleanup(func() { require.NoError(t, gatewayClient.Close()) })

	_, privateKey, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	require.NoError(t, gatewayClient.UpsertCredential(t.Context(), gatewaytypes.Credential{
		Context: system.JWKCredentialContext,
		Name:    system.JWKCredentialContext,
		Secrets: map[string]string{
			"JWK_KEY": base64.StdEncoding.EncodeToString(privateKey),
		},
	}))

	tokenService, err := persistent.NewTokenService(baseURL, gatewayClient)
	require.NoError(t, err)
	now := time.Now()
	_, subjectToken, err := tokenService.NewToken(t.Context(), persistent.TokenContext{
		Audience:  baseURL + "/mcp-connect/" + serverID,
		IssuedAt:  persistent.NewTime(now),
		ExpiresAt: persistent.NewTime(now.Add(time.Hour)),
		UserID:    userID,
		MCPID:     instanceID,
	})
	require.NoError(t, err)

	require.NoError(t, gatewayClient.ReplaceMCPOAuthToken(
		t.Context(),
		userID,
		instanceID,
		resource,
		"",
		&oauth2.Config{},
		&oauth2.Token{
			AccessToken: accessToken,
			TokenType:   "Bearer",
			Expiry:      now.Add(time.Hour),
		},
	))

	recorder := httptest.NewRecorder()
	req := api.Context{
		ResponseWriter: recorder,
		Request:        httptest.NewRequest("POST", "/oauth/token", nil),
		Storage:        storage,
		GatewayClient:  gatewayClient,
	}
	h := &handler{
		tokenService: tokenService,
		tokenStore:   mcp.NewGlobalTokenStore(gatewayClient),
	}

	err = h.doTokenExchange(req, v1.OAuthClient{}, resource, subjectToken, tokenTypeJWT, "")
	require.NoError(t, err)

	var response TokenExchangeResponse
	require.NoError(t, json.NewDecoder(recorder.Body).Decode(&response))
	require.Equal(t, accessToken, response.AccessToken)

	_, otherSubjectToken, err := tokenService.NewToken(t.Context(), persistent.TokenContext{
		Audience:  baseURL + "/mcp-connect/ms1other",
		IssuedAt:  persistent.NewTime(now),
		ExpiresAt: persistent.NewTime(now.Add(time.Hour)),
		UserID:    userID,
		MCPID:     otherInstanceID,
	})
	require.NoError(t, err)

	otherRecorder := httptest.NewRecorder()
	req.ResponseWriter = otherRecorder
	err = h.doTokenExchange(req, v1.OAuthClient{}, resource, otherSubjectToken, tokenTypeJWT, "")
	require.Error(t, err)
	require.Empty(t, otherRecorder.Body.String())

	_, otherUserSubjectToken, err := tokenService.NewToken(t.Context(), persistent.TokenContext{
		Audience:  baseURL + "/mcp-connect/" + serverID,
		IssuedAt:  persistent.NewTime(now),
		ExpiresAt: persistent.NewTime(now.Add(time.Hour)),
		UserID:    "43",
		MCPID:     instanceID,
	})
	require.NoError(t, err)

	otherUserRecorder := httptest.NewRecorder()
	req.ResponseWriter = otherUserRecorder
	err = h.doTokenExchange(
		req,
		v1.OAuthClient{},
		resource,
		otherUserSubjectToken,
		tokenTypeJWT,
		"",
	)
	require.ErrorContains(t, err, "access_denied")
	require.Empty(t, otherUserRecorder.Body.String())
}

func TestDoRefreshTokenRotatesTokenAndPreservesScope(t *testing.T) {
	const (
		baseURL      = "https://obot.example.com"
		clientName   = "oauth-client"
		mcpID        = system.SystemMCPServerPrefix + "test"
		refreshToken = "old-refresh-token"
	)

	storage := clientfake.NewClientBuilder().
		WithScheme(scheme.Scheme).
		WithObjects(&v1.SystemMCPServer{
			Namespace: system.DefaultNamespace,
			Name:      mcpID,
		}).
		Build()

	services, err := sservices.New(sservices.Config{DSN: "sqlite://:memory:"})
	require.NoError(t, err)
	db, err := gatewaydb.New(services.DB.DB, services.DB.SQLDB, true)
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate())

	gatewayClient := gatewayclient.New(t.Context(), db, storage, nil, nil, nil, nil, time.Hour, 10, 90, 90, 90, true)
	t.Cleanup(func() { require.NoError(t, gatewayClient.Close()) })

	require.NoError(t, db.WithContext(t.Context()).Create(&gatewaytypes.User{
		ID:       42,
		Username: "alice",
		Email:    "alice@example.com",
		Role:     types.RoleBasic,
	}).Error)

	_, privateKey, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	require.NoError(t, gatewayClient.UpsertCredential(t.Context(), gatewaytypes.Credential{
		Context: system.JWKCredentialContext,
		Name:    system.JWKCredentialContext,
		Secrets: map[string]string{
			"JWK_KEY": base64.StdEncoding.EncodeToString(privateKey),
		},
	}))

	tokenName := fmt.Sprintf("%x", sha256.Sum256([]byte(refreshToken)))
	storageToken := &v1.OAuthToken{
		Namespace: system.DefaultNamespace,
		Name:      tokenName,
		Spec: v1.OAuthTokenSpec{
			ClientID: clientName,
			Resource: baseURL,
			Scope:    "profile email",
			UserID:   42,
			MCPID:    mcpID,
		},
	}
	require.NoError(t, storage.Create(t.Context(), storageToken))

	tokenService, err := persistent.NewTokenService(baseURL, gatewayClient)
	require.NoError(t, err)
	recorder := httptest.NewRecorder()
	req := api.Context{
		ResponseWriter: recorder,
		Request:        httptest.NewRequest("POST", "/oauth/token", nil),
		Storage:        storage,
		GatewayClient:  gatewayClient,
	}
	oauthClient := v1.OAuthClient{
		Namespace: system.DefaultNamespace,
		Name:      clientName,
	}
	h := &handler{tokenService: tokenService}
	err = h.doRefreshToken(req, oauthClient, refreshToken)
	require.NoError(t, err)

	var response types.OAuthToken
	require.NoError(t, json.NewDecoder(recorder.Body).Decode(&response))
	require.NotEmpty(t, response.RefreshToken)

	var refreshed v1.OAuthToken
	refreshedName := fmt.Sprintf("%x", sha256.Sum256([]byte(response.RefreshToken)))
	require.NoError(t, storage.Get(t.Context(), kclient.ObjectKey{Namespace: system.DefaultNamespace, Name: refreshedName}, &refreshed))
	assert.Equal(t, "profile email", refreshed.Spec.Scope)

	err = h.doRefreshToken(api.Context{
		ResponseWriter: httptest.NewRecorder(),
		Request:        httptest.NewRequest("POST", "/oauth/token", nil),
		Storage:        storage,
	}, oauthClient, refreshToken)
	require.Error(t, err)

	var errHTTP *types.ErrHTTP
	require.ErrorAs(t, err, &errHTTP)
	assert.Equal(t, http.StatusBadRequest, errHTTP.Code)

	var oauthErr oauthError
	require.NoError(t, json.Unmarshal([]byte(errHTTP.Message), &oauthErr))
	assert.Equal(t, "invalid_grant", string(oauthErr.Code))
	assert.Equal(t, "Obot: refresh_token is invalid", oauthErr.Description)

	staleRefreshToken := "deleted-server-refresh-token"
	require.NoError(t, storage.Create(t.Context(), &v1.OAuthToken{
		Namespace: system.DefaultNamespace,
		Name:      fmt.Sprintf("%x", sha256.Sum256([]byte(staleRefreshToken))),
		Spec: v1.OAuthTokenSpec{
			ClientID: clientName,
			Resource: baseURL,
			UserID:   42,
			MCPID:    system.MCPServerPrefix + "deleted",
		},
	}))

	err = h.doRefreshToken(api.Context{
		ResponseWriter: httptest.NewRecorder(),
		Request:        httptest.NewRequest("POST", "/oauth/token", nil),
		Storage:        storage,
		GatewayClient:  gatewayClient,
	}, oauthClient, staleRefreshToken)
	require.Error(t, err)
	require.ErrorAs(t, err, &errHTTP)
	require.NoError(t, json.Unmarshal([]byte(errHTTP.Message), &oauthErr))
	assert.Equal(t, "invalid_grant", string(oauthErr.Code))
	assert.Equal(t, "Obot: invalid MCP server", oauthErr.Description)
	err = storage.Get(t.Context(), kclient.ObjectKey{
		Namespace: system.DefaultNamespace,
		Name:      fmt.Sprintf("%x", sha256.Sum256([]byte(staleRefreshToken))),
	}, &v1.OAuthToken{})
	require.True(t, apierrors.IsNotFound(err), "expected NotFound after consuming stale refresh token, got %v", err)

	racedRefreshToken := "concurrently-consumed-refresh-token"
	require.NoError(t, storage.Create(t.Context(), &v1.OAuthToken{
		Namespace: system.DefaultNamespace,
		Name:      fmt.Sprintf("%x", sha256.Sum256([]byte(racedRefreshToken))),
		Spec: v1.OAuthTokenSpec{
			ClientID: clientName,
			Resource: baseURL,
			UserID:   42,
			MCPID:    system.MCPServerPrefix + "deleted",
		},
	}))

	err = h.doRefreshToken(api.Context{
		ResponseWriter: httptest.NewRecorder(),
		Request:        httptest.NewRequest("POST", "/oauth/token", nil),
		Storage:        &consumeOAuthTokenAfterGetStorage{Client: storage},
		GatewayClient:  gatewayClient,
	}, oauthClient, racedRefreshToken)
	require.Error(t, err)
	require.ErrorAs(t, err, &errHTTP)
	require.NoError(t, json.Unmarshal([]byte(errHTTP.Message), &oauthErr))
	assert.Equal(t, "invalid_grant", string(oauthErr.Code))
	assert.Equal(t, "Obot: refresh_token is invalid", oauthErr.Description)
}
