package oauth

import (
	"cmp"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/obot-platform/obot/apiclient/types"
	"github.com/obot-platform/obot/pkg/api"
	gatewayclient "github.com/obot-platform/obot/pkg/gateway/client"
	gatewaydb "github.com/obot-platform/obot/pkg/gateway/db"
	gatewaytypes "github.com/obot-platform/obot/pkg/gateway/types"
	v1 "github.com/obot-platform/obot/pkg/storage/apis/obot.obot.ai/v1"
	"github.com/obot-platform/obot/pkg/storage/scheme"
	sservices "github.com/obot-platform/obot/pkg/storage/services"
	"github.com/obot-platform/obot/pkg/system"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
	"k8s.io/apiserver/pkg/authentication/user"
	clientfake "sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestOAuthCallbackComponentCompletion(t *testing.T) {
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"token","token_type":"Bearer"}`))
	}))
	defer tokenServer.Close()
	services, err := sservices.New(sservices.Config{DSN: "sqlite://:memory:"})
	require.NoError(t, err)
	db, err := gatewaydb.New(services.DB.DB, services.DB.SQLDB, true)
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate())
	client := gatewayclient.New(t.Context(), db, nil, nil, nil, nil, nil, time.Hour, 10, 90, 90, 90, true)
	t.Cleanup(func() { require.NoError(t, client.Close()) })
	state := newStateManager(client, fixedTokenClient(tokenServer.Client()))
	h := handler{oauthChecker: &MCPOAuthHandlerFactory{stateMgr: state}}
	for _, tt := range []struct {
		name         string
		spec         v1.MCPServerSpec
		instanceSpec *v1.MCPServerInstanceSpec
		want         string
	}{
		{
			name: "shared vmcp",
			spec: v1.MCPServerSpec{VMCPID: "vmcp1shared"},
			want: "/auth/oauth/complete",
		},
		{
			name: "dedicated vmcp",
			spec: v1.MCPServerSpec{VMCPInstanceID: "vmcpi1dedicated"},
			want: "/auth/oauth/complete",
		},
		{
			name: "legacy composite",
			spec: v1.MCPServerSpec{CompositeName: "ms1composite"},
			want: "/auth/oauth/complete",
		},
		{
			name:         "shared vmcp connection",
			spec:         v1.MCPServerSpec{VMCPID: "vmcp1shared"},
			instanceSpec: &v1.MCPServerInstanceSpec{VMCPInstanceID: "vmcpi1selected"},
			want:         "/auth/oauth/complete",
		},
		{
			name:         "legacy composite connection",
			instanceSpec: &v1.MCPServerInstanceSpec{CompositeName: "ms1composite"},
			want:         "/auth/oauth/complete",
		},
		{
			name:         "standalone connection",
			instanceSpec: &v1.MCPServerInstanceSpec{},
			want:         oauthCompletionURL("oar1request"),
		},
		{
			name: "standalone",
			want: oauthCompletionURL("oar1request"),
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			server := &v1.MCPServer{Name: "ms1component", Namespace: system.DefaultNamespace, Spec: tt.spec}
			authRequest := &v1.OAuthAuthRequest{Name: "oar1request", Namespace: system.DefaultNamespace, Spec: v1.OAuthAuthRequestSpec{RedirectURI: "https://client.example/callback"}}
			storage := clientfake.NewClientBuilder().WithScheme(scheme.Scheme).WithObjects(server, authRequest).Build()
			mcpID := server.Name
			if tt.instanceSpec != nil {
				connection := &v1.MCPServerInstance{
					Name:      "msi1connection",
					Namespace: system.DefaultNamespace,
					Spec:      *tt.instanceSpec,
				}
				connection.Spec.MCPServerName = server.Name
				connection.Spec.UserID = "1"
				require.NoError(t, storage.Create(t.Context(), connection))
				mcpID = connection.Name
			}
			require.NoError(t, state.store(t.Context(), "1", mcpID, "https://upstream.example/mcp", authRequest.Name, "", "state", "verifier", "", &oauth2.Config{
				ClientID: "client", Endpoint: oauth2.Endpoint{TokenURL: tokenServer.URL, AuthStyle: oauth2.AuthStyleInParams},
			}))
			response := httptest.NewRecorder()
			require.NoError(t, h.oauthCallback(api.Context{
				Request:        httptest.NewRequest(http.MethodGet, "/oauth/mcp/callback?state=state&code=code", nil),
				ResponseWriter: response,
				Storage:        storage,
				User:           &user.DefaultInfo{UID: "1", Name: "user", Groups: []string{types.GroupAuthenticated}},
			}))
			require.Equal(t, http.StatusFound, response.Code)
			require.Equal(t, tt.want, response.Header().Get("Location"))
		})
	}
}

func TestOAuthCallbackComponentCompletionRedirect(t *testing.T) {
	const completionURL = "/auth/mcp-oauth/complete"
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"token","token_type":"Bearer"}`))
	}))
	defer tokenServer.Close()
	services, err := sservices.New(sservices.Config{DSN: "sqlite://:memory:"})
	require.NoError(t, err)
	db, err := gatewaydb.New(services.DB.DB, services.DB.SQLDB, true)
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate())
	client := gatewayclient.New(t.Context(), db, nil, nil, nil, nil, nil, time.Hour, 10, 90, 90, 90, true)
	t.Cleanup(func() { require.NoError(t, client.Close()) })
	state := newStateManager(client, fixedTokenClient(http.DefaultClient))
	h := handler{oauthChecker: &MCPOAuthHandlerFactory{stateMgr: state}, completionURL: completionURL}
	for _, tt := range []struct {
		name         string
		spec         v1.MCPServerSpec
		instanceSpec *v1.MCPServerInstanceSpec
		query        string
		wantLocation string
		wantQuery    url.Values
		wantHTTP400  bool
	}{
		{
			name:      "shared vmcp success",
			spec:      v1.MCPServerSpec{VMCPID: "vmcp1shared"},
			query:     "state=state&code=code",
			wantQuery: url.Values{"flow": {"component"}, "status": {"success"}, "mcp_id": {"ms1component"}},
		},
		{
			name:         "legacy composite connection success",
			instanceSpec: &v1.MCPServerInstanceSpec{CompositeName: "ms1composite"},
			query:        "state=state&code=code",
			wantQuery:    url.Values{"flow": {"component"}, "status": {"success"}, "mcp_id": {"msi1connection"}},
		},
		{
			name:      "dedicated vmcp denied",
			spec:      v1.MCPServerSpec{VMCPInstanceID: "vmcpi1dedicated"},
			query:     "state=state&error=access_denied&error_description=User+denied+access",
			wantQuery: url.Values{"flow": {"component"}, "status": {"failed"}, "error": {"access_denied"}, "error_description": {"User denied access"}, "mcp_id": {"ms1component"}},
		},
		{
			name:         "standalone success stays with the client",
			query:        "state=state&code=code",
			wantLocation: oauthCompletionURL("oar1request"),
		},
		{
			name:        "standalone denied stays an error",
			query:       "state=state&error=access_denied",
			wantHTTP400: true,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			server := &v1.MCPServer{Name: "ms1component", Namespace: system.DefaultNamespace, Spec: tt.spec}
			authRequest := &v1.OAuthAuthRequest{Name: "oar1request", Namespace: system.DefaultNamespace, Spec: v1.OAuthAuthRequestSpec{RedirectURI: "https://client.example/callback"}}
			storage := clientfake.NewClientBuilder().WithScheme(scheme.Scheme).WithObjects(server, authRequest).Build()
			mcpID := server.Name
			if tt.instanceSpec != nil {
				connection := &v1.MCPServerInstance{
					Name:      "msi1connection",
					Namespace: system.DefaultNamespace,
					Spec:      *tt.instanceSpec,
				}
				connection.Spec.MCPServerName = server.Name
				connection.Spec.UserID = "1"
				require.NoError(t, storage.Create(t.Context(), connection))
				mcpID = connection.Name
			}
			require.NoError(t, state.store(t.Context(), "1", mcpID, "https://upstream.example/mcp", authRequest.Name, "", "state", "verifier", "", &oauth2.Config{
				ClientID: "client", Endpoint: oauth2.Endpoint{TokenURL: tokenServer.URL, AuthStyle: oauth2.AuthStyleInParams},
			}))
			response := httptest.NewRecorder()
			err := h.oauthCallback(api.Context{
				Request:        httptest.NewRequest(http.MethodGet, "/oauth/mcp/callback?"+tt.query, nil),
				ResponseWriter: response,
				Storage:        storage,
				User:           &user.DefaultInfo{UID: "1", Name: "user", Groups: []string{types.GroupAuthenticated}},
			})
			if tt.wantHTTP400 {
				var httpErr *types.ErrHTTP
				require.ErrorAs(t, err, &httpErr)
				require.Equal(t, http.StatusBadRequest, httpErr.Code)
				return
			}
			require.NoError(t, err)
			require.Equal(t, http.StatusFound, response.Code)
			location := response.Header().Get("Location")
			if tt.wantLocation != "" {
				require.Equal(t, tt.wantLocation, location)
				return
			}
			parsed, err := url.Parse(location)
			require.NoError(t, err)
			require.Equal(t, completionURL, parsed.Path)
			require.Equal(t, tt.wantQuery, parsed.Query())
		})
	}
}

func TestOAuthCallbackInstanceCompletionRedirect(t *testing.T) {
	const completionURL = "/auth/mcp-oauth/complete"
	tokenStatus := http.StatusOK
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if tokenStatus != http.StatusOK {
			http.Error(w, "provider body echoes code=leaked-code and client_secret=leaked-secret", tokenStatus)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"token","token_type":"Bearer"}`))
	}))
	defer tokenServer.Close()
	services, err := sservices.New(sservices.Config{DSN: "sqlite://:memory:"})
	require.NoError(t, err)
	db, err := gatewaydb.New(services.DB.DB, services.DB.SQLDB, true)
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate())
	client := gatewayclient.New(t.Context(), db, nil, nil, nil, nil, nil, time.Hour, 10, 90, 90, 90, true)
	t.Cleanup(func() { require.NoError(t, client.Close()) })
	state := newStateManager(client, fixedTokenClient(http.DefaultClient))

	for _, tt := range []struct {
		name          string
		completionURL string
		authRequest   string
		tokenStatus   int
		skipStore     bool
		// storeMCPID overrides the stored connection id; a pointer so "" is a value.
		storeMCPID *string
		// breakCommit drops the token table so the token commit fails.
		breakCommit  bool
		query        string
		wantErr      bool
		wantHTTP400  bool
		wantLocation string
		wantQuery    url.Values
		// wantNotContain replaces wantQuery where the exact redacted wording is
		// not the contract: only the absence of every listed fragment is.
		wantNotContain []string
		wantContain    []string
	}{
		{
			name:          "denial redirects with sanitized description",
			completionURL: completionURL,
			query:         "&error=access_denied&error_description=" + url.QueryEscape("denied code=c-7&state=s-9 for workspace ws-42"),
			wantQuery: url.Values{
				"flow": {"instance"}, "status": {"failed"}, "mcp_id": {"msi1"}, "error": {"access_denied"},
				"error_description": {"denied code=[REDACTED]&state=[REDACTED] for workspace ws-42"},
			},
		},
		{
			name:          "denial description never carries a provider credential",
			completionURL: completionURL,
			query:         "&error=access_denied&error_description=" + url.QueryEscape(`denied client_secret=s3cr3t {"client_secret":"s3cr3t"} access_token: tok-123`),
			wantQuery: url.Values{
				"flow": {"instance"}, "status": {"failed"}, "mcp_id": {"msi1"}, "error": {"access_denied"},
				"error_description": {`denied client_secret=[REDACTED] {'client_secret':'[REDACTED]'} access_token: [REDACTED]`},
			},
		},
		{
			name:          "denial description with quoted values leaks no fragment",
			completionURL: completionURL,
			query:         "&error=access_denied&error_description=" + url.QueryEscape(`denied {"client_secret":"s3 cr,et&x"} password='p w,d&q'`),
			wantQuery: url.Values{
				"flow": {"instance"}, "status": {"failed"}, "mcp_id": {"msi1"}, "error": {"access_denied"},
				"error_description": {`denied {'client_secret':'[REDACTED]'} password='[REDACTED]'`},
			},
		},
		{
			name:          "denial description with an escaped quote inside a JSON-escaped value leaks no fragment",
			completionURL: completionURL,
			query:         "&error=access_denied&error_description=" + url.QueryEscape(`denied {\"client_secret\":\"head\\\" tail-secret\"}`),
			wantQuery: url.Values{
				"flow": {"instance"}, "status": {"failed"}, "mcp_id": {"msi1"}, "error": {"access_denied"},
				"error_description": {`denied {/'client_secret/':/'[REDACTED]/'}`},
			},
		},
		{
			name:          "denial description with an escaped quote inside a quoted header value leaks no fragment",
			completionURL: completionURL,
			query:         "&error=access_denied&error_description=" + url.QueryEscape(`denied authorization: "head\" tail-secret" retry`),
			wantQuery: url.Values{
				"flow": {"instance"}, "status": {"failed"}, "mcp_id": {"msi1"}, "error": {"access_denied"},
				"error_description": {`denied authorization: '[REDACTED]' retry`},
			},
		},
		{
			name:          "denial description never carries a password named in prose",
			completionURL: completionURL,
			query:         "&error=access_denied&error_description=" + url.QueryEscape("The password is hunter2"),
			wantQuery: url.Values{
				"flow": {"instance"}, "status": {"failed"}, "mcp_id": {"msi1"}, "error": {"access_denied"},
				"error_description": {"The password is [REDACTED]"},
			},
		},
		{
			name:          "denial description never carries a digit-led password named in prose",
			completionURL: completionURL,
			query:         "&error=access_denied&error_description=" + url.QueryEscape("denied password 7hunter retry"),
			wantQuery: url.Values{
				"flow": {"instance"}, "status": {"failed"}, "mcp_id": {"msi1"}, "error": {"access_denied"},
				"error_description": {"denied password [REDACTED] retry"},
			},
		},
		{
			name:          "denial description never carries a header credential or URL userinfo",
			completionURL: completionURL,
			query:         "&error=access_denied&error_description=" + url.QueryEscape("denied Authorization: Bearer opaque-credential-123 https://alice:password123@provider.example/fix"),
			wantQuery: url.Values{
				"flow": {"instance"}, "status": {"failed"}, "mcp_id": {"msi1"}, "error": {"access_denied"},
				"error_description": {"denied Authorization: [REDACTED] https://[REDACTED]@provider.example/fix"},
			},
		},
		{
			name:           "denial description never carries any pair of a cookie header",
			completionURL:  completionURL,
			query:          "&error=access_denied&error_description=" + url.QueryEscape("denied Cookie: sid=secret-one; refresh=secret-two retry"),
			wantNotContain: []string{"secret-one", "secret-two"},
		},
		{
			name:          "denial description never carries a cookie value after a quoted or valueless pair",
			completionURL: completionURL,
			query: "&error=access_denied&error_description=" + url.QueryEscape(
				`denied Cookie: sid="head secret-one"; refresh=secret-two Set-Cookie: a=b; Secure, session=secret-three retry`),
			wantNotContain: []string{"secret-one", "secret-two", "secret-three"},
		},
		{
			name:          "denial description never carries a known secret the provider echoes unlabeled",
			completionURL: completionURL,
			query:         "&error=access_denied&error_description=" + url.QueryEscape("Rejected candidate cs-5e8f1a3b9d27 for ws-42 req-77 st-4f9a2c71e8b3 vf-9d3e6b2a7c10"),
			wantQuery: url.Values{
				"flow": {"instance"}, "status": {"failed"}, "mcp_id": {"msi1"}, "error": {"access_denied"},
				"error_description": {"Rejected candidate [REDACTED] for ws-42 req-77 [REDACTED] [REDACTED]"},
			},
		},
		{
			name:          "denial description keeps the text after a cookie header",
			completionURL: completionURL,
			query: "&error=access_denied&error_description=" + url.QueryEscape(
				"denied Cookie: sid=secret-one\nrequest-id=req-42 retry https://provider.example/fix"),
			wantNotContain: []string{"secret-one"},
			wantContain:    []string{"request-id=req-42", "retry", "https://provider.example/fix"},
		},
		{
			name:          "denial description never carries a Digest credential parameter",
			completionURL: completionURL,
			query: "&error=access_denied&error_description=" + url.QueryEscape(
				`denied Authorization: Digest username="alice", realm="example", response="d41d8cd98f00b204e9800998ecf8427e", retry`),
			wantNotContain: []string{"d41d8cd98f00b204e9800998ecf8427e", "alice"},
		},
		{
			name:          "an error code that echoes the verifier is replaced",
			completionURL: completionURL,
			query:         "&error=vf-9d3e6b2a7c10",
			wantQuery:     url.Values{"flow": {"instance"}, "status": {"failed"}, "mcp_id": {"msi1"}, "error": {"server_error"}},
		},
		{
			name:          "an error code that echoes the client secret is replaced",
			completionURL: completionURL,
			query:         "&error=cs-5e8f1a3b9d27",
			wantQuery:     url.Values{"flow": {"instance"}, "status": {"failed"}, "mcp_id": {"msi1"}, "error": {"server_error"}},
		},
		{
			name:          "a token commit failure sends server_error",
			completionURL: completionURL,
			breakCommit:   true,
			query:         "&code=code",
			wantQuery:     url.Values{"flow": {"instance"}, "status": {"failed"}, "mcp_id": {"msi1"}, "error": {"server_error"}},
		},
		{
			name:          "token exchange failure sends a code only",
			completionURL: completionURL,
			tokenStatus:   http.StatusBadRequest,
			query:         "&code=code",
			wantQuery:     url.Values{"flow": {"instance"}, "status": {"failed"}, "mcp_id": {"msi1"}, "error": {"token_exchange_failed"}},
		},
		{
			name:          "success redirects to the configured page",
			completionURL: completionURL,
			query:         "&code=code",
			wantLocation:  "/auth/mcp-oauth/complete?flow=instance&mcp_id=msi1&status=success",
		},
		{
			name:          "success without a connection id sends no empty mcp_id",
			completionURL: completionURL,
			storeMCPID:    new(string),
			query:         "&code=code",
			wantLocation:  "/auth/mcp-oauth/complete?flow=instance&status=success",
		},
		{
			name:         "success keeps Obot's page when unconfigured",
			query:        "&code=code",
			wantLocation: "/auth/oauth/complete",
		},
		{
			name:        "failure keeps the HTTP error when unconfigured",
			query:       "&error=access_denied",
			wantErr:     true,
			wantHTTP400: true,
		},
		{
			name:          "unknown state never redirects",
			completionURL: completionURL,
			skipStore:     true,
			query:         "&code=code",
			wantErr:       true,
		},
		{
			name:          "third-party client failure keeps the HTTP error",
			completionURL: completionURL,
			authRequest:   "oar1request",
			query:         "&error=access_denied",
			wantErr:       true,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			tokenStatus = cmp.Or(tt.tokenStatus, http.StatusOK)
			server := &v1.MCPServer{Name: "ms1component", Namespace: system.DefaultNamespace}
			connection := &v1.MCPServerInstance{Name: "msi1", Namespace: system.DefaultNamespace, Spec: v1.MCPServerInstanceSpec{MCPServerName: server.Name, UserID: "1"}}
			authRequest := &v1.OAuthAuthRequest{Name: "oar1request", Namespace: system.DefaultNamespace, Spec: v1.OAuthAuthRequestSpec{RedirectURI: "https://client.example/callback"}}
			storage := clientfake.NewClientBuilder().WithScheme(scheme.Scheme).WithObjects(server, connection, authRequest).Build()
			if !tt.skipStore {
				require.NoError(t, state.store(t.Context(), "1", *cmp.Or(tt.storeMCPID, &connection.Name), "https://upstream.example/mcp", tt.authRequest, "", "st-4f9a2c71e8b3", "vf-9d3e6b2a7c10", "", &oauth2.Config{
					ClientID: "client", ClientSecret: "cs-5e8f1a3b9d27", Endpoint: oauth2.Endpoint{TokenURL: tokenServer.URL, AuthStyle: oauth2.AuthStyleInParams},
				}))
			}
			if tt.breakCommit {
				require.NoError(t, services.DB.DB.Migrator().DropTable(&gatewaytypes.MCPOAuthToken{}))
				// A failed commit keeps the pending state, which would collide
				// with the next case's store.
				t.Cleanup(func() {
					require.NoError(t, db.AutoMigrate())
					require.NoError(t, services.DB.DB.Where("1 = 1").Delete(&gatewaytypes.MCPOAuthPendingState{}).Error)
				})
			}
			h := handler{oauthChecker: &MCPOAuthHandlerFactory{stateMgr: state}, completionURL: tt.completionURL}
			response := httptest.NewRecorder()
			err := h.oauthCallback(api.Context{
				Request:        httptest.NewRequest(http.MethodGet, "/oauth/mcp/callback?state=st-4f9a2c71e8b3"+tt.query, nil),
				ResponseWriter: response,
				Storage:        storage,
				User:           &user.DefaultInfo{UID: "1", Name: "user", Groups: []string{types.GroupAuthenticated}},
			})
			if tt.wantErr {
				require.Error(t, err)
				require.Empty(t, response.Header().Get("Location"))
				if tt.wantHTTP400 {
					var httpErr *types.ErrHTTP
					require.ErrorAs(t, err, &httpErr)
					require.Equal(t, http.StatusBadRequest, httpErr.Code)
				}
				return
			}
			require.NoError(t, err)
			require.Equal(t, http.StatusFound, response.Code)
			location := response.Header().Get("Location")
			require.NotContains(t, location, "leaked")
			if tt.wantNotContain != nil {
				decoded, err := url.QueryUnescape(location)
				require.NoError(t, err)
				for _, fragment := range tt.wantNotContain {
					require.NotContains(t, decoded, fragment)
				}
				for _, fragment := range tt.wantContain {
					require.Contains(t, decoded, fragment)
				}
				require.Contains(t, location, "status=failed")
				return
			}
			if tt.wantLocation != "" {
				require.Equal(t, tt.wantLocation, location)
				return
			}
			parsed, err := url.Parse(location)
			require.NoError(t, err)
			require.Equal(t, completionURL, parsed.Path)
			require.Equal(t, tt.wantQuery, parsed.Query())
		})
	}
}

func TestStateManagerExchangesAuthorizationCodeWithStoredResource(t *testing.T) {
	const (
		resourceURL = "https://resource.example.com/mcp"
		mcpURL      = "https://connection.example.com/mcp"
		redirectURL = "https://obot.example.com/oauth/mcp/callback"
		clientID    = "dynamic-client"
		verifier    = "pkce-verifier"
	)

	tokenRequest := make(chan url.Values, 1)
	tokenServer := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		if err := req.ParseForm(); err != nil {
			http.Error(rw, err.Error(), http.StatusBadRequest)
			return
		}
		tokenRequest <- req.Form
		rw.Header().Set("Content-Type", "application/json")
		_, _ = rw.Write([]byte(`{"access_token":"access-token","token_type":"Bearer"}`))
	}))
	defer tokenServer.Close()

	services, err := sservices.New(sservices.Config{DSN: "sqlite://:memory:"})
	require.NoError(t, err)
	db, err := gatewaydb.New(services.DB.DB, services.DB.SQLDB, true)
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate())

	gatewayClient := gatewayclient.New(t.Context(), db, nil, nil, nil, nil, nil, time.Hour, 10, 90, 90, 90, true)
	t.Cleanup(func() { require.NoError(t, gatewayClient.Close()) })
	stateManager := newStateManager(gatewayClient, fixedTokenClient(tokenServer.Client()))
	conf := &oauth2.Config{
		ClientID:    clientID,
		RedirectURL: redirectURL,
		Endpoint: oauth2.Endpoint{
			AuthURL:   "https://auth.example.com/authorize",
			TokenURL:  tokenServer.URL,
			AuthStyle: oauth2.AuthStyleInParams,
		},
	}

	require.NoError(t, stateManager.store(t.Context(), "user", "mcp", mcpURL, "request", "", "state", verifier, resourceURL, conf))
	_, _, err = stateManager.createToken(t.Context(), "state", "authorization-code", "", "")
	require.NoError(t, err)

	form := <-tokenRequest
	require.Equal(t, resourceURL, form.Get("resource"))
	require.Equal(t, clientID, form.Get("client_id"))
	require.Equal(t, redirectURL, form.Get("redirect_uri"))
	require.Equal(t, verifier, form.Get("code_verifier"))

	conf.Endpoint.AuthURL = "https://login.microsoftonline.com/tenant/oauth2/v2.0/authorize"
	require.NoError(t, stateManager.store(t.Context(), "user", "mcp", mcpURL, "request", "", "entra-state", verifier, resourceURL, conf))
	_, _, err = stateManager.createToken(t.Context(), "entra-state", "authorization-code", "", "")
	require.NoError(t, err)
	require.Empty(t, (<-tokenRequest).Get("resource"))
}

func fixedTokenClient(client *http.Client) tokenClientFunc {
	return func(string) (*http.Client, error) {
		return client, nil
	}
}

func TestOAuthCallbackExchangeUsesStoredTunnel(t *testing.T) {
	tokenServer := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.Header().Set("Content-Type", "application/json")
		_, _ = rw.Write([]byte(`{"access_token":"access-token","token_type":"Bearer"}`))
	}))
	defer tokenServer.Close()

	services, err := sservices.New(sservices.Config{DSN: "sqlite://:memory:"})
	require.NoError(t, err)
	db, err := gatewaydb.New(services.DB.DB, services.DB.SQLDB, true)
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate())
	gatewayClient := gatewayclient.New(t.Context(), db, nil, nil, nil, nil, nil, time.Hour, 10, 90, 90, 90, true)
	t.Cleanup(func() { require.NoError(t, gatewayClient.Close()) })

	var tunnels []string
	stateManager := newStateManager(gatewayClient, func(tunnelName string) (*http.Client, error) {
		tunnels = append(tunnels, tunnelName)
		return tokenServer.Client(), nil
	})
	conf := &oauth2.Config{
		ClientID: "client",
		Endpoint: oauth2.Endpoint{TokenURL: tokenServer.URL, AuthStyle: oauth2.AuthStyleInParams},
	}

	require.NoError(t, stateManager.storeWithTunnel(t.Context(), "user", "tunneled", "https://private.example/mcp", "private-tunnel", "request", "", "tunneled-state", "verifier", "", conf))
	_, _, err = stateManager.createToken(t.Context(), "tunneled-state", "authorization-code", "", "")
	require.NoError(t, err)

	require.NoError(t, stateManager.storeWithTunnel(t.Context(), "user", "direct", "https://public.example/mcp", "", "request", "", "direct-state", "verifier", "", conf))
	_, _, err = stateManager.createToken(t.Context(), "direct-state", "authorization-code", "", "")
	require.NoError(t, err)

	require.Equal(t, []string{"private-tunnel", ""}, tunnels)
}
