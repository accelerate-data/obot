package client

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	apitypes "github.com/obot-platform/obot/apiclient/types"
	"github.com/obot-platform/obot/pkg/gateway/types"
	"golang.org/x/oauth2"
	"gorm.io/gorm"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apiserver/pkg/storage/value"
)

var mcpOAuthTokenGroupResource = schema.GroupResource{
	Group:    "obot.obot.ai",
	Resource: "mcpoauthtokens",
}

var mcpOAuthPendingStateGroupResource = schema.GroupResource{
	Group:    "obot.obot.ai",
	Resource: "mcpoauthpendingstates",
}

var ErrMCPStaticOAuthTestInvalid = errors.New("invalid static OAuth test proof")

func (c *Client) GetMCPOAuthToken(ctx context.Context, userID, mcpID, url string) (*types.MCPOAuthToken, error) {
	var tokens []types.MCPOAuthToken
	err := c.db.WithContext(ctx).Where("mcp_id = ? AND user_id = ?", mcpID, userID).Find(&tokens).Error
	if err != nil {
		return nil, err
	}

	var token types.MCPOAuthToken
	for _, t := range tokens {
		if t.URL == url {
			token = t
			break
		}
	}

	if token.MCPID == "" {
		// We didn't find a token. If there is only one, then use that one.
		if len(tokens) != 1 {
			return nil, gorm.ErrRecordNotFound
		}

		token = tokens[0]
	}

	if err = c.decryptMCPOAuthToken(ctx, &token); err != nil {
		return nil, fmt.Errorf("failed to decrypt token: %w", err)
	}

	return &token, nil
}

func (c *Client) ReplaceMCPOAuthToken(ctx context.Context, userID, mcpID, url, oauthAuthRequestID string, oauthConf *oauth2.Config, token *oauth2.Token) error {
	t := &types.MCPOAuthToken{
		UserID:             userID,
		MCPID:              mcpID,
		URL:                url,
		OAuthAuthRequestID: oauthAuthRequestID,
		AccessToken:        token.AccessToken,
		TokenType:          token.TokenType,
		RefreshToken:       token.RefreshToken,
		Expiry:             token.Expiry,
		ExpiresIn:          token.ExpiresIn,
		ClientID:           oauthConf.ClientID,
		ClientSecret:       oauthConf.ClientSecret,
		Endpoint:           oauthConf.Endpoint,
		RedirectURL:        oauthConf.RedirectURL,
		Scopes:             strings.Join(oauthConf.Scopes, " "),
	}

	if err := c.encryptMCPOAuthToken(ctx, t); err != nil {
		return fmt.Errorf("failed to encrypt token: %w", err)
	}

	if err := c.db.WithContext(ctx).Save(t).Error; err != nil {
		return err
	}
	return c.triggerMCPOAuthTokenChange(ctx, mcpID)
}

func (c *Client) DeleteMCPOAuthTokenForURL(ctx context.Context, userID, mcpID, mcpURL string) error {
	if err := c.db.WithContext(ctx).Delete(&types.MCPOAuthToken{}, "user_id = ? AND mcp_id = ? AND (url = ? OR url = ?)", userID, mcpID, mcpURL, "").Error; !errors.Is(err, gorm.ErrRecordNotFound) {
		return err
	}
	return c.triggerMCPOAuthTokenChange(ctx, mcpID)
}

func (c *Client) DeleteMCPOAuthTokens(ctx context.Context, userID, mcpID string) error {
	if err := c.db.WithContext(ctx).Delete(&types.MCPOAuthToken{}, "user_id = ? AND mcp_id = ?", userID, mcpID).Error; !errors.Is(err, gorm.ErrRecordNotFound) {
		return err
	}
	return c.triggerMCPOAuthTokenChange(ctx, mcpID)
}

func (c *Client) DeleteMCPOAuthTokenForAllUsers(ctx context.Context, mcpID string) error {
	if err := c.db.WithContext(ctx).Delete(&types.MCPOAuthToken{}, "mcp_id = ?", mcpID).Error; !errors.Is(err, gorm.ErrRecordNotFound) {
		return err
	}
	return c.triggerMCPOAuthTokenChange(ctx, mcpID)
}

func (c *Client) triggerMCPOAuthTokenChange(ctx context.Context, mcpID string) error {
	if mcpID == "" || c.mcpOAuthTokenTrigger == nil {
		return nil
	}
	return c.mcpOAuthTokenTrigger(ctx, mcpID)
}

// Pending state methods

func (c *Client) CreateMCPStaticOAuthTest(ctx context.Context, userID, mcpID, mcpURL, verifier string, oauthConf *oauth2.Config) (string, error) {
	state := strings.ToLower(rand.Text())
	ps := &types.MCPOAuthPendingState{
		HashedState:           fmt.Sprintf("%x", sha256.Sum256([]byte(state))),
		State:                 state,
		Verifier:              verifier,
		UserID:                userID,
		MCPID:                 mcpID,
		URL:                   mcpURL,
		ClientID:              oauthConf.ClientID,
		ClientSecret:          oauthConf.ClientSecret,
		AuthURL:               oauthConf.Endpoint.AuthURL,
		TokenURL:              oauthConf.Endpoint.TokenURL,
		AuthStyle:             oauthConf.Endpoint.AuthStyle,
		RedirectURL:           oauthConf.RedirectURL,
		Scopes:                strings.Join(oauthConf.Scopes, " "),
		StaticOAuthTest:       true,
		StaticOAuthTestStatus: apitypes.MCPStaticOAuthTestStatusPending,
	}

	if err := c.encryptMCPOAuthPendingState(ctx, ps); err != nil {
		return "", fmt.Errorf("failed to encrypt static OAuth test: %w", err)
	}
	if err := c.db.WithContext(ctx).Create(ps).Error; err != nil {
		return "", err
	}
	return state, nil
}

func (c *Client) GetMCPStaticOAuthTestStatus(ctx context.Context, state string) (apitypes.MCPStaticOAuthTestResult, error) {
	ps, err := c.GetMCPOAuthPendingState(ctx, state)
	if err != nil {
		return apitypes.MCPStaticOAuthTestResult{}, err
	}
	if !ps.StaticOAuthTest {
		return apitypes.MCPStaticOAuthTestResult{}, ErrMCPStaticOAuthTestInvalid
	}
	if time.Since(ps.CreatedAt) >= pendingStateTTL {
		return apitypes.MCPStaticOAuthTestResult{
			Status:          apitypes.MCPStaticOAuthTestStatusFailed,
			FailureCategory: apitypes.MCPStaticOAuthTestFailureExpired,
		}, nil
	}
	return apitypes.MCPStaticOAuthTestResult{
		Status:          ps.StaticOAuthTestStatus,
		FailureCategory: ps.StaticOAuthTestFailureCategory,
	}, nil
}

func (c *Client) CompleteMCPStaticOAuthTest(ctx context.Context, state string, status apitypes.MCPStaticOAuthTestStatus, failureCategory apitypes.MCPStaticOAuthTestFailureCategory) error {
	if !validMCPStaticOAuthTestCompletion(status, failureCategory) {
		return ErrMCPStaticOAuthTestInvalid
	}

	hashedState := fmt.Sprintf("%x", sha256.Sum256([]byte(state)))
	completedAt := time.Now()
	result := c.db.WithContext(ctx).
		Model(&types.MCPOAuthPendingState{}).
		Where("hashed_state = ? AND static_o_auth_test = ? AND static_o_auth_test_status = ? AND created_at >= ?", hashedState, true, apitypes.MCPStaticOAuthTestStatusPending, completedAt.Add(-pendingStateTTL)).
		Select("StaticOAuthTestStatus", "StaticOAuthTestFailureCategory", "StaticOAuthTestCompletedAt").
		Updates(&types.MCPOAuthPendingState{
			StaticOAuthTestStatus:          status,
			StaticOAuthTestFailureCategory: failureCategory,
			StaticOAuthTestCompletedAt:     completedAt,
		})
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected != 1 {
		return ErrMCPStaticOAuthTestInvalid
	}
	return nil
}

func validMCPStaticOAuthTestCompletion(status apitypes.MCPStaticOAuthTestStatus, failureCategory apitypes.MCPStaticOAuthTestFailureCategory) bool {
	if status == apitypes.MCPStaticOAuthTestStatusSucceeded {
		return failureCategory == ""
	}
	if status != apitypes.MCPStaticOAuthTestStatusFailed {
		return false
	}
	switch failureCategory {
	case apitypes.MCPStaticOAuthTestFailureAuthorizationDenied,
		apitypes.MCPStaticOAuthTestFailureInvalidCallback,
		apitypes.MCPStaticOAuthTestFailureTokenExchange:
		return true
	default:
		return false
	}
}

func (c *Client) ConsumeMCPStaticOAuthTest(ctx context.Context, state, userID, mcpID, mcpURL, clientID, clientSecret string) error {
	ps, err := c.GetMCPOAuthPendingState(ctx, state)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrMCPStaticOAuthTestInvalid
		}
		return err
	}
	if !ps.StaticOAuthTest ||
		ps.StaticOAuthTestStatus != apitypes.MCPStaticOAuthTestStatusSucceeded ||
		time.Since(ps.CreatedAt) >= pendingStateTTL ||
		!secureStringEqual(ps.UserID, userID) ||
		!secureStringEqual(ps.MCPID, mcpID) ||
		!secureStringEqual(ps.URL, mcpURL) ||
		!secureStringEqual(ps.ClientID, clientID) ||
		!secureStringEqual(ps.ClientSecret, clientSecret) {
		return ErrMCPStaticOAuthTestInvalid
	}

	result := c.db.WithContext(ctx).Delete(
		&types.MCPOAuthPendingState{},
		"hashed_state = ? AND static_o_auth_test = ? AND static_o_auth_test_status = ? AND created_at >= ?",
		ps.HashedState,
		true,
		apitypes.MCPStaticOAuthTestStatusSucceeded,
		time.Now().Add(-pendingStateTTL),
	)
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected != 1 {
		return ErrMCPStaticOAuthTestInvalid
	}
	return nil
}

func secureStringEqual(a, b string) bool {
	aHash := sha256.Sum256([]byte(a))
	bHash := sha256.Sum256([]byte(b))
	return subtle.ConstantTimeCompare(aHash[:], bHash[:]) == 1
}

func (c *Client) CreateMCPOAuthPendingState(ctx context.Context, userID, mcpID, mcpURL, oauthAuthRequestID, state, verifier string, oauthConf *oauth2.Config) error {
	hashedState := fmt.Sprintf("%x", sha256.Sum256([]byte(state)))
	ps := &types.MCPOAuthPendingState{
		HashedState:        hashedState,
		State:              state,
		Verifier:           verifier,
		UserID:             userID,
		MCPID:              mcpID,
		URL:                mcpURL,
		OAuthAuthRequestID: oauthAuthRequestID,
		ClientID:           oauthConf.ClientID,
		ClientSecret:       oauthConf.ClientSecret,
		AuthURL:            oauthConf.Endpoint.AuthURL,
		TokenURL:           oauthConf.Endpoint.TokenURL,
		AuthStyle:          oauthConf.Endpoint.AuthStyle,
		RedirectURL:        oauthConf.RedirectURL,
		Scopes:             strings.Join(oauthConf.Scopes, " "),
	}

	if err := c.encryptMCPOAuthPendingState(ctx, ps); err != nil {
		return fmt.Errorf("failed to encrypt pending state: %w", err)
	}

	return c.db.WithContext(ctx).Create(ps).Error
}

func (c *Client) GetMCPOAuthPendingState(ctx context.Context, state string) (*types.MCPOAuthPendingState, error) {
	hashedState := fmt.Sprintf("%x", sha256.Sum256([]byte(state)))
	ps := new(types.MCPOAuthPendingState)
	if err := c.db.WithContext(ctx).Where("hashed_state = ?", hashedState).First(ps).Error; err != nil {
		return nil, err
	}

	if err := c.decryptMCPOAuthPendingState(ctx, ps); err != nil {
		return nil, fmt.Errorf("failed to decrypt pending state: %w", err)
	}

	return ps, nil
}

func (c *Client) DeleteMCPOAuthPendingState(ctx context.Context, hashedState string) error {
	return c.db.WithContext(ctx).Delete(&types.MCPOAuthPendingState{}, "hashed_state = ?", hashedState).Error
}

const pendingStateTTL = 30 * time.Minute

func (c *Client) CleanupExpiredMCPOAuthPendingStates(ctx context.Context, olderThan time.Duration) error {
	cutoff := time.Now().Add(-olderThan)
	return c.db.WithContext(ctx).Delete(&types.MCPOAuthPendingState{}, "created_at < ?", cutoff).Error
}

func (c *Client) runPendingStateCleanup(ctx context.Context) {
	timer := time.NewTimer(pendingStateTTL)
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}

		if err := c.CleanupExpiredMCPOAuthPendingStates(ctx, pendingStateTTL); err != nil {
			log.Errorf("Failed to cleanup expired MCP OAuth pending states: %v", err)
		}

		timer.Reset(pendingStateTTL)
	}
}

// Encryption for MCPOAuthToken

func (c *Client) encryptMCPOAuthToken(ctx context.Context, token *types.MCPOAuthToken) error {
	if c.encryptionConfig == nil {
		return nil
	}

	transformer := c.encryptionConfig.Transformers[mcpOAuthTokenGroupResource]
	if transformer == nil {
		return nil
	}

	var (
		b    []byte
		err  error
		errs []error

		dataCtx = mcpOAuthTokenCtx(token)
	)
	if b, err = transformer.TransformToStorage(ctx, []byte(token.AccessToken), dataCtx); err != nil {
		errs = append(errs, err)
	} else {
		token.AccessToken = base64.StdEncoding.EncodeToString(b)
	}
	if b, err = transformer.TransformToStorage(ctx, []byte(token.RefreshToken), dataCtx); err != nil {
		errs = append(errs, err)
	} else {
		token.RefreshToken = base64.StdEncoding.EncodeToString(b)
	}
	if b, err = transformer.TransformToStorage(ctx, []byte(token.ClientID), dataCtx); err != nil {
		errs = append(errs, err)
	} else {
		token.ClientID = base64.StdEncoding.EncodeToString(b)
	}
	if b, err = transformer.TransformToStorage(ctx, []byte(token.ClientSecret), dataCtx); err != nil {
		errs = append(errs, err)
	} else {
		token.ClientSecret = base64.StdEncoding.EncodeToString(b)
	}

	token.Encrypted = true

	return errors.Join(errs...)
}

func (c *Client) decryptMCPOAuthToken(ctx context.Context, token *types.MCPOAuthToken) error {
	if !token.Encrypted || c.encryptionConfig == nil {
		return nil
	}

	transformer := c.encryptionConfig.Transformers[mcpOAuthTokenGroupResource]
	if transformer == nil {
		return nil
	}

	var (
		out, decoded []byte
		n            int
		err          error
		errs         []error

		dataCtx = mcpOAuthTokenCtx(token)
	)

	decoded = make([]byte, base64.StdEncoding.DecodedLen(len(token.AccessToken)))
	n, err = base64.StdEncoding.Decode(decoded, []byte(token.AccessToken))
	if err == nil {
		if out, _, err = transformer.TransformFromStorage(ctx, decoded[:n], dataCtx); err != nil {
			errs = append(errs, err)
		} else {
			token.AccessToken = string(out)
		}
	} else {
		errs = append(errs, err)
	}

	decoded = make([]byte, base64.StdEncoding.DecodedLen(len(token.RefreshToken)))
	n, err = base64.StdEncoding.Decode(decoded, []byte(token.RefreshToken))
	if err == nil {
		if out, _, err = transformer.TransformFromStorage(ctx, decoded[:n], dataCtx); err != nil {
			errs = append(errs, err)
		} else {
			token.RefreshToken = string(out)
		}
	} else {
		errs = append(errs, err)
	}

	decoded = make([]byte, base64.StdEncoding.DecodedLen(len(token.ClientID)))
	n, err = base64.StdEncoding.Decode(decoded, []byte(token.ClientID))
	if err == nil {
		if out, _, err = transformer.TransformFromStorage(ctx, decoded[:n], dataCtx); err != nil {
			errs = append(errs, err)
		} else {
			token.ClientID = string(out)
		}
	} else {
		errs = append(errs, err)
	}

	decoded = make([]byte, base64.StdEncoding.DecodedLen(len(token.ClientSecret)))
	n, err = base64.StdEncoding.Decode(decoded, []byte(token.ClientSecret))
	if err == nil {
		if out, _, err = transformer.TransformFromStorage(ctx, decoded[:n], dataCtx); err != nil {
			errs = append(errs, err)
		} else {
			token.ClientSecret = string(out)
		}
	} else {
		errs = append(errs, err)
	}

	return errors.Join(errs...)
}

func mcpOAuthTokenCtx(token *types.MCPOAuthToken) value.Context {
	return value.DefaultContext(fmt.Sprintf("%s/%s", mcpOAuthTokenGroupResource.String(), token.MCPID))
}

// Encryption for MCPOAuthPendingState

func (c *Client) encryptMCPOAuthPendingState(ctx context.Context, ps *types.MCPOAuthPendingState) error {
	if c.encryptionConfig == nil {
		return nil
	}

	transformer := c.encryptionConfig.Transformers[mcpOAuthPendingStateGroupResource]
	if transformer == nil {
		// Fall back to using the token transformer if no specific one is configured
		transformer = c.encryptionConfig.Transformers[mcpOAuthTokenGroupResource]
		if transformer == nil {
			return nil
		}
	}

	var errs []error
	dataCtx := mcpOAuthPendingStateCtx(ps)
	for _, field := range mcpOAuthPendingStateEncryptedFields(ps) {
		b, err := transformer.TransformToStorage(ctx, []byte(*field), dataCtx)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		*field = base64.StdEncoding.EncodeToString(b)
	}

	ps.Encrypted = true

	return errors.Join(errs...)
}

func (c *Client) decryptMCPOAuthPendingState(ctx context.Context, ps *types.MCPOAuthPendingState) error {
	if !ps.Encrypted || c.encryptionConfig == nil {
		return nil
	}

	transformer := c.encryptionConfig.Transformers[mcpOAuthPendingStateGroupResource]
	if transformer == nil {
		transformer = c.encryptionConfig.Transformers[mcpOAuthTokenGroupResource]
		if transformer == nil {
			return nil
		}
	}

	var errs []error
	dataCtx := mcpOAuthPendingStateCtx(ps)
	for _, field := range mcpOAuthPendingStateEncryptedFields(ps) {
		decoded, err := base64.StdEncoding.DecodeString(*field)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		out, _, err := transformer.TransformFromStorage(ctx, decoded, dataCtx)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		*field = string(out)
	}

	return errors.Join(errs...)
}

func mcpOAuthPendingStateEncryptedFields(ps *types.MCPOAuthPendingState) []*string {
	fields := []*string{
		&ps.State,
		&ps.Verifier,
		&ps.ClientID,
		&ps.ClientSecret,
	}
	if ps.StaticOAuthTest {
		fields = append(fields, &ps.URL, &ps.AuthURL, &ps.TokenURL, &ps.RedirectURL, &ps.Scopes)
	}
	return fields
}

func mcpOAuthPendingStateCtx(ps *types.MCPOAuthPendingState) value.Context {
	return value.DefaultContext(fmt.Sprintf("%s/%s", mcpOAuthPendingStateGroupResource.String(), ps.MCPID))
}
