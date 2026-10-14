package oauth

import (
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSafeOAuthErrorCode(t *testing.T) {
	require.Equal(t, "badscriptcode", safeOAuthErrorCode("bad<script>\ncode"))
	require.Equal(t, "access_denied", safeOAuthErrorCode("access_denied"))
	require.Equal(t, "server_error", safeOAuthErrorCode(""))
	require.Equal(t, "server_error", safeOAuthErrorCode("<>"))
	require.Len(t, safeOAuthErrorCode(strings.Repeat("a", 100)), 64)
}

func TestSanitizeMCPOAuthCompletionDescription(t *testing.T) {
	got := sanitizeMCPOAuthCompletionDescription("denied\r\ncode=c-7&state=s-9 for workspace ws-42")
	require.Equal(t, "denied code=[REDACTED]&state=[REDACTED] for workspace ws-42", got)
	require.NotContains(t, got, "c-7")
	require.NotContains(t, got, "s-9")
	for _, leak := range []string{"client_secret=s3cr3t", `{"client_secret":"s3cr3t"}`, "access_token: tok-123", "refresh_token=tok-123&x=1"} {
		got := sanitizeMCPOAuthCompletionDescription("denied " + leak)
		require.NotContains(t, got, "s3cr3t", leak)
		require.NotContains(t, got, "tok-123", leak)
		require.Contains(t, got, "[REDACTED]", leak)
	}
	got = sanitizeMCPOAuthCompletionDescription(`denied {"client_secret":"s3 cr,et&x"} {\"access_token\":\"tok 1,2&3\"} password='p w,d&q'`)
	require.Equal(t, `denied {'client_secret':'[REDACTED]'} {/'access_token/':/'[REDACTED]/'} password='[REDACTED]'`, got)
	for _, fragment := range []string{"s3", "cr,et", "&x", "tok 1,2", "p w,d"} {
		require.NotContains(t, got, fragment)
	}
	// An escaped quote inside a JSON-escaped value does not end the value.
	got = sanitizeMCPOAuthCompletionDescription(`denied {\"client_secret\":\"head\\\" tail-secret\"} done`)
	require.Equal(t, `denied {/'client_secret/':/'[REDACTED]/'} done`, got)
	require.NotContains(t, got, "head")
	require.NotContains(t, got, "tail-secret")
	got = sanitizeMCPOAuthCompletionDescription(`denied {"password":"a\" b-secret"}`)
	require.Equal(t, `denied {'password':'[REDACTED]'}`, got)
	require.NotContains(t, got, "b-secret")
	// A doubly JSON-escaped key is still recognised, so its value is redacted.
	for _, tc := range []struct{ in, secret string }{
		{`denied {\\\"client_secret\\\":\\\"a\\\\\\\" b-secret\\\"} retry`, "b-secret"},
		{`denied {\"x\":\"{\\\"password\\\":\\\"p-secret\\\"}\"} retry`, "p-secret"},
	} {
		got := sanitizeMCPOAuthCompletionDescription(tc.in)
		require.NotContains(t, got, tc.secret, tc.in)
		require.Contains(t, got, "[REDACTED]", tc.in)
		require.True(t, strings.HasPrefix(got, "denied "), got)
		require.True(t, strings.HasSuffix(got, " retry"), got)
	}
	got = sanitizeMCPOAuthCompletionDescription(`denied {\\\"password\\\":\\\"unterminated p-secret`)
	require.NotContains(t, got, "p-secret")
	require.True(t, strings.HasPrefix(got, "denied "), got)
	// Every pair of a multi-value cookie header is redacted, not only the first.
	for _, in := range []string{
		"denied Cookie: sid=secret-one; refresh=secret-two retry",
		"denied Set-Cookie: sid=secret-one; Path=/; refresh=secret-two retry",
		`denied Cookie: sid="head secret-one"; refresh=secret-two retry`,
		"denied Set-Cookie: sid=secret-one; Secure, session=secret-two retry",
		"denied Set-Cookie: a=secret-one; Expires=Wed, 21 Oct 2015 07:28:00 GMT; session=secret-two retry",
		`denied {"x":"Cookie: sid=\"head secret-one\"; b=secret-two"} retry`,
		`denied {"x":"Cookie: sid=\"head\\\" secret-one\"; b=secret-two"} retry`,
	} {
		got := sanitizeMCPOAuthCompletionDescription(in)
		require.NotContains(t, got, "secret-one", in)
		require.NotContains(t, got, "secret-two", in)
		require.Contains(t, got, "retry", in)
	}
	// A cookie header ends at its line and at the first separator that is neither
	// ";" nor ","; the request id and URL after it stay readable.
	for _, in := range []string{
		"denied Cookie: sid=secret-one\nrequest-id=req-42 retry https://provider.example/fix",
		"denied Cookie: sid=secret-one request-id=req-42 retry https://provider.example/fix",
		"denied Set-Cookie: a=secret-one; Expires=Wed, 21 Oct 2015 07:28:00 GMT, b=secret-two request-id=req-42 retry https://provider.example/fix",
	} {
		got := sanitizeMCPOAuthCompletionDescription(in)
		require.NotContains(t, got, "secret-one", in)
		require.NotContains(t, got, "secret-two", in)
		for _, kept := range []string{"request-id=req-42", "retry", "https://provider.example/fix"} {
			require.Contains(t, got, kept, in)
		}
	}
	// Known values are removed wherever they appear; overlapping matches merge.
	require.Equal(t, "Rejected candidate [REDACTED] for ws-42 req-77 via [REDACTED]",
		redactKnownValues("Rejected candidate cs-5e8f1a3b9d27 for ws-42 req-77 via vf-9d3e6b2a7c10", "cs-5e8f1a3b9d27", "", "vf-9d3e6b2a7c10"))
	require.Equal(t, "ab[REDACTED]", redactKnownValues("abcdcde", "cdc", "dcde"))
	// Every parameter of a Digest credential is redacted, not only the first.
	for _, in := range []string{
		`denied Authorization: Digest username="alice", realm="example", response="d41d8cd98f00b204e9800998ecf8427e", retry`,
		`denied Digest username=alice, cnonce=c0ffee, response=d41d8cd98f00b204e9800998ecf8427e retry`,
		`denied {\"auth\":\"Digest username=\\\"alice\\\", response=\\\"d41d8cd98f00b204e9800998ecf8427e\\\"\"} retry`,
	} {
		got := sanitizeMCPOAuthCompletionDescription(in)
		require.NotContains(t, got, "d41d8cd98f00b204e9800998ecf8427e", in)
		require.NotContains(t, got, "alice", in)
		require.Contains(t, got, "retry", in)
	}
	// A value cut off before its closing quote is removed to the end.
	got = sanitizeMCPOAuthCompletionDescription(`denied "password":"cut off sec`)
	require.Equal(t, `denied 'password':'[REDACTED]'`, got)
	require.NotContains(t, got, "sec")
	// Credential shapes with no key=value form, as Studio's MCP Settings redaction
	// covers them. The remediation text around each one survives.
	for _, tc := range []struct{ in, want string }{
		{"denied Authorization: Bearer opaque-credential-123; reconnect the provider", "denied Authorization: [REDACTED]; reconnect the provider"},
		{"denied Bearer opaque-credential-123, reconnect the provider", "denied Bearer [REDACTED], reconnect the provider"},
		{"denied authorization Basic YWxpY2U6cHc9 reconnect the provider", "denied authorization Basic [REDACTED] reconnect the provider"},
		{"denied https://alice:password123@provider.example/fix then retry", "denied https://[REDACTED]@provider.example/fix then retry"},
		{"denied key ghp_abcdefghijklmnopqrstuvwxyz0123 was revoked", "denied key [REDACTED] was revoked"},
		{"denied -----BEGIN PRIVATE KEY-----\nMIIEvQ\n-----END PRIVATE KEY----- rotate it", "denied [REDACTED] rotate it"},
		{`denied {"authorization":"Bearer a b-secret"} retry`, `denied {'authorization':'[REDACTED]'} retry`},
		{`denied {\"authorization\":\"Bearer opaque-credential-123\"} retry`, `denied {/'authorization/':/'[REDACTED]/'} retry`},
		{"denied client secret: s3cr3t nonce=n-1 retry", "denied client secret: [REDACTED] nonce=[REDACTED] retry"},
		// A quoted header value goes through the escape-aware scan.
		{`denied authorization: "head\" tail-secret" retry`, `denied authorization: '[REDACTED]' retry`},
		{`denied authorization: "cut off tail-secret`, `denied authorization: '[REDACTED]'`},
		// Values named in prose.
		{"The password is hunter2", "The password is [REDACTED]"},
		{"denied password opaque-value for request-id=req-42", "denied password [REDACTED] for request-id=req-42"},
		{`denied secret "documentation" retry`, `denied secret '[REDACTED]' retry`},
		{`denied secret "a\" b-secret" retry`, `denied secret '[REDACTED]' retry`},
		{"denied token rotation-opaque-value retry", "denied token [REDACTED] retry"},
		{"Provider says client secret was s3cr3t-value", "Provider says client secret was [REDACTED]"},
		{"denied password value: hunter2 retry", "denied password value: [REDACTED] retry"},
		// A leading digit marks a credential too.
		{"denied password 7hunter retry", "denied password [REDACTED] retry"},
	} {
		got := sanitizeMCPOAuthCompletionDescription(tc.in)
		require.Equal(t, tc.want, got, tc.in)
		for _, fragment := range []string{"opaque-credential-123", "alice", "password123", "YWxpY2U6cHc9", "ghp_", "MIIEvQ", "b-secret", "s3cr3t", "n-1", "tail-secret", "hunter2", "opaque-value", "documentation", "7hunter"} {
			require.NotContains(t, got, fragment, tc.in)
		}
	}
	// A provider describing a credential's status keeps its words.
	for _, prose := range []string{
		"the token expired. token exchange failed; access token is invalid",
		"the secret is missing, password was rejected",
		"denied password is [REDACTED] already",
	} {
		require.Equal(t, prose, sanitizeMCPOAuthCompletionDescription(prose))
	}
	require.LessOrEqual(t, len(sanitizeMCPOAuthCompletionDescription(strings.Repeat("x ", 600))), 512)
	require.Empty(t, sanitizeMCPOAuthCompletionDescription(" \r\n "))
}

func TestInstanceCallbackFailureQuery(t *testing.T) {
	q := instanceCallbackFailureQuery("msi1", &oauthCallbackError{Code: "access_denied", Description: "user said no", Err: errors.New("x")})
	require.Equal(t, "access_denied", q.Get("error"))
	require.Equal(t, "user said no", q.Get("error_description"))
	require.Equal(t, "instance", q.Get("flow"))
	require.Equal(t, "failed", q.Get("status"))
	require.Equal(t, "msi1", q.Get("mcp_id"))

	q = instanceCallbackFailureQuery("", &oauthCallbackError{Code: "token_exchange_failed", Err: errors.New("x")})
	require.False(t, q.Has("error_description"))
	require.False(t, q.Has("mcp_id"))
}
