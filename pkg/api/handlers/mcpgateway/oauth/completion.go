package oauth

import (
	"net/url"
	"regexp"
	"strings"
)

const (
	maxCompletionErrorCodeBytes   = 64
	maxCompletionDescriptionBytes = 512
)

var (
	// The key list matches Studio's MCP Settings redaction
	// (src/server/modules/mcp/obot-client/error-message.ts), plus code and state.
	completionCredentialKey = regexp.MustCompile(`(?i)(?:(?:\\\\)*\\?["'])?\b(?:aws[\s_-]*secret[\s_-]*access[\s_-]*key|client[\s_-]*secret|client[\s_-]*assertion|api[\s_-]*key|authorization[\s_-]*code|oauth[\s_-]*code|access[\s_-]*token|refresh[\s_-]*token|id[\s_-]*token|test[\s_-]*state|code[\s_-]*(?:verifier|challenge)|private[\s_-]*key|proof|set[\s_-]*cookie|cookie|password|secret|token|authorization|credential|nonce|signature|code|state)\b(?:(?:\\\\)*\\?["'])?\s*[:=]\s*`)

	// Credential shapes that carry no key=value form, ported from Studio's MCP
	// Settings redaction. RE2 has no lookahead, so Studio's "not already redacted"
	// guards are dropped: redacting "[REDACTED]" again changes nothing. An
	// unquoted value also stops at a quote or backslash, so a match never
	// swallows the quote that closes a JSON value.
	//
	// Run before the key scan: an authorization header value has a scheme word
	// and a space, which the key scan would stop at.
	credentialShapesBeforeKeys = []credentialShape{
		{regexp.MustCompile(`(?i)-{4,}[ \t]*BEGIN[ \t]+(?:[A-Z0-9]+[ \t]+)*PRIVATE[ \t]+KEY(?:[ \t]+BLOCK)?[ \t]*-{4,}[\s\S]*?(?:-{4,}[ \t]*END[ \t]+(?:[A-Z0-9]+[ \t]+)*PRIVATE[ \t]+KEY(?:[ \t]+BLOCK)?[ \t]*-{4,}|$)`), "[REDACTED]"},
		// Unquoted only: a quoted value goes to the escape-aware key scan, which
		// does not stop at an escaped quote inside it.
		{regexp.MustCompile(`(?i)(\bauthorization\b\s*[:=]\s*)(?:[A-Za-z][A-Za-z0-9_-]{0,31}\s+)?[^\s,;&}"'\\]+`), "${1}[REDACTED]"},
		{regexp.MustCompile(`(?i)(\b(?:proxy-)?authorization\b\s+(?:Basic|Bearer|Digest|ApiKey|Token)\s+)[^\s,;&}"'\\]+`), "${1}[REDACTED]"},
		{regexp.MustCompile(`(?i)\bBearer\s+[^\s,;&"'\\]+`), "Bearer [REDACTED]"},
	}
	credentialShapesAfterKeys = []credentialShape{
		{regexp.MustCompile(`(?i)(^|[^A-Za-z0-9_-])(?:vd_(?:iat|pat|org|svc)_[A-Za-z0-9_.-]+|ok1-\d+-\d+-[A-Za-z0-9_-]+|osa1-\d+-[A-Za-z0-9_-]+|github_pat_[A-Za-z0-9_]{20,}|gh[pousr]_[A-Za-z0-9]{20,}|sk-(?:proj-|ant-api\d+-)?[A-Za-z0-9_-]{20,}|xox[baprs]-[A-Za-z0-9-]{20,}|AKIA[A-Z0-9]{16}\b|AIza[A-Za-z0-9_-]{32,}|eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})`), "${1}[REDACTED]"},
		{regexp.MustCompile(`(\b[a-zA-Z][a-zA-Z0-9+\-.]{0,31}://)(?:[^@\s/:]+:[^@\s/]+|[^@\s/]+)@`), "${1}[REDACTED]@"},
	}

	// Studio's named keys without code and state, which are ordinary words in
	// prose. The connector is "is"/"was", "value:", or bare whitespace.
	bareCredentialKey = regexp.MustCompile(`(?i)\b(?:aws[\s_-]*secret[\s_-]*access[\s_-]*key|client[\s_-]*secret|client[\s_-]*assertion|api[\s_-]*key|authorization[\s_-]*code|oauth[\s_-]*code|access[\s_-]*token|refresh[\s_-]*token|id[\s_-]*token|test[\s_-]*state|code[\s_-]*(?:verifier|challenge)|private[\s_-]*key|proof|set[\s_-]*cookie|cookie|password|secret|token)\b(\s+(?:is|was)\s+|\s+value\s*[:=]\s*|\s+)`)

	// A provider saying a credential is expired or missing is the diagnostic the
	// user needs, so those words stay.
	safeCredentialStatus = map[string]bool{
		"active": true, "available": true, "configured": true, "disabled": true, "enabled": true,
		"expired": true, "invalid": true, "missing": true, "not": true, "rejected": true,
		"required": true, "revoked": true, "unavailable": true, "unset": true, "valid": true,
	}

	cookieScheme      = regexp.MustCompile(`(?i)\b(?:set[\s_-]*)?cookie[ \t]*:[ \t]*`)
	cookieToken       = regexp.MustCompile(`^[^\s=;,"'\\]+`)
	cookieAssign      = regexp.MustCompile(`^[ \t]*=[ \t]*`)
	cookieSeparator   = regexp.MustCompile(`^[ \t]*[;,][ \t]*`)
	cookieExpiresDate = regexp.MustCompile(`(?i)^[a-z]{3},[ \t]*\d{1,2}[ -][a-z]{3}[ -]\d{2,4}[ \t]+\d{2}:\d{2}:\d{2}[ \t]*GMT`)

	digestScheme         = regexp.MustCompile(`(?i)\bDigest\s+`)
	digestParamName      = regexp.MustCompile(`^[A-Za-z0-9_-]+\s*=\s*`)
	digestParamSeparator = regexp.MustCompile(`^\s*,\s*`)
)

// oauthCallbackError carries the parts of a failed callback that may reach a
// completion page. Err keeps the full message for Obot's own HTTP error path.
type oauthCallbackError struct {
	Code        string
	Description string
	Err         error
}

type credentialShape struct {
	pattern *regexp.Regexp
	replace string
}

func (e *oauthCallbackError) Error() string { return e.Err.Error() }

func (e *oauthCallbackError) Unwrap() error { return e.Err }

func redactCredentialShapes(s string, shapes []credentialShape) string {
	for _, shape := range shapes {
		s = shape.pattern.ReplaceAllString(s, shape.replace)
	}
	return s
}

// redactCompletionCredentials runs on the raw provider text, before
// sanitizeOAuthErrorDescription rewrites quotes and backslashes, so a quoted
// or JSON-escaped value is removed whole, including any spaces it contains.
// A regex cannot tell an escaped quote inside a value from the quote that
// closes it, so the value is scanned instead.
func redactCompletionCredentials(s string) string {
	var b strings.Builder
	pos := 0
	for pos < len(s) {
		loc := completionCredentialKey.FindStringIndex(s[pos:])
		if loc == nil {
			break
		}
		keyEnd := pos + loc[1]
		b.WriteString(s[pos:keyEnd])
		delim, valueEnd := credentialValueEnd(s, keyEnd)
		b.WriteString(delim + "[REDACTED]" + delim)
		pos = valueEnd
	}
	b.WriteString(s[pos:])
	return b.String()
}

// credentialValueEnd returns the delimiter a value opened with and the index
// just past the value. An unterminated quoted value runs to the end of s, so a
// truncated description never leaks its tail.
func credentialValueEnd(s string, i int) (string, int) {
	rest := s[i:]
	if n := len(rest) - len(strings.TrimLeft(rest, `\`)); n >= 3 && n%2 == 1 && n < len(rest) && rest[n] == '"' {
		// A quote escaped at a deeper layer (JSON in JSON in a string): the value
		// ends at the next quote preceded by exactly the same backslash run, since
		// a quote escaped inside the value carries a longer run.
		for j := i + n + 1; j < len(s); j++ {
			if s[j] != '"' {
				continue
			}
			k := j
			for k > i+n+1 && s[k-1] == '\\' {
				k--
			}
			if j-k == n {
				return rest[:n+1], j + 1
			}
		}
		return rest[:n+1], len(s)
	}
	switch {
	case strings.HasPrefix(rest, `\"`):
		// JSON inside another string: undo one escape layer, then stop at the
		// first inner quote that no inner backslash escapes.
		innerEscape := false
		for j := i + 2; j < len(s); {
			c, step := s[j], 1
			if c == '\\' && j+1 < len(s) {
				c, step = s[j+1], 2
			}
			j += step
			switch {
			case innerEscape:
				innerEscape = false
			case c == '\\':
				innerEscape = true
			case c == '"':
				return `\"`, j
			}
		}
		return `\"`, len(s)
	case strings.HasPrefix(rest, `"`), strings.HasPrefix(rest, `'`):
		quote := s[i]
		for j := i + 1; j < len(s); j++ {
			if s[j] == '\\' {
				j++
				continue
			}
			if s[j] == quote {
				return string(quote), j + 1
			}
		}
		return string(quote), len(s)
	}
	j := i
	for j < len(s) && !strings.ContainsRune(" \t\r\n&,;}\"'", rune(s[j])) {
		j++
	}
	return "", j
}

// safeOAuthErrorCode keeps the RFC 6749 error-code alphabet so a provider
// cannot smuggle markup or a second query parameter through the code.
func safeOAuthErrorCode(code string) string {
	code = strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_', r == '.', r == '-':
			return r
		default:
			return -1
		}
	}, code)
	if len(code) > maxCompletionErrorCodeBytes {
		code = code[:maxCompletionErrorCodeBytes]
	}
	if code == "" {
		return "server_error"
	}
	return code
}

// redactBareCredentials removes values named in prose ("the password is
// hunter2", "secret \"x\"", "token rotation-opaque-value"). After bare
// whitespace an unquoted word is redacted only when it looks like a credential,
// so "token exchange failed" keeps its words.
func redactBareCredentials(s string) string {
	var b strings.Builder
	pos := 0
	for pos < len(s) {
		loc := bareCredentialKey.FindStringSubmatchIndex(s[pos:])
		if loc == nil {
			break
		}
		keyEnd := pos + loc[1]
		plain := strings.TrimSpace(s[pos+loc[2]:pos+loc[3]]) == ""
		delim, valueEnd := credentialValueEnd(s, keyEnd)
		value := strings.TrimSuffix(strings.TrimPrefix(s[keyEnd:valueEnd], delim), delim)
		b.WriteString(s[pos:keyEnd])
		if !bareValueIsCredential(value, delim, plain) {
			pos = keyEnd
			continue
		}
		b.WriteString(delim + "[REDACTED]" + delim)
		pos = valueEnd
	}
	b.WriteString(s[pos:])
	return b.String()
}

func bareValueIsCredential(value, delim string, plain bool) bool {
	word := strings.TrimRight(value, ".!?")
	switch {
	case word == "" || word == "[REDACTED]":
		return false
	case plain && delim != "":
		return true
	case safeCredentialStatus[strings.ToLower(word)]:
		return false
	case plain:
		return len(word) >= 20 || strings.ContainsAny(word, "-_.0123456789")
	}
	return true
}

// redactCookieHeaders redacts every value of a Cookie or Set-Cookie header. It
// scans pair by pair instead of matching the whole header, because a quoted value
// may hold whitespace and an attribute such as Secure has no value; either one
// ended a single-regex match early and left the later pairs readable. Pairs are
// separated only by ";" or "," on the same line, so a request id or URL after the
// header is not mistaken for a pair. An Expires date holds ", " itself, so it is
// matched whole and kept rather than ending the scan before the next pair.
func redactCookieHeaders(s string) string {
	var b strings.Builder
	pos := 0
	for pos < len(s) {
		loc := cookieScheme.FindStringIndex(s[pos:])
		if loc == nil {
			break
		}
		i := pos + loc[1]
		b.WriteString(s[pos:i])
		for {
			token := cookieToken.FindStringIndex(s[i:])
			if token == nil {
				break
			}
			j := i + token[1]
			if assign := cookieAssign.FindStringIndex(s[j:]); assign != nil {
				valueStart := j + assign[1]
				if date := cookieExpiresDate.FindStringIndex(s[valueStart:]); date != nil && strings.EqualFold(s[i:j], "expires") {
					b.WriteString(s[i : valueStart+date[1]])
					j = valueStart + date[1]
				} else {
					delim, valueEnd := credentialValueEnd(s, valueStart)
					b.WriteString(s[i:valueStart] + delim + "[REDACTED]" + delim)
					j = valueEnd
				}
			} else {
				b.WriteString(s[i:j])
			}
			i = j
			sep := cookieSeparator.FindStringIndex(s[i:])
			if sep == nil {
				break
			}
			b.WriteString(s[i : i+sep[1]])
			i += sep[1]
		}
		pos = i
	}
	b.WriteString(s[pos:])
	return b.String()
}

// redactDigestParameters redacts every value of a Digest credential or challenge. The
// authorization pass stops at the first parameter and the key scan knows neither
// "response" nor "cnonce", so later parameters would otherwise survive.
func redactDigestParameters(s string) string {
	var b strings.Builder
	pos := 0
	for pos < len(s) {
		loc := digestScheme.FindStringIndex(s[pos:])
		if loc == nil {
			break
		}
		i := pos + loc[1]
		b.WriteString(s[pos:i])
		pos = i
		for {
			name := digestParamName.FindStringIndex(s[i:])
			if name == nil {
				break
			}
			valueStart := i + name[1]
			delim, valueEnd := credentialValueEnd(s, valueStart)
			b.WriteString(s[i:valueStart] + delim + "[REDACTED]" + delim)
			i, pos = valueEnd, valueEnd
			sep := digestParamSeparator.FindStringIndex(s[i:])
			if sep == nil {
				break
			}
			b.WriteString(s[i : i+sep[1]])
			i += sep[1]
			pos = i
		}
	}
	b.WriteString(s[pos:])
	return b.String()
}

// redactKnownValues replaces every occurrence of a value this callback holds, so a
// provider that echoes the client secret, verifier, state or code without a
// recognizable label still cannot put it in the redirect. Overlapping matches merge
// into one marker.
func redactKnownValues(s string, values ...string) string {
	covered := make([]bool, len(s))
	for _, v := range values {
		if v == "" {
			continue
		}
		for from := 0; from < len(s); {
			at := strings.Index(s[from:], v)
			if at < 0 {
				break
			}
			for k := from + at; k < from+at+len(v); k++ {
				covered[k] = true
			}
			from += at + 1
		}
	}
	var b strings.Builder
	for i := 0; i < len(s); {
		if !covered[i] {
			b.WriteByte(s[i])
			i++
			continue
		}
		for i < len(s) && covered[i] {
			i++
		}
		b.WriteString("[REDACTED]")
	}
	return b.String()
}

// sanitizeMCPOAuthCompletionDescription keeps the provider's own words but
// removes any authorization code, state or credential it echoed, because the result is
// placed in a URL that lands in browser history.
func sanitizeMCPOAuthCompletionDescription(description string) string {
	description = redactDigestParameters(description)
	description = redactCookieHeaders(description)
	description = redactCredentialShapes(description, credentialShapesBeforeKeys)
	description = redactCompletionCredentials(description)
	description = redactBareCredentials(description)
	description = redactCredentialShapes(description, credentialShapesAfterKeys)
	description = sanitizeOAuthErrorDescription(description)
	if len(description) > maxCompletionDescriptionBytes {
		description = description[:maxCompletionDescriptionBytes]
	}
	return description
}

// callbackFailureQuery describes a failed callback for the completion page;
// flow is "instance" for a UI-started connection or "component" for one
// component of an aggregate.
func callbackFailureQuery(flow, mcpID string, cbErr *oauthCallbackError) url.Values {
	q := url.Values{
		"flow":   {flow},
		"status": {"failed"},
		"error":  {safeOAuthErrorCode(cbErr.Code)},
	}
	if description := sanitizeMCPOAuthCompletionDescription(cbErr.Description); description != "" {
		q.Set("error_description", description)
	}
	if mcpID != "" {
		q.Set("mcp_id", mcpID)
	}
	return q
}
