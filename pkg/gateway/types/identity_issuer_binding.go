package types

import "strings"

// GenericOAuthAuthProviderName is the auth provider whose identities bind the issuer into their provider user ID.
// Its issuer is admin-configurable, so a subject alone does not identify a user: the same subject from a different
// issuer is a different person.
const GenericOAuthAuthProviderName = "generic-oauth-auth-provider"

const (
	qualifiedIssuerPrefix  = "iss:"
	qualifiedSubjectPrefix = "\nsub:"
)

// NormalizeIssuer returns the issuer in the form identities are keyed on: surrounding whitespace and trailing
// slashes removed, matching how the configured issuer and token issuers are compared.
func NormalizeIssuer(issuer string) string {
	return strings.TrimRight(strings.TrimSpace(issuer), "/")
}

// QualifyProviderUserID binds a subject to its issuer, so the identity key changes when the issuer does. It returns
// the subject unchanged when the issuer is empty. The separator is a newline because a URL cannot contain one and
// Postgres text, which stores the ID when encryption is off, rejects NUL bytes.
func QualifyProviderUserID(issuer, subject string) string {
	issuer = NormalizeIssuer(issuer)
	if issuer == "" {
		return subject
	}
	return qualifiedIssuerPrefix + issuer + qualifiedSubjectPrefix + subject
}

// ParseQualifiedProviderUserID splits an ID built by QualifyProviderUserID. ok is false for any other ID, such as a
// legacy subject-only ID.
func ParseQualifiedProviderUserID(id string) (issuer, subject string, ok bool) {
	rest, found := strings.CutPrefix(id, qualifiedIssuerPrefix)
	if !found {
		return "", "", false
	}
	issuer, subject, found = strings.Cut(rest, qualifiedSubjectPrefix)
	if !found || issuer == "" {
		return "", "", false
	}
	return issuer, subject, true
}

// ProviderSubject returns the subject the identity provider knows the user by: the subject part of a qualified ID,
// or the ID itself.
func ProviderSubject(id string) string {
	if _, subject, ok := ParseQualifiedProviderUserID(id); ok {
		return subject
	}
	return id
}
