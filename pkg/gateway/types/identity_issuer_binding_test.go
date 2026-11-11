package types

import "testing"

func TestQualifyProviderUserIDBindsTheNormalizedIssuer(t *testing.T) {
	tests := []struct {
		name    string
		issuer  string
		subject string
		want    string
	}{
		{name: "issuer and subject", issuer: "https://idp.example.com", subject: "alice", want: "iss:https://idp.example.com\nsub:alice"},
		{name: "trailing slash and whitespace are normalized", issuer: " https://idp.example.com/ ", subject: "alice", want: "iss:https://idp.example.com\nsub:alice"},
		{name: "an empty issuer leaves the subject", issuer: "", subject: "alice", want: "alice"},
		{name: "a blank issuer leaves the subject", issuer: " / ", subject: "alice", want: "alice"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := QualifyProviderUserID(tt.issuer, tt.subject); got != tt.want {
				t.Fatalf("QualifyProviderUserID(%q, %q) = %q, want %q", tt.issuer, tt.subject, got, tt.want)
			}
		})
	}
}

func TestQualifyProviderUserIDDiffersByIssuer(t *testing.T) {
	a := QualifyProviderUserID("https://a.example.com", "alice")
	b := QualifyProviderUserID("https://b.example.com", "alice")
	if a == b {
		t.Fatalf("the same subject under two issuers qualified to the same ID %q", a)
	}
}

func TestParseQualifiedProviderUserID(t *testing.T) {
	tests := []struct {
		name        string
		id          string
		wantIssuer  string
		wantSubject string
		wantOK      bool
	}{
		{name: "qualified", id: QualifyProviderUserID("https://idp.example.com", "alice"), wantIssuer: "https://idp.example.com", wantSubject: "alice", wantOK: true},
		{name: "a subject that itself contains the separator text", id: QualifyProviderUserID("https://idp.example.com", "a\nsub:b"), wantIssuer: "https://idp.example.com", wantSubject: "a\nsub:b", wantOK: true},
		{name: "an empty subject", id: "iss:https://idp.example.com\nsub:", wantIssuer: "https://idp.example.com", wantSubject: "", wantOK: true},
		{name: "a legacy subject", id: "alice", wantOK: false},
		{name: "a subject that starts with the issuer prefix", id: "iss:alice", wantOK: false},
		{name: "an empty issuer", id: "iss:\nsub:alice", wantOK: false},
		{name: "empty", id: "", wantOK: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			issuer, subject, ok := ParseQualifiedProviderUserID(tt.id)
			if issuer != tt.wantIssuer || subject != tt.wantSubject || ok != tt.wantOK {
				t.Fatalf("ParseQualifiedProviderUserID(%q) = (%q, %q, %v), want (%q, %q, %v)", tt.id, issuer, subject, ok, tt.wantIssuer, tt.wantSubject, tt.wantOK)
			}
		})
	}
}

func TestProviderSubject(t *testing.T) {
	if got := ProviderSubject(QualifyProviderUserID("https://idp.example.com", "alice")); got != "alice" {
		t.Fatalf("ProviderSubject(qualified) = %q, want alice", got)
	}
	if got := ProviderSubject("alice"); got != "alice" {
		t.Fatalf("ProviderSubject(legacy) = %q, want alice", got)
	}
}

func TestGroupLookupIDFallsBackToTheProviderSubject(t *testing.T) {
	id := Identity{ProviderUserID: QualifyProviderUserID("https://idp.example.com", "alice")}
	if got := id.GroupLookupID(); got != "alice" {
		t.Fatalf("GroupLookupID() = %q, want the subject alice", got)
	}
}
