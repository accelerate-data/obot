package safehttp

// Fork-only guarantee (VD-4887, restored by VD-6903): credential-carrying
// clients never follow a redirect. Kept in its own file so an upstream sync
// cannot drop these tests by merging over a shared one.

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestNoRedirectsRefusesRedirectWithoutContactingTarget(t *testing.T) {
	var targetHits atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		targetHits.Add(1)
	}))
	defer target.Close()
	origin := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		http.Redirect(rw, req, target.URL+"/token", http.StatusTemporaryRedirect)
	}))
	defer origin.Close()

	resp, err := NoRedirects(&http.Client{}).Post(origin.URL, "application/x-www-form-urlencoded", strings.NewReader("code=secret"))
	if err == nil {
		_ = resp.Body.Close()
		t.Fatal("redirected request succeeded, want refusal")
	}
	if !strings.Contains(err.Error(), "refusing to follow redirect") {
		t.Fatalf("error = %v, want redirect refusal", err)
	}
	if strings.Contains(err.Error(), "secret") {
		t.Fatalf("error %q leaks request body", err)
	}
	if got := targetHits.Load(); got != 0 {
		t.Fatalf("redirect target hits = %d, want 0", got)
	}
}

func TestNoRedirectsClonesSourceClient(t *testing.T) {
	source := &http.Client{}

	clone := NoRedirects(source)

	if clone == source {
		t.Fatal("NoRedirects returned the source client, want a copy")
	}
	if source.CheckRedirect != nil {
		t.Fatal("NoRedirects mutated the source client's redirect policy")
	}
	if clone.CheckRedirect == nil {
		t.Fatal("clone has no redirect policy")
	}
	if NoRedirects(nil) != nil {
		t.Fatal("NoRedirects(nil) returned a client, want nil")
	}
}
