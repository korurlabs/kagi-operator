package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// kagi-init authenticates through the token exchange for exactly the pair of
// the pod's annotations, then reads that pair's secrets with the minted token.
func TestKagiInitExchangesForTheAnnotationsPair(t *testing.T) {
	tokenPath := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenPath, []byte("pod-sa-jwt"), 0o600); err != nil {
		t.Fatalf("failed to write token fixture: %v", err)
	}

	var resources []string
	var subjectToken, fetchAuth, fetchPath string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/kagi/auth/token" {
			if err := r.ParseForm(); err != nil {
				t.Errorf("failed to parse exchange form: %v", err)
			}
			resources = r.PostForm["resource"]
			subjectToken = r.PostForm.Get("subject_token")
			_, _ = w.Write([]byte(`{"access_token":"vv_pod","expires_in":900,` +
				`"issued_token_type":"urn:ietf:params:oauth:token-type:access_token","token_type":"Bearer",` +
				`"scope":"secrets:app-1/staging","granted_by":{"role_id":"r","role_name":"n"}}`))
			return
		}
		fetchPath = r.URL.Path
		fetchAuth = r.Header.Get("Authorization")
		_, _ = w.Write([]byte(`{"secrets":{"DB_URL":"postgres://x"}}`))
	}))
	defer ts.Close()

	cfg := &config{
		appID:          "app-1",
		environment:    "staging",
		apiURL:         ts.URL,
		saTokenPath:    tokenPath,
		startupTimeout: time.Second,
	}
	secrets, err := fetchWithRetry(context.Background(), cfg, newKagiClient(cfg), t.Logf)
	if err != nil {
		t.Fatalf("fetchWithRetry returned error: %v", err)
	}
	if secrets["DB_URL"] != "postgres://x" {
		t.Errorf("secrets = %v, want DB_URL", secrets)
	}
	wantResource := ts.URL + "/kagi/apps/app-1/environments/staging"
	if len(resources) != 1 || resources[0] != wantResource {
		t.Errorf("resource = %v, want exactly [%s]", resources, wantResource)
	}
	if subjectToken != "pod-sa-jwt" {
		t.Errorf("subject_token = %q, want the projected token", subjectToken)
	}
	if fetchPath != "/kagi/apps/app-1/environments/staging/secrets/fetch" || fetchAuth != "Bearer vv_pod" {
		t.Errorf("fetch = %s with %q, want the pair's fetch route with the minted token", fetchPath, fetchAuth)
	}
}
