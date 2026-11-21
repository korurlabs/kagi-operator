package main

import (
	"context"
	"flag"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	kagi "github.com/korurlabs/kagi-operator/internal/kagiclient"
)

// exchangeAPI is a Kagi API with the token exchange: it records each exchange
// form and each API path with its bearer token. A denied resource gets 401.
type exchangeAPI struct {
	denied string

	mu        sync.Mutex
	resources [][]string
	apiCalls  map[string]string
}

func newExchangeAPI(t *testing.T) (*exchangeAPI, *httptest.Server) {
	t.Helper()
	api := &exchangeAPI{apiCalls: map[string]string{}}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		api.mu.Lock()
		defer api.mu.Unlock()
		if r.URL.Path == "/kagi/auth/token" {
			if err := r.ParseForm(); err != nil {
				t.Errorf("failed to parse exchange form: %v", err)
			}
			api.resources = append(api.resources, r.PostForm["resource"])
			if api.denied != "" && r.PostForm.Get("resource") == api.denied {
				w.Header().Set("Content-Type", "application/problem+json")
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"type":"urn:kagi:error:KGI_AUT_003","title":"Unauthorized",` +
					`"status":401,"code":"KGI_AUT_003","detail":"no workload role grants this identity"}`))
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"access_token":"vv_pod","expires_in":900,` +
				`"issued_token_type":"urn:ietf:params:oauth:token-type:access_token","token_type":"Bearer",` +
				`"scope":"secrets:x/y","granted_by":{"role_id":"r","role_name":"n"}}`))
			return
		}
		api.apiCalls[r.URL.Path] = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		if strings.HasSuffix(r.URL.Path, "/secrets/version") {
			_, _ = w.Write([]byte(`{"version":"v1","count":1}`))
			return
		}
		_, _ = w.Write([]byte(`{"secrets":{"DB_URL":"postgres://x"}}`))
	}))
	t.Cleanup(ts.Close)
	return api, ts
}

func writeProjectedToken(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(path, []byte("pod-sa-jwt"), 0o600); err != nil {
		t.Fatalf("failed to write token fixture: %v", err)
	}
	return path
}

// The webhook passes the pod's kagi.pw/app-id and kagi.pw/environment
// annotations as flags and the API URL and token path as env; kagi-init
// exchanges for exactly that pair, and the flags win over a stray env pair.
func TestKagiInitExchangesForThePairTheWebhookPasses(t *testing.T) {
	api, ts := newExchangeAPI(t)
	t.Setenv("KAGI_API_URL", ts.URL)
	t.Setenv("KAGI_SA_TOKEN_PATH", writeProjectedToken(t))
	t.Setenv("KAGI_APP_ID", "app-from-env")
	t.Setenv("KAGI_ENVIRONMENT", "env-from-env")

	flagArgs, cmdArgs, hasSep := splitArgs([]string{
		"--app-id=3f2504e0-4f89-11d3-9a0c-0305e82c3301", "--environment=production", "--", "/app/server",
	})
	if !hasSep || len(cmdArgs) != 1 {
		t.Fatalf("splitArgs = %v, %v, %v", flagArgs, cmdArgs, hasSep)
	}
	fs := flag.NewFlagSet("kagi-init", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	cfg, err := parseConfig(fs, flagArgs)
	if err != nil {
		t.Fatalf("parseConfig returned error: %v", err)
	}
	if err := cfg.validate(); err != nil {
		t.Fatalf("validate returned error: %v", err)
	}

	if _, err := fetchWithRetry(context.Background(), cfg, newKagiClient(cfg), t.Logf); err != nil {
		t.Fatalf("fetchWithRetry returned error: %v", err)
	}

	wantResource := ts.URL + "/kagi/apps/3f2504e0-4f89-11d3-9a0c-0305e82c3301/environments/production"
	if len(api.resources) != 1 || len(api.resources[0]) != 1 || api.resources[0][0] != wantResource {
		t.Errorf("exchange resources = %v, want exactly [[%s]]", api.resources, wantResource)
	}
}

// The version watch probes the same pair with the token the fetch already
// holds: one exchange serves both.
func TestKagiInitVersionProbeReusesThePairToken(t *testing.T) {
	api, ts := newExchangeAPI(t)
	cfg := &config{appID: "app-1", environment: "staging", apiURL: ts.URL, saTokenPath: writeProjectedToken(t)}
	client := newKagiClient(cfg)

	if _, err := fetchWithRetry(context.Background(), cfg, client, t.Logf); err != nil {
		t.Fatalf("fetchWithRetry returned error: %v", err)
	}
	if _, err := client.GetSecretsVersion(context.Background(), cfg.appID, cfg.environment); err != nil {
		t.Fatalf("GetSecretsVersion returned error: %v", err)
	}

	if len(api.resources) != 1 {
		t.Errorf("exchanges = %d, want 1 shared by the fetch and the probe", len(api.resources))
	}
	if got := api.apiCalls["/kagi/apps/app-1/environments/staging/secrets/version"]; got != "Bearer vv_pod" {
		t.Errorf("version probe carried %q, want the pair's token", got)
	}
}

// A refused exchange ends the start-up with an error that is still the
// denial, so the pod crash-loops with the reason, and no secret is fetched.
func TestKagiInitDeniedExchangeFailsWithoutFetching(t *testing.T) {
	api, ts := newExchangeAPI(t)
	api.denied = ts.URL + "/kagi/apps/app-1/environments/staging"
	cfg := &config{appID: "app-1", environment: "staging", apiURL: ts.URL, saTokenPath: writeProjectedToken(t)}

	var logged []string
	logf := func(format string, args ...any) { logged = append(logged, format) }
	_, err := fetchWithRetry(context.Background(), cfg, newKagiClient(cfg), logf)
	if err == nil {
		t.Fatal("fetchWithRetry returned no error for a denied exchange")
	}
	if !kagi.IsWorkloadAccessDenied(err) {
		t.Errorf("err = %v, want it to wrap the access denial", err)
	}
	if !strings.Contains(err.Error(), "app-1") || !strings.Contains(err.Error(), "staging") {
		t.Errorf("err = %q, want it to name the pair", err.Error())
	}
	if len(api.apiCalls) != 0 {
		t.Errorf("API calls = %v, want none after the denial", api.apiCalls)
	}
	if len(logged) == 0 {
		t.Error("the failed attempt was not logged")
	}
}
