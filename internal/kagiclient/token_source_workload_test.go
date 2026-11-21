package kagiclient

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// The cache key is the whole pair: two environments of one app are two
// tokens, each exchanged for its own resource.
func TestWorkloadTokenSourceKeysTheCacheByEnvironmentToo(t *testing.T) {
	tokenPath := writeTempToken(t, "sa-jwt")
	f, ts := newFakeExchange(t, 3600)
	src := NewWorkloadTokenSource(ts.URL, WithServiceAccountTokenPath(tokenPath))
	ctx := context.Background()

	production, err := src.TokenFor(ctx, "app-a", "production")
	if err != nil {
		t.Fatalf("TokenFor(production) returned error: %v", err)
	}
	staging, err := src.TokenFor(ctx, "app-a", "staging")
	if err != nil {
		t.Fatalf("TokenFor(staging) returned error: %v", err)
	}
	if production == staging {
		t.Errorf("two environments of one app share token %q", production)
	}
	if f.calls() != 2 {
		t.Fatalf("exchange calls = %d, want 2 (one per environment)", f.calls())
	}
	wantResources := []string{
		ts.URL + "/kagi/apps/app-a/environments/production",
		ts.URL + "/kagi/apps/app-a/environments/staging",
	}
	for i, want := range wantResources {
		if got := f.forms[i]["resource"]; len(got) != 1 || got[0] != want {
			t.Errorf("exchange %d resource = %v, want exactly [%s]", i+1, got, want)
		}
	}
}

// Concurrent reconciles of one pair share a single exchange instead of each
// minting a token.
func TestWorkloadTokenSourceConcurrentCallersOfOnePairExchangeOnce(t *testing.T) {
	tokenPath := writeTempToken(t, "sa-jwt")
	f, ts := newFakeExchange(t, 3600)
	src := NewWorkloadTokenSource(ts.URL, WithServiceAccountTokenPath(tokenPath))

	const callers = 16
	tokens := make([]string, callers)
	errs := make([]error, callers)
	var wg sync.WaitGroup
	for i := range callers {
		wg.Go(func() {
			tokens[i], errs[i] = src.TokenFor(context.Background(), "app-a", "prod")
		})
	}
	wg.Wait()

	for i := range callers {
		if errs[i] != nil {
			t.Fatalf("caller %d returned error: %v", i, errs[i])
		}
		if tokens[i] != tokens[0] {
			t.Errorf("caller %d got %q, want the shared %q", i, tokens[i], tokens[0])
		}
	}
	if f.calls() != 1 {
		t.Errorf("exchange calls = %d, want 1 for one pair", f.calls())
	}
}

// The kubelet rotates the projected token file, so every exchange reads it
// again rather than reusing the JWT of the first one.
func TestWorkloadTokenSourceRereadsTheProjectedTokenOnRefresh(t *testing.T) {
	tokenPath := writeTempToken(t, "sa-jwt-first\n")
	f, ts := newFakeExchange(t, 300)
	src := NewWorkloadTokenSource(ts.URL, WithServiceAccountTokenPath(tokenPath))
	now := time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)
	src.now = func() time.Time { return now }
	ctx := context.Background()

	if _, err := src.TokenFor(ctx, "app-a", "prod"); err != nil {
		t.Fatalf("TokenFor returned error: %v", err)
	}
	if err := os.WriteFile(tokenPath, []byte("sa-jwt-rotated\n"), 0o600); err != nil {
		t.Fatalf("failed to rotate token fixture: %v", err)
	}
	now = now.Add(5 * time.Minute)
	if _, err := src.TokenFor(ctx, "app-a", "prod"); err != nil {
		t.Fatalf("TokenFor after rotation returned error: %v", err)
	}

	if f.calls() != 2 {
		t.Fatalf("exchange calls = %d, want 2", f.calls())
	}
	if got := f.forms[1].Get("subject_token"); got != "sa-jwt-rotated" {
		t.Errorf("second exchange subject_token = %q, want the rotated JWT", got)
	}
}

// A failed refresh never serves the expired token, and the next call
// exchanges again instead of remembering the failure.
func TestWorkloadTokenSourceFailedRefreshServesNoStaleToken(t *testing.T) {
	tokenPath := writeTempToken(t, "sa-jwt")
	var refuse bool
	var mu sync.Mutex
	var calls int
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		calls++
		failing := refuse
		mu.Unlock()
		if failing {
			w.Header().Set("Content-Type", "application/problem+json")
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"type":"about:blank","title":"Unavailable","status":503,"detail":"down"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"vv_fresh","expires_in":300}`))
	}))
	defer ts.Close()

	src := NewWorkloadTokenSource(ts.URL, WithServiceAccountTokenPath(tokenPath))
	now := time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)
	src.now = func() time.Time { return now }
	ctx := context.Background()

	if _, err := src.TokenFor(ctx, "app-a", "prod"); err != nil {
		t.Fatalf("TokenFor returned error: %v", err)
	}
	mu.Lock()
	refuse = true
	mu.Unlock()
	now = now.Add(5 * time.Minute)

	token, err := src.TokenFor(ctx, "app-a", "prod")
	if err == nil || token != "" {
		t.Fatalf("TokenFor during the outage = %q, %v; want no token and an error", token, err)
	}
	if !IsExchangeError(err) || IsWorkloadAccessDenied(err) {
		t.Errorf("err = %v, want an exchange error that is not a denial", err)
	}

	mu.Lock()
	refuse = false
	mu.Unlock()
	if token, err := src.TokenFor(ctx, "app-a", "prod"); err != nil || token != "vv_fresh" {
		t.Errorf("TokenFor after the outage = %q, %v; want a fresh token", token, err)
	}
	mu.Lock()
	defer mu.Unlock()
	if calls != 3 {
		t.Errorf("exchange calls = %d, want 3 (the failure is not cached)", calls)
	}
}

// Only a 401 means no workload role grants the pair; any other refusal is an
// exchange failure the reconciler reports as TokenResolutionFailed.
func TestIsWorkloadAccessDeniedOnlyFor401(t *testing.T) {
	scope := TokenScope{AppID: "app-a", EnvironmentSlug: "prod"}
	cases := []struct {
		name       string
		err        error
		denied     bool
		isExchange bool
	}{
		{"401 inside an exchange error", &ExchangeError{Scope: scope, Err: &APIError{StatusCode: 401}}, true, true},
		{"wrapped again", errors.Join(errors.New("ctx"), &ExchangeError{Scope: scope, Err: &APIError{StatusCode: 401}}), true, true},
		{"403 inside an exchange error", &ExchangeError{Scope: scope, Err: &APIError{StatusCode: 403}}, false, true},
		{"429 inside an exchange error", &ExchangeError{Scope: scope, Err: &APIError{StatusCode: 429}}, false, true},
		{"network failure", &ExchangeError{Scope: scope, Err: errors.New("dial tcp: refused")}, false, true},
		{"401 of an API call, not the exchange", &APIError{StatusCode: 401}, false, false},
		{"nil", nil, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsWorkloadAccessDenied(tc.err); got != tc.denied {
				t.Errorf("IsWorkloadAccessDenied = %v, want %v", got, tc.denied)
			}
			if got := IsExchangeError(tc.err); got != tc.isExchange {
				t.Errorf("IsExchangeError = %v, want %v", got, tc.isExchange)
			}
		})
	}
}

// The error names the pair, so a status message tells the admin which grant
// is missing.
func TestExchangeErrorNamesThePair(t *testing.T) {
	err := &ExchangeError{Scope: TokenScope{AppID: "app-a", EnvironmentSlug: "prod"}, Err: errors.New("boom")}
	for _, want := range []string{"app-a", "prod", "boom"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("Error() = %q, want it to contain %q", err.Error(), want)
		}
	}
}

// The version probe authenticates with the same pair's cached token as the
// fetch: one exchange serves both calls of a reconcile.
func TestClientVersionProbeAndFetchShareThePairToken(t *testing.T) {
	tokenPath := writeTempToken(t, "sa-jwt")
	f, exchange := newFakeExchange(t, 3600)

	var mu sync.Mutex
	auths := map[string]string{}
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == tokenExchangePath {
			f.handler(w, r)
			return
		}
		mu.Lock()
		auths[r.URL.Path] = r.Header.Get("Authorization")
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if strings.HasSuffix(r.URL.Path, "/secrets/version") {
			_, _ = w.Write([]byte(`{"version":"v7","count":1}`))
			return
		}
		_, _ = w.Write([]byte(`{"secrets":{"K":"V"}}`))
	}))
	defer api.Close()
	exchange.Close()

	client := NewClient(api.URL, "",
		WithTokenSource(NewWorkloadTokenSource(api.URL, WithServiceAccountTokenPath(tokenPath))))
	ctx := context.Background()

	version, err := client.GetSecretsVersion(ctx, "app-1", "prod")
	if err != nil || version != "v7" {
		t.Fatalf("GetSecretsVersion = %q, %v; want v7", version, err)
	}
	if _, err := client.FetchSecrets(ctx, "app-1", "prod"); err != nil {
		t.Fatalf("FetchSecrets returned error: %v", err)
	}

	if f.calls() != 1 {
		t.Errorf("exchange calls = %d, want 1 shared by the probe and the fetch", f.calls())
	}
	if got := f.forms[0].Get("resource"); got != api.URL+"/kagi/apps/app-1/environments/prod" {
		t.Errorf("resource = %q, want the app-1/prod pair", got)
	}
	for _, path := range []string{
		"/kagi/apps/app-1/environments/prod/secrets/version",
		"/kagi/apps/app-1/environments/prod/secrets/fetch",
	} {
		if auths[path] != "Bearer vv_workload_1" {
			t.Errorf("%s carried %q, want the pair's workload token", path, auths[path])
		}
	}
}

// Calls that name no pair (listing a folder, reading a certificate) are
// refused before any request, so no unauthenticated call reaches the API.
func TestClientRefusesUnscopedCallsUnderTheExchange(t *testing.T) {
	var calls int
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer api.Close()

	client := NewClient(api.URL, "",
		WithTokenSource(NewWorkloadTokenSource(api.URL, WithServiceAccountTokenPath("/does/not/exist"))))
	ctx := context.Background()

	checks := map[string]func() error{
		"FetchCertificateByID": func() error { _, err := client.FetchCertificateByID(ctx, "cert-1"); return err },
		"ResolveCertificate":   func() error { _, err := client.ResolveCertificate(ctx, "/tls/web"); return err },
		"ListEnvironments":     func() error { _, err := client.ListEnvironments(ctx, "app-1"); return err },
		"ListApps":             func() error { _, err := client.ListApps(ctx, "/team"); return err },
	}
	for name, call := range checks {
		if err := call(); !errors.Is(err, ErrTokenScopeRequired) {
			t.Errorf("%s err = %v, want ErrTokenScopeRequired", name, err)
		}
	}
	if calls != 0 {
		t.Errorf("API calls = %d, want none", calls)
	}
}

// roundTripFunc adapts a function to http.RoundTripper.
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// WithExchangeHTTPClient routes the exchange through the given client, and a
// nil client keeps the default.
func TestWorkloadTokenSourceUsesTheGivenHTTPClient(t *testing.T) {
	tokenPath := writeTempToken(t, "sa-jwt")
	_, ts := newFakeExchange(t, 3600)
	var through atomic.Int32
	hc := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		through.Add(1)
		return http.DefaultTransport.RoundTrip(r)
	})}

	src := NewWorkloadTokenSource(ts.URL, WithServiceAccountTokenPath(tokenPath), WithExchangeHTTPClient(hc))
	if _, err := src.TokenFor(context.Background(), "app-a", "prod"); err != nil {
		t.Fatalf("TokenFor returned error: %v", err)
	}
	if through.Load() != 1 {
		t.Errorf("requests through the given client = %d, want 1", through.Load())
	}

	defaulted := NewWorkloadTokenSource(ts.URL, WithExchangeHTTPClient(nil))
	if defaulted.httpClient == nil {
		t.Error("a nil client replaced the default HTTP client")
	}
}
