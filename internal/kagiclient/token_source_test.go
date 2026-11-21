package kagiclient

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// writeTempToken writes a projected-SA-token fixture and returns its path.
func writeTempToken(t *testing.T, contents string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "token")
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("failed to write temp token: %v", err)
	}
	return path
}

// fakeExchange is a token exchange that records every form it receives and
// answers per resource: a resource listed in denied gets 401, every other one a
// token named after its call count.
type fakeExchange struct {
	t         *testing.T
	expiresIn int32
	denied    map[string]bool

	mu    sync.Mutex
	forms []url.Values
}

func (f *fakeExchange) handler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != tokenExchangePath || r.Method != http.MethodPost {
		f.t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		http.NotFound(w, r)
		return
	}
	if ct := r.Header.Get("Content-Type"); ct != "application/x-www-form-urlencoded" {
		f.t.Errorf("Content-Type = %q, want application/x-www-form-urlencoded", ct)
	}
	if err := r.ParseForm(); err != nil {
		f.t.Errorf("failed to parse exchange form: %v", err)
	}
	f.mu.Lock()
	f.forms = append(f.forms, r.PostForm)
	call := len(f.forms)
	denied := f.denied[r.PostForm.Get("resource")]
	f.mu.Unlock()

	if denied {
		w.Header().Set("Content-Type", "application/problem+json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"type":"urn:kagi:error:KGI_AUT_003","title":"Unauthorized",` +
			`"status":401,"code":"KGI_AUT_003","detail":"exchange refused"}`))
		return
	}
	resp := TokenExchangeResponse{
		AccessToken:     "vv_workload_" + strconv.Itoa(call),
		ExpiresIn:       f.expiresIn,
		IssuedTokenType: TokenExchangeIssuedTokenTypeUrnIetfParamsOauthTokenTypeAccessToken,
		TokenType:       TokenExchangeTokenTypeBearer,
		Scope:           "secrets:x/y",
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func (f *fakeExchange) calls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.forms)
}

func newFakeExchange(t *testing.T, expiresIn int32) (*fakeExchange, *httptest.Server) {
	t.Helper()
	f := &fakeExchange{t: t, expiresIn: expiresIn, denied: map[string]bool{}}
	ts := httptest.NewServer(http.HandlerFunc(f.handler))
	t.Cleanup(ts.Close)
	return f, ts
}

func TestStaticTokenSource(t *testing.T) {
	src := NewStaticTokenSource("vv_static")
	got, err := src.Token(context.Background(), TokenScope{AppID: "a", EnvironmentSlug: "e"})
	if err != nil {
		t.Fatalf("StaticTokenSource.Token returned error: %v", err)
	}
	if got != "vv_static" {
		t.Errorf("unexpected token: got %q, want vv_static", got)
	}
}

// The exchange is an RFC 8693 form with exactly one resource for the pair, on
// the API host the client talks to.
func TestWorkloadTokenSourcePostsTheFormForOnePair(t *testing.T) {
	tokenPath := writeTempToken(t, "sa-jwt-abc\n")
	f, ts := newFakeExchange(t, 3600)

	src := NewWorkloadTokenSource(ts.URL+"/", WithServiceAccountTokenPath(tokenPath))
	got, err := src.TokenFor(context.Background(), "3f2a9c4e-8b1d-4e7a-9f6c-2d5b8a1e0c47", "production")
	if err != nil {
		t.Fatalf("TokenFor returned error: %v", err)
	}
	if got != "vv_workload_1" {
		t.Errorf("token = %q, want vv_workload_1", got)
	}

	form := f.forms[0]
	want := map[string]string{
		"grant_type":         "urn:ietf:params:oauth:grant-type:token-exchange",
		"subject_token":      "sa-jwt-abc",
		"subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
	}
	for key, value := range want {
		if got := form.Get(key); got != value {
			t.Errorf("%s = %q, want %q", key, got, value)
		}
	}
	wantResource := ts.URL + "/kagi/apps/3f2a9c4e-8b1d-4e7a-9f6c-2d5b8a1e0c47/environments/production"
	if resources := form["resource"]; len(resources) != 1 || resources[0] != wantResource {
		t.Errorf("resource = %v, want exactly [%s]", resources, wantResource)
	}
	for _, refused := range []string{"audience", "scope", "requested_token_ttl"} {
		if form.Has(refused) {
			t.Errorf("form carries %s, which the client must not send", refused)
		}
	}
}

// Each pair has its own cached token; a second call for a pair reuses it.
func TestWorkloadTokenSourceCachesOneTokenPerPair(t *testing.T) {
	tokenPath := writeTempToken(t, "sa-jwt")
	f, ts := newFakeExchange(t, 3600)
	src := NewWorkloadTokenSource(ts.URL, WithServiceAccountTokenPath(tokenPath))
	ctx := context.Background()

	first, err := src.TokenFor(ctx, "app-a", "prod")
	if err != nil {
		t.Fatalf("TokenFor(app-a) returned error: %v", err)
	}
	second, err := src.TokenFor(ctx, "app-b", "prod")
	if err != nil {
		t.Fatalf("TokenFor(app-b) returned error: %v", err)
	}
	again, err := src.TokenFor(ctx, "app-a", "prod")
	if err != nil {
		t.Fatalf("TokenFor(app-a) again returned error: %v", err)
	}
	if first == second {
		t.Errorf("two pairs share token %q", first)
	}
	if again != first {
		t.Errorf("cached token = %q, want %q", again, first)
	}
	if f.calls() != 2 {
		t.Errorf("exchange calls = %d, want 2 (one per pair)", f.calls())
	}
}

// A token is re-exchanged before it expires, with the leeway, not after.
func TestWorkloadTokenSourceRefreshesBeforeExpiry(t *testing.T) {
	tokenPath := writeTempToken(t, "sa-jwt")
	f, ts := newFakeExchange(t, 300)
	src := NewWorkloadTokenSource(ts.URL, WithServiceAccountTokenPath(tokenPath))
	now := time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)
	src.now = func() time.Time { return now }
	ctx := context.Background()

	if _, err := src.TokenFor(ctx, "app-a", "prod"); err != nil {
		t.Fatalf("TokenFor returned error: %v", err)
	}
	now = now.Add(239 * time.Second)
	if _, err := src.TokenFor(ctx, "app-a", "prod"); err != nil {
		t.Fatalf("TokenFor returned error: %v", err)
	}
	if f.calls() != 1 {
		t.Fatalf("exchange calls = %d before the leeway, want 1", f.calls())
	}
	now = now.Add(time.Second)
	if _, err := src.TokenFor(ctx, "app-a", "prod"); err != nil {
		t.Fatalf("TokenFor returned error: %v", err)
	}
	if f.calls() != 2 {
		t.Errorf("exchange calls = %d at expiry minus leeway, want 2", f.calls())
	}
}

// A short-lived token refreshes at half its lifetime rather than on every call.
func TestWorkloadTokenSourceShortTokenRefreshesAtHalfLife(t *testing.T) {
	tokenPath := writeTempToken(t, "sa-jwt")
	f, ts := newFakeExchange(t, 60)
	src := NewWorkloadTokenSource(ts.URL, WithServiceAccountTokenPath(tokenPath))
	now := time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)
	src.now = func() time.Time { return now }
	ctx := context.Background()

	for range 2 {
		if _, err := src.TokenFor(ctx, "app-a", "prod"); err != nil {
			t.Fatalf("TokenFor returned error: %v", err)
		}
		now = now.Add(29 * time.Second)
	}
	if f.calls() != 1 {
		t.Errorf("exchange calls = %d within half the lifetime, want 1", f.calls())
	}
}

// A refused pair surfaces a 401 as an access denial and leaves the other
// pairs' cached tokens in place.
func TestWorkloadTokenSourceDenialIsPerPair(t *testing.T) {
	tokenPath := writeTempToken(t, "sa-jwt")
	f, ts := newFakeExchange(t, 3600)
	f.denied[ts.URL+"/kagi/apps/app-b/environments/prod"] = true

	src := NewWorkloadTokenSource(ts.URL, WithServiceAccountTokenPath(tokenPath))
	ctx := context.Background()

	allowed, err := src.TokenFor(ctx, "app-a", "prod")
	if err != nil {
		t.Fatalf("TokenFor(app-a) returned error: %v", err)
	}
	_, err = src.TokenFor(ctx, "app-b", "prod")
	if !IsWorkloadAccessDenied(err) {
		t.Fatalf("err = %v, want an access denial", err)
	}
	var exchangeErr *ExchangeError
	if !errors.As(err, &exchangeErr) || exchangeErr.Scope != (TokenScope{AppID: "app-b", EnvironmentSlug: "prod"}) {
		t.Errorf("err = %v, want an *ExchangeError naming app-b/prod", err)
	}
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Code != "KGI_AUT_003" {
		t.Errorf("err = %v, want it to wrap the KGI_AUT_003 problem", err)
	}

	callsBefore := f.calls()
	again, err := src.TokenFor(ctx, "app-a", "prod")
	if err != nil || again != allowed {
		t.Errorf("TokenFor(app-a) after the denial = %q, %v; want the cached %q", again, err, allowed)
	}
	if f.calls() != callsBefore {
		t.Errorf("the denial evicted app-a: exchange calls went from %d to %d", callsBefore, f.calls())
	}
}

// A request that names no pair cannot be authenticated by the exchange.
func TestWorkloadTokenSourceRefusesAZeroScope(t *testing.T) {
	src := NewWorkloadTokenSource("http://unused", WithServiceAccountTokenPath("/does/not/exist"))
	for _, scope := range []TokenScope{{}, {AppID: "app-a"}, {EnvironmentSlug: "prod"}} {
		if _, err := src.Token(context.Background(), scope); !errors.Is(err, ErrTokenScopeRequired) {
			t.Errorf("Token(%+v) err = %v, want ErrTokenScopeRequired", scope, err)
		}
	}
}

func TestWorkloadTokenSourceMissingFile(t *testing.T) {
	src := NewWorkloadTokenSource("http://unused", WithServiceAccountTokenPath("/does/not/exist/token"))
	_, err := src.TokenFor(context.Background(), "app-a", "prod")
	if err == nil {
		t.Fatal("expected error for missing SA token file, got nil")
	}
	if !IsExchangeError(err) || IsWorkloadAccessDenied(err) {
		t.Errorf("err = %v, want an exchange error that is not a denial", err)
	}
}

// An exchange that answers 200 with no payload, no access token or no lifetime
// must fail: caching an empty token would send unauthenticated requests.
func TestWorkloadTokenSourceEmptyExchange(t *testing.T) {
	bodies := []string{"", "null", "{}",
		`{"access_token":"","expires_in":3600}`,
		`{"access_token":"vv_x","expires_in":0}`}
	for _, body := range bodies {
		t.Run(body, func(t *testing.T) {
			tokenPath := writeTempToken(t, "sa-jwt")
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(body))
			}))
			defer ts.Close()

			src := NewWorkloadTokenSource(ts.URL, WithServiceAccountTokenPath(tokenPath))
			if token, err := src.TokenFor(context.Background(), "app-a", "prod"); err == nil {
				t.Fatalf("TokenFor = %q and no error for exchange body %q", token, body)
			}
		})
	}
}

// A client built with a WorkloadTokenSource authenticates the secret fetch with
// the pair's token, and refuses calls that name no pair before any request.
func TestClientWithWorkloadTokenSource(t *testing.T) {
	tokenPath := writeTempToken(t, "sa-jwt")

	var gotAuth, gotResource string
	var apiCalls int
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == tokenExchangePath {
			if err := r.ParseForm(); err != nil {
				t.Errorf("failed to parse exchange form: %v", err)
			}
			gotResource = r.PostForm.Get("resource")
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"access_token":"vv_workload_xyz","expires_in":3600,` +
				`"issued_token_type":"urn:ietf:params:oauth:token-type:access_token","token_type":"Bearer",` +
				`"scope":"secrets:app-1/prod","granted_by":{"role_id":"r","role_name":"n"}}`))
			return
		}
		apiCalls++
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"secrets":{"K":"V"}}`))
	}))
	defer ts.Close()

	client := NewClient(ts.URL, "ignored-static-token",
		WithTokenSource(NewWorkloadTokenSource(ts.URL, WithServiceAccountTokenPath(tokenPath))))

	if _, err := client.FetchSecrets(context.Background(), "app-1", "prod"); err != nil {
		t.Fatalf("FetchSecrets returned error: %v", err)
	}
	if gotAuth != "Bearer vv_workload_xyz" {
		t.Errorf("Authorization = %q, want Bearer vv_workload_xyz", gotAuth)
	}
	if !strings.HasSuffix(gotResource, "/kagi/apps/app-1/environments/prod") {
		t.Errorf("resource = %q, want the app-1/prod pair", gotResource)
	}

	if _, err := client.ResolveApp(context.Background(), "/team/app"); !errors.Is(err, ErrTokenScopeRequired) {
		t.Errorf("ResolveApp err = %v, want ErrTokenScopeRequired", err)
	}
	if apiCalls != 1 {
		t.Errorf("API calls = %d, want 1 (ResolveApp must not reach the API)", apiCalls)
	}
}
