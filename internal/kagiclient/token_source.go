package kagiclient

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// DefaultServiceAccountTokenPath is the conventional in-pod path of a projected
// Kubernetes ServiceAccount token. A WorkloadTokenSource reads the SA JWT from
// here unless WithServiceAccountTokenPath overrides it.
const DefaultServiceAccountTokenPath = "/var/run/secrets/kagi/token"

// tokenExchangePath is the RFC 8693 token exchange of the Kagi API. It trades
// a platform token for a short-lived Kagi WORKLOAD token that reads only the
// (app, environment) pairs named by its resource parameters.
const tokenExchangePath = "/kagi/auth/token"

// The RFC 8693 parameter values this client sends. The API accepts others
// (id_token, machine assertions), but a projected ServiceAccount token is a
// plain JWT.
const (
	grantTypeTokenExchange = "urn:ietf:params:oauth:grant-type:token-exchange"
	subjectTokenTypeJWT    = "urn:ietf:params:oauth:token-type:jwt"
)

// defaultTokenRefreshLeeway is how long before a cached token's expiry a
// WorkloadTokenSource proactively re-exchanges, so requests never race a hard
// expiry.
const defaultTokenRefreshLeeway = 60 * time.Second

// ErrTokenScopeRequired is returned by a WorkloadTokenSource asked for a token
// without an (app, environment) pair. A workload token reads only the pairs it
// was exchanged for, so calls that are not about one pair (resolving a folder
// path, reading a certificate) cannot be authenticated by the exchange.
var ErrTokenScopeRequired = errors.New(
	"kagi: the workload token exchange grants (app, environment) pairs only; this call names none")

// TokenScope is the (app, environment) pair a request reads. The zero value
// means the request is not about one pair.
type TokenScope struct {
	AppID           string
	EnvironmentSlug string
}

// TokenSource obtains a bearer token used to authenticate Kagi API requests. It
// is consulted once per request with the pair that request reads, so an
// implementation may return a rotating, short-lived token per pair rather than
// a fixed string. Implementations MUST be safe for concurrent use.
type TokenSource interface {
	// Token returns the current bearer token for scope, refreshing it if
	// necessary. It returns a non-nil error if a token cannot be obtained;
	// callers must not send a request with an empty token.
	Token(ctx context.Context, scope TokenScope) (string, error)
}

// StaticTokenSource is a TokenSource that always returns the same fixed bearer
// token (typically a long-lived vv_... PAT), whatever the scope. It is the
// default token source.
type StaticTokenSource struct {
	token string
}

// NewStaticTokenSource wraps a fixed bearer token as a TokenSource.
func NewStaticTokenSource(token string) *StaticTokenSource {
	return &StaticTokenSource{token: token}
}

// Token returns the fixed token. It never fails.
func (s *StaticTokenSource) Token(context.Context, TokenScope) (string, error) {
	return s.token, nil
}

// WorkloadOption configures a WorkloadTokenSource at construction.
type WorkloadOption func(*WorkloadTokenSource)

// WithServiceAccountTokenPath overrides the file path the projected Kubernetes
// ServiceAccount JWT is read from (default DefaultServiceAccountTokenPath).
func WithServiceAccountTokenPath(path string) WorkloadOption {
	return func(s *WorkloadTokenSource) {
		if path != "" {
			s.tokenPath = path
		}
	}
}

// WithExchangeHTTPClient overrides the HTTP client used for the token exchange
// call. A nil client is ignored so the default is preserved.
func WithExchangeHTTPClient(hc *http.Client) WorkloadOption {
	return func(s *WorkloadTokenSource) {
		if hc != nil {
			s.httpClient = hc
		}
	}
}

// ExchangeError is a failed token exchange for one (app, environment) pair. It
// wraps the cause, which is an *APIError when the API answered.
type ExchangeError struct {
	Scope TokenScope
	Err   error
}

// Error implements the error interface.
func (e *ExchangeError) Error() string {
	return fmt.Sprintf("kagi: token exchange for app %s environment %s failed: %v",
		e.Scope.AppID, e.Scope.EnvironmentSlug, e.Err)
}

// Unwrap returns the cause.
func (e *ExchangeError) Unwrap() error {
	return e.Err
}

// IsWorkloadAccessDenied reports whether err is an exchange the API refused
// with 401: no workload role of the organization trusts this identity for the
// requested pair. The API records the refusal as a denial the admin sees in
// the portal.
func IsWorkloadAccessDenied(err error) bool {
	var exchangeErr *ExchangeError
	if !errors.As(err, &exchangeErr) {
		return false
	}
	var apiErr *APIError
	return errors.As(exchangeErr.Err, &apiErr) && apiErr.StatusCode == http.StatusUnauthorized
}

// IsExchangeError reports whether err is a failed token exchange of any kind
// (an unreadable token file, a network failure, a refusal).
func IsExchangeError(err error) bool {
	var exchangeErr *ExchangeError
	return errors.As(err, &exchangeErr)
}

// WorkloadTokenSource exchanges this workload's projected Kubernetes
// ServiceAccount JWT at the Kagi token exchange for a short-lived WORKLOAD
// token, one per (app, environment) pair. Each pair's token is cached and
// re-exchanged shortly before it expires; pairs refresh independently, so a
// refused pair never evicts or blocks the others. It is safe for concurrent
// use.
type WorkloadTokenSource struct {
	baseURL    string
	tokenPath  string
	httpClient *http.Client
	leeway     time.Duration
	now        func() time.Time

	mu      sync.Mutex
	entries map[TokenScope]*workloadTokenEntry
}

// workloadTokenEntry is the cached token of one pair. Its own lock serializes
// the exchanges of that pair only.
type workloadTokenEntry struct {
	mu        sync.Mutex
	token     string
	refreshAt time.Time
}

// NewWorkloadTokenSource creates a WorkloadTokenSource that exchanges projected
// ServiceAccount JWTs against baseURL (the root URL of the Kagi API, which is
// also the host of every resource URI it sends).
func NewWorkloadTokenSource(baseURL string, opts ...WorkloadOption) *WorkloadTokenSource {
	s := &WorkloadTokenSource{
		baseURL:   strings.TrimRight(baseURL, "/"),
		tokenPath: DefaultServiceAccountTokenPath,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		leeway:  defaultTokenRefreshLeeway,
		now:     time.Now,
		entries: make(map[TokenScope]*workloadTokenEntry),
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// Token returns a valid token for scope. A scope without both an app id and an
// environment is refused with ErrTokenScopeRequired.
func (s *WorkloadTokenSource) Token(ctx context.Context, scope TokenScope) (string, error) {
	if scope.AppID == "" || scope.EnvironmentSlug == "" {
		return "", ErrTokenScopeRequired
	}
	return s.TokenFor(ctx, scope.AppID, scope.EnvironmentSlug)
}

// TokenFor returns a valid token for the pair, exchanging the ServiceAccount
// JWT when there is no cached token or the cached one is due for refresh. A
// failure is an *ExchangeError.
func (s *WorkloadTokenSource) TokenFor(ctx context.Context, appID, environmentSlug string) (string, error) {
	scope := TokenScope{AppID: appID, EnvironmentSlug: environmentSlug}
	entry := s.entry(scope)

	entry.mu.Lock()
	defer entry.mu.Unlock()

	if entry.token != "" && s.now().Before(entry.refreshAt) {
		return entry.token, nil
	}

	exchanged, err := s.exchange(ctx, scope)
	if err != nil {
		return "", &ExchangeError{Scope: scope, Err: err}
	}

	lifetime := time.Duration(exchanged.ExpiresIn) * time.Second
	// A token shorter than twice the leeway would be stale on arrival, so it
	// refreshes at half its lifetime instead.
	leeway := min(s.leeway, lifetime/2)
	entry.token = exchanged.AccessToken
	entry.refreshAt = s.now().Add(lifetime - leeway)
	return entry.token, nil
}

// entry returns the cache entry of scope, creating it on first use.
func (s *WorkloadTokenSource) entry(scope TokenScope) *workloadTokenEntry {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.entries[scope]
	if !ok {
		entry = &workloadTokenEntry{}
		s.entries[scope] = entry
	}
	return entry
}

// exchange reads the projected ServiceAccount JWT and posts the RFC 8693 form
// for one pair.
func (s *WorkloadTokenSource) exchange(ctx context.Context, scope TokenScope) (*TokenExchangeResponse, error) {
	rawJWT, err := os.ReadFile(s.tokenPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read service account token at %s: %w", s.tokenPath, err)
	}
	saJWT := strings.TrimSpace(string(rawJWT))
	if saJWT == "" {
		return nil, fmt.Errorf("service account token at %s is empty", s.tokenPath)
	}

	form := TokenExchangeForm{
		GrantType:        grantTypeTokenExchange,
		SubjectToken:     saJWT,
		SubjectTokenType: subjectTokenTypeJWT,
		Resource:         []string{s.resourceURI(scope)},
	}
	values := url.Values{
		"grant_type":         {form.GrantType},
		"subject_token":      {form.SubjectToken},
		"subject_token_type": {form.SubjectTokenType},
		"resource":           form.Resource,
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.baseURL+tokenExchangePath,
		strings.NewReader(values.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create token exchange request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", acceptHeader)

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("token exchange request failed: %w", err)
	}
	// The body is fully consumed by decodeResponse; a close error cannot change the result.
	defer func() { _ = resp.Body.Close() }()

	var exchanged TokenExchangeResponse
	if err := decodeResponse(resp, &exchanged); err != nil {
		return nil, err
	}
	if exchanged.AccessToken == "" {
		return nil, errors.New("token exchange response contained no access token")
	}
	if exchanged.ExpiresIn <= 0 {
		return nil, fmt.Errorf("token exchange response carried expires_in %d", exchanged.ExpiresIn)
	}
	return &exchanged, nil
}

// resourceURI is the RFC 8693 resource of one pair: the prefix of the fetch
// route the token will call, on the API host the exchange checks it against.
func (s *WorkloadTokenSource) resourceURI(scope TokenScope) string {
	return s.baseURL + "/kagi/apps/" + url.PathEscape(scope.AppID) +
		"/environments/" + url.PathEscape(scope.EnvironmentSlug)
}
