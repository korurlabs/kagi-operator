package kagiclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// headerOrganizationID is the HTTP header used to cross-check the organization a
// request is scoped to. The Kagi API derives the org from the PAT; when this
// header is also present it MUST equal the token's bound org or the API rejects
// the request with 403. It is therefore a safety cross-check, never the primary
// source of org context.
const headerOrganizationID = "X-Organization-ID"

// acceptHeader names both media types the API answers with: the JSON payload on
// success and Problem Details on an error.
const acceptHeader = "application/json, application/problem+json"

// organizationIDPattern is the canonical UUID form the X-Organization-ID header
// must carry. It is the same expression the KagiSecret and KagiCertificate CRDs
// enforce at admission (+kubebuilder:validation:Pattern on spec.organization);
// keep the two in step.
//
// It exists because a non-UUID value can never be a Kagi organization id -- the
// API parses the header with UUID.fromString -- and the failure is invisible at
// the point of the mistake: under tenancy enforcement STRICT the cross-check
// fails 403 on every single request forever, and under OFF/SHADOW the mismatch
// is logged server-side and the request proceeds on the token's org, so the
// cross-check the caller asked for is silently not performed.
var organizationIDPattern = regexp.MustCompile(
	`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// ValidateOrganizationID reports whether organizationID is usable as the
// X-Organization-ID cross-check. The empty string is valid and means "no
// cross-check; use the organization the token is bound to". Any other value must
// be a canonical UUID.
//
// This is deliberately STRICTER than the server, and the difference is not a bug
// to be "fixed". The Kagi API parses the header with UUID.fromString(raw.trim())
// (OrganizationContextFilter.parseOrgId), and Java's parser is lenient: it trims
// surrounding whitespace and accepts the abbreviated group form, so "1-1-1-1-1"
// is read as 00000001-0001-0001-0001-000000000001. Nothing in Kagi ever renders
// an organization id that way -- the portal, the CLI and the API all emit the
// canonical 36-character form -- so a value in any other shape is a typo, and
// accepting it would send a silently different organization than the one the
// author wrote. Refusing it names the value instead.
//
// Callers that take an organization id from configuration (kagi-init's
// --organization/KAGI_ORGANIZATION_ID) and from a CR spec (KagiSecret and
// KagiCertificate spec.organization) validate with this before constructing a
// Client, so a typo fails loudly -- at startup, or in the CR's Ready condition --
// instead of degrading into a permanent 403 loop or a cross-check that quietly
// never happens.
func ValidateOrganizationID(organizationID string) error {
	if organizationID == "" || organizationIDPattern.MatchString(organizationID) {
		return nil
	}
	return fmt.Errorf("kagi: organization %q is not a canonical UUID; "+
		"it is sent as the %s cross-check and must be the organization's UUID",
		organizationID, headerOrganizationID)
}

// Client is a read-only HTTP client for the Kagi secrets management API.
type Client struct {
	baseURL        string
	tokenSource    TokenSource
	organizationID string
	httpClient     *http.Client
}

// APIError is returned by client calls when the Kagi API answers with a non-2xx
// status. The API answers every error with RFC 9457 Problem Details
// (application/problem+json); Code and Message are its code and detail
// members. StatusCode lets callers branch on the status -- for example the
// KagiCertificate operator distinguishing a 404 (no certificate with that id)
// from other failures.
//
// A body that is not a Problem Details document -- a proxy's HTML error page,
// an empty body -- leaves Code empty, and Body carries the raw text so the
// failure stays diagnosable.
type APIError struct {
	StatusCode int
	Code       string
	Message    string
	Body       string
}

// Error implements the error interface.
func (e *APIError) Error() string {
	switch {
	case e.Code != "" && e.Message != "":
		return fmt.Sprintf("kagi: API returned status %d (%s): %s", e.StatusCode, e.Code, e.Message)
	case e.Code != "":
		return fmt.Sprintf("kagi: API returned status %d (%s)", e.StatusCode, e.Code)
	case e.Body != "":
		return fmt.Sprintf("kagi: API returned status %d: %s", e.StatusCode, e.Body)
	default:
		return fmt.Sprintf("kagi: API returned status %d with an empty body", e.StatusCode)
	}
}

// newAPIError builds the error for a non-2xx answer from its body. The
// catalogue title stands in for detail when the backend sent no detail, so the
// message is never emptier than the code warrants.
func newAPIError(statusCode int, body []byte) *APIError {
	apiErr := &APIError{StatusCode: statusCode, Body: string(body)}

	var problem KagiProblem
	if err := json.Unmarshal(body, &problem); err != nil || problem.Code == "" {
		return apiErr
	}
	apiErr.Code = problem.Code
	apiErr.Message = problem.Title
	if problem.Detail != nil && *problem.Detail != "" {
		apiErr.Message = *problem.Detail
	}
	return apiErr
}

// decodeResponse reads resp, turns a non-2xx status into an *APIError, and
// unmarshals a 2xx body into result. Every operation this client calls answers
// 200 with a JSON payload, so an empty or null body on a 2xx is an error: decoding
// it would hand the caller a zero value -- an empty secret map, an empty token --
// that looks like a real answer.
func decodeResponse(resp *http.Response, result any) error {
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("kagi: failed to read response body: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return newAPIError(resp.StatusCode, body)
	}

	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return fmt.Errorf("kagi: API returned status %d with no payload", resp.StatusCode)
	}

	if err := json.Unmarshal(trimmed, result); err != nil {
		return fmt.Errorf("kagi: failed to parse response: %w", err)
	}
	return nil
}

// Option configures a Client at construction time.
type Option func(*Client)

// WithOrganization sets the organization UUID sent as the X-Organization-ID
// cross-check header. When organizationID is empty the header is omitted and the
// client behaves identically to one constructed without this option (the org is
// taken from the PAT server-side).
func WithOrganization(organizationID string) Option {
	return func(c *Client) {
		c.organizationID = organizationID
	}
}

// WithTokenSource replaces the client's default static-PAT token source with a
// custom one -- for example a WorkloadTokenSource that exchanges a projected
// Kubernetes ServiceAccount JWT for short-lived Kagi access tokens per
// (app, environment) pair.
// When set, the token passed to NewClient is ignored. A nil source is ignored,
// so the static-token default is preserved.
func WithTokenSource(ts TokenSource) Option {
	return func(c *Client) {
		if ts != nil {
			c.tokenSource = ts
		}
	}
}

// NewClient creates a new Kagi SDK client.
//
// baseURL is the root URL of the Kagi API (e.g. "https://api.example.com").
// token is a static Bearer token (typically a vv_... PAT) used for
// authentication; it is wrapped in a StaticTokenSource, so the existing
// constructor keeps working unchanged. Pass WithTokenSource to authenticate via
// a rotating source instead. Optional Options (e.g. WithOrganization) tune
// additional request behavior.
func NewClient(baseURL, token string, opts ...Option) *Client {
	c := &Client{
		baseURL:     baseURL,
		tokenSource: NewStaticTokenSource(token),
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// ListFolderChildren browses a folder by path and returns its child folders
// and, for the SECRETS library, the apps directly under it. The path is the
// human-readable folder path (e.g. "/fepatex/backend"); an empty or "/" path
// browses the library root. It hits
// GET /kagi/folders/{library}/children/{*path}.
func (c *Client) ListFolderChildren(ctx context.Context, library LibrarySlug, path string) (*FolderChildren, error) {
	var children FolderChildren
	if err := c.doGet(ctx, TokenScope{}, folderChildrenPath(library, path), &children); err != nil {
		return nil, err
	}
	return &children, nil
}

// ResolveApp resolves a human-entered SECRETS folder path to an app's stable
// internal ID. The final path segment is the app slug; the preceding segments
// identify the folder the app lives in. The returned app ID is the durable
// machine binding and should be captured once at setup, then used to address
// secrets thereafter (it is stable across app renames and folder moves).
func (c *Client) ResolveApp(ctx context.Context, folderPath string) (string, error) {
	trimmed := strings.Trim(folderPath, "/")
	if trimmed == "" {
		return "", fmt.Errorf("kagi: folder path %q does not address an app", folderPath)
	}

	segments := strings.Split(trimmed, "/")
	appSlug := segments[len(segments)-1]
	parentPath := "/" + strings.Join(segments[:len(segments)-1], "/")

	children, err := c.ListFolderChildren(ctx, LibrarySecrets, parentPath)
	if err != nil {
		return "", err
	}

	for _, app := range children.Apps {
		if app.Slug == appSlug {
			return app.ID, nil
		}
	}

	return "", fmt.Errorf("kagi: no app with slug %q under folder %q", appSlug, parentPath)
}

// ListApps returns the apps directly under a SECRETS folder path.
func (c *Client) ListApps(ctx context.Context, folderPath string) ([]App, error) {
	children, err := c.ListFolderChildren(ctx, LibrarySecrets, folderPath)
	if err != nil {
		return nil, err
	}
	return children.Apps, nil
}

// ListEnvironments returns all environments for an app, addressed by its stable
// app ID. It hits GET /kagi/apps/{appId}/environments.
func (c *Client) ListEnvironments(ctx context.Context, appID string) ([]Environment, error) {
	var environments []Environment
	if err := c.doGet(ctx, TokenScope{}, fmt.Sprintf("/kagi/apps/%s/environments", appID), &environments); err != nil {
		return nil, err
	}
	return environments, nil
}

// FetchSecrets returns decrypted secrets as key-value pairs for an app's
// environment, addressed by the stable app ID and the environment slug. It hits
// GET /kagi/apps/{appId}/environments/{environmentSlug}/secrets/fetch (the
// plaintext machine-fetch variant).
//
// An environment with no secrets answers {"secrets": {}} and yields an empty,
// non-nil map. A payload without the secrets member is refused: the managed
// Secret and kagi-init's environment are written from this map, and treating a
// malformed answer as "no secrets" would wipe them.
func (c *Client) FetchSecrets(ctx context.Context, appID, environmentSlug string) (map[string]string, error) {
	var resp SecretFetchResponse
	if err := c.doGet(ctx, TokenScope{AppID: appID, EnvironmentSlug: environmentSlug},
		fmt.Sprintf("/kagi/apps/%s/environments/%s/secrets/fetch", appID, environmentSlug), &resp); err != nil {
		return nil, err
	}
	if resp.Secrets == nil {
		return nil, fmt.Errorf("kagi: secret fetch response for app %s environment %s carried no secrets member", appID, environmentSlug)
	}
	return resp.Secrets, nil
}

// GetSecretsVersion returns the opaque version token for an app environment's
// secrets, addressed by the stable app ID and the environment slug. It hits
// GET /kagi/apps/{appId}/environments/{environmentSlug}/secrets/version -- a
// cheap, decrypt-free probe used to decide whether a full FetchSecrets is
// needed. The returned string is opaque: compare it for equality against a
// previously observed version, never parse or order it. An older backend that
// does not expose this route returns a non-2xx status, surfaced here as an
// error so callers can fall back to always fetching.
func (c *Client) GetSecretsVersion(ctx context.Context, appID, environmentSlug string) (string, error) {
	var resp SecretVersionResponse
	if err := c.doGet(ctx, TokenScope{AppID: appID, EnvironmentSlug: environmentSlug},
		fmt.Sprintf("/kagi/apps/%s/environments/%s/secrets/version", appID, environmentSlug), &resp); err != nil {
		return "", err
	}
	return resp.Version, nil
}

// folderChildrenPath builds the folder-children browse URL. The Kagi route uses
// a terminal capturing wildcard (/kagi/folders/{library}/children/{*path}), so
// the path is appended last with a single leading slash; an empty/"/" path
// browses the root (no trailing segment).
func folderChildrenPath(library LibrarySlug, path string) string {
	return "/kagi/folders/" + string(library) + "/children" + normalizeFolderPath(path)
}

// normalizeFolderPath collapses a folder path to the canonical wildcard suffix:
// "" for the root, or "/seg1/seg2" otherwise. Folder slugs are [a-z0-9-] only,
// so no URL escaping is required.
func normalizeFolderPath(path string) string {
	trimmed := strings.Trim(path, "/")
	if trimmed == "" {
		return ""
	}
	return "/" + trimmed
}

// doGet performs an authenticated GET request and decodes the JSON payload into
// result. scope is the (app, environment) pair the request reads, zero when it
// reads none; the token source decides whether it can authenticate that. A
// non-2xx answer is returned as an *APIError.
func (c *Client) doGet(ctx context.Context, scope TokenScope, path string, result any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return fmt.Errorf("kagi: failed to create request: %w", err)
	}

	token, err := c.tokenSource.Token(ctx, scope)
	if err != nil {
		return fmt.Errorf("kagi: failed to obtain auth token: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", acceptHeader)
	if c.organizationID != "" {
		req.Header.Set(headerOrganizationID, c.organizationID)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("kagi: request failed: %w", err)
	}
	// The body is fully consumed by decodeResponse; a close error cannot change the result.
	defer func() { _ = resp.Body.Close() }()

	return decodeResponse(resp, result)
}
