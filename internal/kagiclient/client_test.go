package kagiclient

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

// newTestServer answers GET wantPath with payload as the JSON body, the way the
// Kagi API answers a successful read: the payload itself, no envelope.
func newTestServer(t *testing.T, wantPath string, payload any) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != wantPath {
			t.Errorf("unexpected path: got %s, want %s", r.URL.Path, wantPath)
			http.NotFound(w, r)
			return
		}
		if r.Method != http.MethodGet {
			t.Errorf("unexpected method: got %s, want GET", r.Method)
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if got := r.Header.Get("Authorization"); got != "Bearer test-token" {
			t.Errorf("unexpected Authorization header: got %q", got)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(payload); err != nil {
			t.Errorf("encode payload: %v", err)
		}
	}))
}

func TestListFolderChildren(t *testing.T) {
	children := FolderChildren{
		Path: "/fepatex",
		Folders: []Folder{
			{ID: "f1", Name: "Backend", Slug: "backend", Path: "/fepatex/backend"},
		},
		Apps: []App{
			{ID: "a1", Name: "API", Slug: "api"},
		},
	}
	ts := newTestServer(t, "/kagi/folders/secrets/children/fepatex", children)
	defer ts.Close()

	client := NewClient(ts.URL, "test-token")
	result, err := client.ListFolderChildren(context.Background(), LibrarySecrets, "/fepatex")
	if err != nil {
		t.Fatalf("ListFolderChildren returned error: %v", err)
	}
	if len(result.Folders) != 1 || result.Folders[0].Slug != "backend" {
		t.Errorf("unexpected folders: %+v", result.Folders)
	}
	if len(result.Apps) != 1 || result.Apps[0].ID != "a1" {
		t.Errorf("unexpected apps: %+v", result.Apps)
	}
}

func TestListFolderChildrenRoot(t *testing.T) {
	children := FolderChildren{Path: "/", Folders: []Folder{}, Apps: []App{}}
	// Empty path must browse the root: no trailing segment after "children".
	ts := newTestServer(t, "/kagi/folders/secrets/children", children)
	defer ts.Close()

	client := NewClient(ts.URL, "test-token")
	if _, err := client.ListFolderChildren(context.Background(), LibrarySecrets, ""); err != nil {
		t.Fatalf("ListFolderChildren(root) returned error: %v", err)
	}
}

func TestResolveApp(t *testing.T) {
	children := FolderChildren{
		Path: "/fepatex/backend",
		Apps: []App{
			{ID: "app-123", Name: "API", Slug: "api"},
			{ID: "app-456", Name: "Worker", Slug: "worker"},
		},
	}
	// ResolveApp browses the PARENT folder (/fepatex/backend) of the app slug "api".
	ts := newTestServer(t, "/kagi/folders/secrets/children/fepatex/backend", children)
	defer ts.Close()

	client := NewClient(ts.URL, "test-token")
	appID, err := client.ResolveApp(context.Background(), "/fepatex/backend/api")
	if err != nil {
		t.Fatalf("ResolveApp returned error: %v", err)
	}
	if appID != "app-123" {
		t.Errorf("unexpected app ID: got %q, want app-123", appID)
	}
}

func TestResolveAppNotFound(t *testing.T) {
	children := FolderChildren{Path: "/fepatex/backend", Apps: []App{{ID: "app-123", Slug: "api"}}}
	ts := newTestServer(t, "/kagi/folders/secrets/children/fepatex/backend", children)
	defer ts.Close()

	client := NewClient(ts.URL, "test-token")
	if _, err := client.ResolveApp(context.Background(), "/fepatex/backend/missing"); err == nil {
		t.Fatal("expected error for missing app slug, got nil")
	}
}

func TestResolveAppEmptyPath(t *testing.T) {
	client := NewClient("http://unused", "test-token")
	if _, err := client.ResolveApp(context.Background(), "/"); err == nil {
		t.Fatal("expected error for empty folder path, got nil")
	}
}

func TestListApps(t *testing.T) {
	children := FolderChildren{
		Path: "/fepatex/backend",
		Apps: []App{
			{ID: "a1", Name: "App One", Slug: "app-one"},
			{ID: "a2", Name: "App Two", Slug: "app-two"},
		},
	}
	ts := newTestServer(t, "/kagi/folders/secrets/children/fepatex/backend", children)
	defer ts.Close()

	client := NewClient(ts.URL, "test-token")
	result, err := client.ListApps(context.Background(), "/fepatex/backend")
	if err != nil {
		t.Fatalf("ListApps returned error: %v", err)
	}
	if len(result) != 2 {
		t.Fatalf("expected 2 apps, got %d", len(result))
	}
	if result[0].Slug != "app-one" {
		t.Errorf("unexpected first app slug: %s", result[0].Slug)
	}
}

func TestListEnvironments(t *testing.T) {
	envs := []Environment{
		{ID: "e1", Name: "Production", Slug: "production"},
		{ID: "e2", Name: "Staging", Slug: "staging"},
	}
	ts := newTestServer(t, "/kagi/apps/app-123/environments", envs)
	defer ts.Close()

	client := NewClient(ts.URL, "test-token")
	result, err := client.ListEnvironments(context.Background(), "app-123")
	if err != nil {
		t.Fatalf("ListEnvironments returned error: %v", err)
	}
	if len(result) != 2 {
		t.Fatalf("expected 2 environments, got %d", len(result))
	}
	if result[0].Name != "Production" {
		t.Errorf("unexpected first environment: %+v", result[0])
	}
}

func TestFetchSecrets(t *testing.T) {
	secretData := SecretFetchResponse{
		Secrets: map[string]string{
			"DB_HOST":     "localhost",
			"DB_PASSWORD": "secret123",
		},
	}
	ts := newTestServer(t, "/kagi/apps/app-1/environments/production/secrets/fetch", secretData)
	defer ts.Close()

	client := NewClient(ts.URL, "test-token")
	result, err := client.FetchSecrets(context.Background(), "app-1", "production")
	if err != nil {
		t.Fatalf("FetchSecrets returned error: %v", err)
	}
	if len(result) != 2 {
		t.Fatalf("expected 2 secrets, got %d", len(result))
	}
	if result["DB_HOST"] != "localhost" {
		t.Errorf("unexpected DB_HOST: %s", result["DB_HOST"])
	}
	if result["DB_PASSWORD"] != "secret123" {
		t.Errorf("unexpected DB_PASSWORD: %s", result["DB_PASSWORD"])
	}
}

func TestGetSecretsVersion(t *testing.T) {
	versionData := SecretVersionResponse{
		Version: "v-abc123",
		Count:   7,
	}
	ts := newTestServer(t, "/kagi/apps/app-1/environments/production/secrets/version", versionData)
	defer ts.Close()

	client := NewClient(ts.URL, "test-token")
	version, err := client.GetSecretsVersion(context.Background(), "app-1", "production")
	if err != nil {
		t.Fatalf("GetSecretsVersion returned error: %v", err)
	}
	if version != "v-abc123" {
		t.Errorf("unexpected version: got %q, want v-abc123", version)
	}
}

// TestGetSecretsVersionOlderBackend asserts that a backend without the version
// route (404) surfaces an error, so the caller can fall back to always fetch.
func TestGetSecretsVersionOlderBackend(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/problem+json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"type":"urn:kagi:error:GEN_NOT_001","title":"Resource not found.","status":404,"code":"GEN_NOT_001"}`))
	}))
	defer ts.Close()

	client := NewClient(ts.URL, "test-token")
	if _, err := client.GetSecretsVersion(context.Background(), "app-1", "production"); err == nil {
		t.Fatal("expected error for missing version route, got nil")
	}
}

// TestWithOrganizationSendsHeader asserts that a client constructed with
// WithOrganization sends the org UUID as X-Organization-ID on its requests.
func TestWithOrganizationSendsHeader(t *testing.T) {
	const orgID = "00000000-0000-0000-0000-000000000001"
	var gotOrg string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotOrg = r.Header.Get("X-Organization-ID")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode([]Environment{})
	}))
	defer ts.Close()

	client := NewClient(ts.URL, "test-token", WithOrganization(orgID))
	if _, err := client.ListEnvironments(context.Background(), "app-1"); err != nil {
		t.Fatalf("ListEnvironments returned error: %v", err)
	}
	if gotOrg != orgID {
		t.Errorf("expected X-Organization-ID %q, got %q", orgID, gotOrg)
	}
}

// TestWithoutOrganizationOmitsHeader asserts that the default client (no
// WithOrganization) sends NO X-Organization-ID header, preserving pre-multi-org
// behavior byte-for-byte.
func TestWithoutOrganizationOmitsHeader(t *testing.T) {
	var hadHeader bool
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, hadHeader = r.Header["X-Organization-Id"]
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode([]Environment{})
	}))
	defer ts.Close()

	client := NewClient(ts.URL, "test-token")
	if _, err := client.ListEnvironments(context.Background(), "app-1"); err != nil {
		t.Fatalf("ListEnvironments returned error: %v", err)
	}
	if hadHeader {
		t.Error("expected no X-Organization-ID header when org is unset")
	}
}

// forbiddenCode and forbiddenProblem are the Problem Details answer to a request
// the caller may not make, with no detail member.
const (
	forbiddenCode    = "GEN_SEC_002"
	forbiddenProblem = `{"type":"urn:kagi:error:GEN_SEC_002","title":"Access forbidden.","status":403,"code":"GEN_SEC_002"}`
)

// problemServer answers every request with status and a Problem Details body.
func problemServer(t *testing.T, status int, body string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/problem+json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
}

func TestErrorHandling_ProblemDetails(t *testing.T) {
	ts := problemServer(t, http.StatusPaymentRequired, `{
		"type": "urn:kagi:error:KGI_SEC_005",
		"title": "Organization billing is locked.",
		"status": 402,
		"detail": "The organization's trial has ended.",
		"instance": "/kagi/apps/app-1/environments",
		"code": "KGI_SEC_005"
	}`)
	defer ts.Close()

	client := NewClient(ts.URL, "test-token")
	_, err := client.ListEnvironments(context.Background(), "app-1")

	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("err = %v, want an *APIError", err)
	}
	if apiErr.StatusCode != http.StatusPaymentRequired {
		t.Errorf("StatusCode = %d, want 402", apiErr.StatusCode)
	}
	if apiErr.Code != "KGI_SEC_005" {
		t.Errorf("Code = %q, want KGI_SEC_005", apiErr.Code)
	}
	if apiErr.Message != "The organization's trial has ended." {
		t.Errorf("Message = %q, want the problem's detail", apiErr.Message)
	}
	if want := "kagi: API returned status 402 (KGI_SEC_005): The organization's trial has ended."; err.Error() != want {
		t.Errorf("Error() = %q, want %q", err.Error(), want)
	}
}

// A problem without detail falls back to the catalogue title, so the message
// never reads emptier than the code warrants.
func TestErrorHandling_ProblemWithoutDetailUsesTitle(t *testing.T) {
	ts := problemServer(t, http.StatusForbidden, forbiddenProblem)
	defer ts.Close()

	client := NewClient(ts.URL, "test-token")
	_, err := client.ListEnvironments(context.Background(), "app-1")

	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("err = %v, want an *APIError", err)
	}
	if apiErr.Code != forbiddenCode || apiErr.Message != "Access forbidden." {
		t.Errorf("Code, Message = %q, %q; want GEN_SEC_002, Access forbidden.", apiErr.Code, apiErr.Message)
	}
}

// A non-Problem body (a proxy's HTML page) still yields an *APIError with the
// status, an empty Code and the raw body for diagnosis.
func TestErrorHandling_NonProblemBody(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte("<html>bad gateway</html>"))
	}))
	defer ts.Close()

	client := NewClient(ts.URL, "test-token")
	_, err := client.ListEnvironments(context.Background(), "app-1")

	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("err = %v, want an *APIError", err)
	}
	if apiErr.StatusCode != http.StatusBadGateway || apiErr.Code != "" || apiErr.Body != "<html>bad gateway</html>" {
		t.Errorf("APIError = %+v, want status 502, no code, the raw body", apiErr)
	}
}

// FetchSecrets feeds the managed Secret and kagi-init's environment, so every
// failed or malformed answer must be an error, never an empty map that the
// caller would write out as "this environment has no secrets".
func TestFetchSecrets_NeverAnEmptyMapOnFailure(t *testing.T) {
	cases := []struct {
		name        string
		status      int
		contentType string
		body        string
		wantAPIErr  bool
		wantCode    string
	}{
		{
			name:        "Problem Details 403",
			status:      http.StatusForbidden,
			contentType: "application/problem+json",
			body:        forbiddenProblem,
			wantAPIErr:  true,
			wantCode:    forbiddenCode,
		},
		{
			name:        "Problem Details 404",
			status:      http.StatusNotFound,
			contentType: "application/problem+json",
			body:        `{"type":"urn:kagi:error:GEN_NOT_001","title":"Resource not found.","status":404,"code":"GEN_NOT_001","detail":"No environment production."}`,
			wantAPIErr:  true,
			wantCode:    "GEN_NOT_001",
		},
		{name: "empty body on a 500", status: http.StatusInternalServerError, wantAPIErr: true},
		{name: "empty body on a 200", status: http.StatusOK, contentType: "application/json"},
		{name: "empty body on a 204", status: http.StatusNoContent},
		{name: "null body on a 200", status: http.StatusOK, contentType: "application/json", body: "null"},
		{name: "object without secrets on a 200", status: http.StatusOK, contentType: "application/json", body: "{}"},
		{name: "null secrets on a 200", status: http.StatusOK, contentType: "application/json", body: `{"secrets":null}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tc.contentType != "" {
					w.Header().Set("Content-Type", tc.contentType)
				}
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer ts.Close()

			client := NewClient(ts.URL, "test-token")
			secrets, err := client.FetchSecrets(context.Background(), "app-1", "production")
			if err == nil {
				t.Fatalf("FetchSecrets returned %v and no error", secrets)
			}
			if secrets != nil {
				t.Errorf("FetchSecrets returned map %v alongside the error, want nil", secrets)
			}

			var apiErr *APIError
			isAPIErr := errors.As(err, &apiErr)
			if isAPIErr != tc.wantAPIErr {
				t.Fatalf("errors.As(*APIError) = %v, want %v (err: %v)", isAPIErr, tc.wantAPIErr, err)
			}
			if isAPIErr && apiErr.Code != tc.wantCode {
				t.Errorf("Code = %q, want %q", apiErr.Code, tc.wantCode)
			}
		})
	}
}

// An environment that really has no secrets answers an empty object, which is
// an empty, non-nil map and no error.
func TestFetchSecrets_EmptyEnvironment(t *testing.T) {
	ts := newTestServer(t, "/kagi/apps/app-1/environments/production/secrets/fetch",
		SecretFetchResponse{Secrets: map[string]string{}})
	defer ts.Close()

	client := NewClient(ts.URL, "test-token")
	secrets, err := client.FetchSecrets(context.Background(), "app-1", "production")
	if err != nil {
		t.Fatalf("FetchSecrets returned error: %v", err)
	}
	if secrets == nil || len(secrets) != 0 {
		t.Errorf("FetchSecrets = %#v, want an empty non-nil map", secrets)
	}
}

func TestFetchCertificateByID(t *testing.T) {
	key := "-----BEGIN PRIVATE KEY-----"
	ts := newTestServer(t, "/kagi/certificates/by-id/cert-1/tls",
		CertificateEntry{Name: "acme-tls", TLSCrt: "-----BEGIN CERTIFICATE-----", TLSKey: &key})
	defer ts.Close()

	client := NewClient(ts.URL, "test-token")
	entry, err := client.FetchCertificateByID(context.Background(), "cert-1")
	if err != nil {
		t.Fatalf("FetchCertificateByID returned error: %v", err)
	}
	if entry.Name != "acme-tls" || entry.TLSKey == nil || *entry.TLSKey != key {
		t.Errorf("unexpected entry: %+v", entry)
	}
}

func TestResolveCertificate(t *testing.T) {
	ts := newTestServer(t, "/kagi/folders/certificates/resolve/team-tls/acme-tls",
		CertificateResolveResponse{CertificateID: "cert-1", Name: "acme-tls"})
	defer ts.Close()

	client := NewClient(ts.URL, "test-token")
	id, err := client.ResolveCertificate(context.Background(), "/team-tls/acme-tls")
	if err != nil {
		t.Fatalf("ResolveCertificate returned error: %v", err)
	}
	if id != "cert-1" {
		t.Errorf("ResolveCertificate = %q, want cert-1", id)
	}
}

func TestErrorHandling_NetworkError(t *testing.T) {
	// Use a server that's already closed to simulate network error.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	ts.Close()

	client := NewClient(ts.URL, "test-token")
	_, err := client.ListEnvironments(context.Background(), "app-1")
	if err == nil {
		t.Fatal("expected error for closed server, got nil")
	}
}

func TestErrorHandling_CancelledContext(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode([]Environment{})
	}))
	defer ts.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	client := NewClient(ts.URL, "test-token")
	_, err := client.ListEnvironments(ctx, "app-1")
	if err == nil {
		t.Fatal("expected error for cancelled context, got nil")
	}
}

func TestFolderChildrenPath(t *testing.T) {
	cases := []struct {
		library LibrarySlug
		path    string
		want    string
	}{
		{LibrarySecrets, "", "/kagi/folders/secrets/children"},
		{LibrarySecrets, "/", "/kagi/folders/secrets/children"},
		{LibrarySecrets, "/fepatex", "/kagi/folders/secrets/children/fepatex"},
		{LibrarySecrets, "fepatex/backend", "/kagi/folders/secrets/children/fepatex/backend"},
		{LibrarySecrets, "/fepatex/backend/", "/kagi/folders/secrets/children/fepatex/backend"},
		{LibraryPasswords, "/team", "/kagi/folders/passwords/children/team"},
	}
	for _, tc := range cases {
		if got := folderChildrenPath(tc.library, tc.path); got != tc.want {
			t.Errorf("folderChildrenPath(%q, %q) = %q, want %q", tc.library, tc.path, got, tc.want)
		}
	}
}

// ValidateOrganizationID guards the X-Organization-ID cross-check at the point a
// caller supplies it, because the Kagi API's answer to a malformed value is
// either a permanent 403 on every request or (under tenancy enforcement
// OFF/SHADOW) a silent fallback to the token's own organization -- neither of
// which names the typo that caused it.
func TestValidateOrganizationID(t *testing.T) {
	cases := []struct {
		name           string
		organizationID string
		wantErr        bool
	}{
		// The empty string is how both the CRD and kagi-init spell "no
		// cross-check"; it must stay valid or every existing install breaks.
		{"empty means no cross-check", "", false},
		{"canonical lowercase", "3f2504e0-4f89-11d3-9a0c-0305e82c3301", false},
		{"canonical uppercase", "3F2504E0-4F89-11D3-9A0C-0305E82C3301", false},
		{"an organization slug is not a UUID", "acme", true},
		{"a Java-lenient short UUID is refused", "1-1-1-1-1", true},
		{"braced form is refused", "{3f2504e0-4f89-11d3-9a0c-0305e82c3301}", true},
		{"unhyphenated form is refused", "3f2504e04f8911d39a0c0305e82c3301", true},
		{"trailing whitespace is refused", "3f2504e0-4f89-11d3-9a0c-0305e82c3301 ", true},
		{"a header-splitting value is refused", "3f2504e0-4f89-11d3-9a0c-0305e82c3301\r\nX: y", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateOrganizationID(tc.organizationID)
			if tc.wantErr && err == nil {
				t.Fatalf("ValidateOrganizationID(%q) = nil, want an error", tc.organizationID)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("ValidateOrganizationID(%q) = %v, want nil", tc.organizationID, err)
			}
		})
	}
}
