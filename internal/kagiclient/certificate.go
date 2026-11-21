package kagiclient

import (
	"context"
	"fmt"
	"strings"
)

// FetchCertificateByID fetches TLS content for a certificate addressed by its
// stable UUID id -- the durable machine binding, analogous to the app ID used
// for secrets. The id is stable across certificate renames and folder moves, so
// reconciliation never depends on the certificate's current slug or location. It
// hits GET /kagi/certificates/by-id/{certificateId}/tls.
func (c *Client) FetchCertificateByID(ctx context.Context, certificateID string) (*CertificateEntry, error) {
	var entry CertificateEntry
	path := fmt.Sprintf("/kagi/certificates/by-id/%s/tls", certificateID)
	if err := c.doGet(ctx, TokenScope{}, path, &entry); err != nil {
		return nil, err
	}
	return &entry, nil
}

// ResolveCertificate resolves a human-entered certificate node path to a
// certificate's stable id. The path is the full certificate node path: the final
// segment is the certificate slug and the preceding segments identify the folder
// the certificate lives in (e.g. "/team-tls/acme-tls" is slug "acme-tls" in
// folder "/team-tls"; "/acme-tls" is slug "acme-tls" at the certificates root).
// The returned certificate id is the durable machine binding and should be
// captured once at setup, then used with FetchCertificateByID thereafter (it is
// stable across certificate renames and folder moves). This mirrors ResolveApp
// for secrets. It hits GET /kagi/folders/certificates/resolve/{*path}.
func (c *Client) ResolveCertificate(ctx context.Context, path string) (string, error) {
	trimmed := strings.Trim(path, "/")
	if trimmed == "" {
		return "", fmt.Errorf("kagi: certificate path %q does not address a certificate", path)
	}

	var resp CertificateResolveResponse
	// The resolve route uses a terminal capturing wildcard carrying a leading
	// slash. Certificate + folder slugs are [a-z0-9-] only, so no URL escaping is
	// required (same as folderChildrenPath).
	url := "/kagi/folders/certificates/resolve/" + trimmed
	if err := c.doGet(ctx, TokenScope{}, url, &resp); err != nil {
		return "", err
	}
	if resp.CertificateID == "" {
		return "", fmt.Errorf("kagi: certificate resolve response for %q carried no certificate id", path)
	}
	return resp.CertificateID, nil
}
