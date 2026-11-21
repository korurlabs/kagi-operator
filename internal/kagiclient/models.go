// Package kagiclient provides a read-only Go client for the Kagi secrets
// management API, vendored into the operator.
//
// Addressing follows the folder model: secrets are addressed by an app's stable
// internal ID plus an environment slug (the durable machine binding), while
// folder paths are used only for browsing and one-time path -> app-ID
// resolution at setup. Folder IDs are never sent by the client.
package kagiclient

// LibrarySlug is the URL slug identifying a Kagi folder library in the
// folder-browse routes. It is not the wire enum: KagiLibrary (generated) carries
// SECRETS, PASSWORDS, ... in response bodies, while the path segment is the
// lower-case slug, which the spec types as a plain string.
type LibrarySlug string

// Library slugs as accepted by the folder-browse routes.
const (
	LibrarySecrets       LibrarySlug = "secrets"
	LibraryPasswords     LibrarySlug = "passwords"
	LibraryAuthenticator LibrarySlug = "authenticator"
	LibraryCertificates  LibrarySlug = "certificates"
	LibraryAccessTokens  LibrarySlug = "access-tokens"
)

// The wire shapes are generated (zz_generated_api.go, from the operator bundle
// projects/kagi/contract/clients/operator.json). These names are aliases, not new types,
// so every existing caller keeps working while the fields, their nullability and
// their JSON tags come from the backend DTO. Never re-declare one of them as a
// struct here: models_contract_test.go fails on a name that stops being its
// generated counterpart.

// App represents a Kagi app exposed by a SECRETS folder's children listing.
// The ID is the stable machine binding used to address secrets; renaming or
// moving an app never changes it.
type App = FolderAppResponse

// Folder represents a folder node within a Kagi library. Library is the wire
// enum KagiLibrary (SECRETS, PASSWORDS, ...), not the URL slug LibrarySlug carries.
type Folder = FolderResponse

// FolderChildren is the result of browsing a folder: its child folders and,
// for the SECRETS library, the apps directly under it. Apps is empty for
// non-SECRETS libraries.
type FolderChildren = FolderChildrenResponse

// Environment represents a Kagi environment within an app. The hand-written
// three-field copy this replaces read only id/name/slug; the generated record
// also carries displayOrder, secretCount, personal and ownerId.
type Environment = KagiEnvironmentListResponse

// SecretFetchResponse holds decrypted secrets as key-value pairs.
type SecretFetchResponse = KagiSecretFetchResponse

// SecretVersionResponse is the lightweight version probe for an app
// environment's secrets. It carries an opaque version token that changes
// whenever the underlying secret set changes, plus cheap metadata. It never
// contains secret values, so consumers can poll it without triggering a
// decrypt on the server. Version is opaque: compare it for equality only, do
// not parse or order it.
type SecretVersionResponse = KagiSecretVersionResponse

// CertificateResolveResponse is the result of resolving a certificate node path
// to its stable id. CertificateID is the durable machine binding (survives
// certificate renames and folder moves) and should be captured once at setup,
// then used to fetch TLS content thereafter. Name is the certificate's
// human-readable display name, returned for setup confirmation only.
//
// The TLS content itself is the generated CertificateEntry, used under its own
// name. Its TLSKey is a pointer: the backend sends null for a certificate stored
// without a private key.
type CertificateResolveResponse = KagiCertificateResolveResponse
