/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// KagiCertificateSpec defines the desired state of KagiCertificate.
// +kubebuilder:validation:XValidation:rule="has(self.certificateID) || has(self.folderPath)",message="one of certificateID or folderPath is required"
type KagiCertificateSpec struct {
	// CertificateID is the Kagi certificate's stable internal ID -- the durable
	// machine binding. Resolve it once from a certificate node path at setup (e.g.
	// via the Kagi CLI/SDK ResolveCertificate) and pin it here. It is stable across
	// certificate renames and folder moves, so reconciliation never depends on the
	// certificate's current slug or location. This is the primary, preferred field.
	// When set, FolderPath is ignored.
	// +optional
	CertificateID string `json:"certificateID,omitempty"`

	// FolderPath is the human-readable certificate node path (e.g.
	// "/team-tls/acme-tls"): the final segment is the certificate slug and the
	// preceding segments identify the folder it lives in. When CertificateID is
	// empty, the controller resolves this path to a certificate ID once per
	// reconcile via the Kagi SDK. Prefer CertificateID: a folder move or rename
	// invalidates a FolderPath binding.
	// +optional
	FolderPath string `json:"folderPath,omitempty"`

	// Organization is the optional Kagi organization UUID. When set, it is sent as a
	// cross-check (X-Organization-ID) and MUST match the PAT's bound organization, or the
	// Kagi API rejects the request (403). Leave empty to use the token's bound organization.
	//
	// The value is validated as a canonical UUID at admission because a non-UUID can never
	// be a Kagi organization id: the API parses the header with UUID.fromString, so a typo
	// either makes every reconcile fail with a permanent 403 (tenancy enforcement STRICT) or
	// is discarded without comment (OFF/SHADOW), silently disabling the cross-check the user
	// asked for. The empty string stays accepted so an unset chart value templated as
	// `organization: ""` keeps meaning "use the token's bound organization".
	// +kubebuilder:validation:Pattern=`^$|^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`
	// +optional
	Organization string `json:"organization,omitempty"`

	// TokenSecret references the K8s Secret holding the Kagi PAT. It overrides
	// the operator's default authentication for this object, and it is required
	// when the operator runs with --kagi-auth exchange, which cannot read a
	// certificate.
	// +optional
	TokenSecret *TokenSecretRef `json:"tokenSecret,omitempty"`

	// ManagedSecret defines the target K8s Secret to create/update.
	ManagedSecret ManagedSecretRef `json:"managedSecret"`
}

// KagiCertificateStatus defines the observed state of KagiCertificate.
type KagiCertificateStatus struct {
	// conditions represent the current state of the KagiCertificate resource.
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// LastSyncTime is the timestamp of the last successful sync.
	// +optional
	LastSyncTime *metav1.Time `json:"lastSyncTime,omitempty"`

	// Thumbprint is the SHA-256 thumbprint of the synced certificate.
	// +optional
	Thumbprint string `json:"thumbprint,omitempty"`

	// NotAfter is the expiration time of the synced certificate.
	// +optional
	NotAfter *metav1.Time `json:"notAfter,omitempty"`

	// ExpiresInDays is the number of days until the certificate expires.
	// +optional
	ExpiresInDays int `json:"expiresInDays,omitempty"`

	// ResolvedCertificateID is the stable certificate ID the last sync addressed
	// TLS content with. When spec.certificateID is set it equals that; when only
	// spec.folderPath is set it records the ID resolved from the path. Purely
	// observational.
	// +optional
	ResolvedCertificateID string `json:"resolvedCertificateID,omitempty"`

	// LastErrorMessage is the error message from the last failed sync.
	// +optional
	LastErrorMessage string `json:"lastErrorMessage,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Certificate ID",type=string,JSONPath=`.spec.certificateID`
// +kubebuilder:printcolumn:name="Folder Path",type=string,JSONPath=`.spec.folderPath`
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`
// +kubebuilder:printcolumn:name="Last Sync",type=date,JSONPath=`.status.lastSyncTime`
// +kubebuilder:printcolumn:name="Expires",type=date,JSONPath=`.status.notAfter`
// +kubebuilder:printcolumn:name="Days Left",type=integer,JSONPath=`.status.expiresInDays`

// KagiCertificate is the Schema for the kagicertificates API.
type KagiCertificate struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// spec defines the desired state of KagiCertificate
	// +required
	Spec KagiCertificateSpec `json:"spec"`

	// status defines the observed state of KagiCertificate
	// +optional
	Status KagiCertificateStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true

// KagiCertificateList contains a list of KagiCertificate.
type KagiCertificateList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []KagiCertificate `json:"items"`
}

func init() {
	SchemeBuilder.Register(&KagiCertificate{}, &KagiCertificateList{})
}
