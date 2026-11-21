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

// KagiSecretSpec defines the desired state of KagiSecret.
// +kubebuilder:validation:XValidation:rule="has(self.appId) || has(self.folderPath)",message="one of appId or folderPath is required"
// +kubebuilder:validation:XValidation:rule="self.mode == 'Injected' || has(self.managedSecret)",message="spec.managedSecret is required unless spec.mode is Injected"
type KagiSecretSpec struct {
	// AppID is the Kagi app's stable internal ID -- the durable machine binding.
	// Resolve it once from a folder path at setup (e.g. via the Kagi CLI/SDK
	// ResolveApp) and pin it here. It is stable across app renames and folder
	// moves, so reconciliation never depends on the app's current location.
	// This is the primary, preferred field. When set, FolderPath is ignored.
	// +optional
	AppID string `json:"appId,omitempty"`

	// FolderPath is the human-readable SECRETS folder path of the app
	// (e.g. "/fepatex/backend/api"). When AppID is empty, the controller
	// resolves this path to an app ID once per reconcile via the Kagi SDK.
	// Prefer AppID: a folder move or rename invalidates a FolderPath binding.
	// +optional
	FolderPath string `json:"folderPath,omitempty"`

	// Environment is the environment slug (e.g., "production").
	Environment string `json:"environment"`

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

	// Mode selects how fetched secrets are delivered. "Secret" (the default)
	// materializes them into the managed Kubernetes Secret named by
	// managedSecret. "Injected" delivers them directly to the workloads named by
	// rollout without persisting a standalone Secret. Existing resources that
	// omit this field behave as "Secret".
	// +kubebuilder:validation:Enum=Secret;Injected
	// +kubebuilder:default=Secret
	// +optional
	Mode string `json:"mode,omitempty"`

	// How the operator authenticates is an operator setting, not a field here:
	// --kagi-auth (token-secret or exchange) picks the default for every object,
	// and spec.tokenSecret below overrides it per object.

	// TokenSecret references the K8s Secret holding the Kagi PAT. It overrides
	// the operator's default authentication for this object, including
	// --kagi-auth exchange.
	// +optional
	TokenSecret *TokenSecretRef `json:"tokenSecret,omitempty"`

	// Rollout optionally names workloads to restart when the synced secrets
	// change (and identifies the injection targets in "Injected" mode). Inert
	// when omitted.
	// +optional
	Rollout *RolloutSpec `json:"rollout,omitempty"`

	// ManagedSecret defines the target K8s Secret to create/update. It is
	// required in "Secret" mode (the default) and enforced by an XValidation
	// rule on the spec. In "Injected" mode no standalone Secret is materialized,
	// so it may be omitted.
	// +optional
	ManagedSecret *ManagedSecretRef `json:"managedSecret,omitempty"`
}

// RolloutSpec configures which workloads are rolled out when this KagiSecret's
// secrets change. It is consumed to trigger rolling restarts (and, in
// "Injected" mode, to identify injection targets); it is inert when empty.
type RolloutSpec struct {
	// Deployments is an explicit list of Deployment names, in the managed
	// Secret's namespace, to roll out when the synced secrets change.
	// +optional
	Deployments []string `json:"deployments,omitempty"`

	// WorkloadSelector selects additional workloads to roll out by label, in
	// addition to any named in Deployments.
	// +optional
	WorkloadSelector *metav1.LabelSelector `json:"workloadSelector,omitempty"`
}

// TokenSecretRef references a K8s Secret containing the Kagi PAT.
type TokenSecretRef struct {
	// Name is the name of the K8s Secret.
	Name string `json:"name"`

	// Namespace is the namespace of the K8s Secret.
	// +optional
	Namespace string `json:"namespace,omitempty"`
}

// ManagedSecretRef defines the target K8s Secret to create/update.
type ManagedSecretRef struct {
	// Name is the name of the managed K8s Secret.
	Name string `json:"name"`

	// Namespace is the namespace of the managed K8s Secret.
	// Defaults to the CR's namespace if omitted.
	// +optional
	Namespace string `json:"namespace,omitempty"`

	// Type is the type of the managed K8s Secret. Only the types the operator
	// writes are accepted: Opaque for a KagiSecret, and kubernetes.io/tls for a
	// KagiCertificate, which also maps Opaque to kubernetes.io/tls. Other types
	// are refused because some mean more to the cluster than the data they
	// hold; the token controller, for one, fills a
	// kubernetes.io/service-account-token Secret with a ServiceAccount token.
	// +kubebuilder:validation:Enum=Opaque;kubernetes.io/tls
	// +kubebuilder:default=Opaque
	// +optional
	Type string `json:"type,omitempty"`
}

// KagiSecretStatus defines the observed state of KagiSecret.
type KagiSecretStatus struct {
	// conditions represent the current state of the KagiSecret resource.
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// LastSyncTime is the timestamp of the last successful sync.
	// +optional
	LastSyncTime *metav1.Time `json:"lastSyncTime,omitempty"`

	// LastRolloutTime is the timestamp of the last rolling restart the controller
	// triggered in "Injected" mode by stamping the secrets-version annotation on
	// the rollout targets. Only set in Injected mode; nil until the first
	// version-change-driven rollout.
	// +optional
	LastRolloutTime *metav1.Time `json:"lastRolloutTime,omitempty"`

	// SecretCount is the number of secrets synced.
	// +optional
	SecretCount int `json:"secretCount,omitempty"`

	// LastVersion is the opaque secrets version token observed at the last
	// successful sync. On the next reconcile the controller probes the current
	// version cheaply; when it equals this value and the managed Secret is still
	// intact, the full (decrypting) fetch is skipped. Treated as opaque: compared
	// for equality only, never parsed or ordered.
	// +optional
	LastVersion string `json:"lastVersion,omitempty"`

	// ResolvedAppID is the stable app ID the last sync addressed secrets with.
	// When spec.appId is set it equals that; when only spec.folderPath is set it
	// records the ID resolved from the path. Purely observational.
	// +optional
	ResolvedAppID string `json:"resolvedAppID,omitempty"`

	// LastErrorMessage is the error message from the last failed sync.
	// +optional
	LastErrorMessage string `json:"lastErrorMessage,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="App ID",type=string,JSONPath=`.spec.appId`
// +kubebuilder:printcolumn:name="Folder Path",type=string,JSONPath=`.spec.folderPath`
// +kubebuilder:printcolumn:name="Environment",type=string,JSONPath=`.spec.environment`
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`
// +kubebuilder:printcolumn:name="Last Sync",type=date,JSONPath=`.status.lastSyncTime`
// +kubebuilder:printcolumn:name="Secrets",type=integer,JSONPath=`.status.secretCount`
// +kubebuilder:printcolumn:name="Version",type=string,priority=1,JSONPath=`.status.lastVersion`

// KagiSecret is the Schema for the kagisecrets API.
type KagiSecret struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// spec defines the desired state of KagiSecret
	// +required
	Spec KagiSecretSpec `json:"spec"`

	// status defines the observed state of KagiSecret
	// +optional
	Status KagiSecretStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true

// KagiSecretList contains a list of KagiSecret.
type KagiSecretList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []KagiSecret `json:"items"`
}

func init() {
	SchemeBuilder.Register(&KagiSecret{}, &KagiSecretList{})
}
