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

package controller

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"math"
	"net/http"
	"os"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	kagiv1alpha1 "github.com/korurlabs/kagi-operator/api/v1alpha1"
	kagi "github.com/korurlabs/kagi-operator/internal/kagiclient"
)

// kagiCertificateResyncInterval is the fixed cadence at which each
// KagiCertificate is re-reconciled absent a spec/annotation change. Looser
// than the KagiSecret cadence because certs rotate rarely and status fields
// (ExpiresInDays) are day-granular, so sub-10m polling buys nothing.
const kagiCertificateResyncInterval = 10 * time.Minute

const (
	certFinalizerName  = "kagi.pw/certificate-cleanup"
	labelCertificateID = "kagi.pw/certificate-id"
)

// KagiCertificateReconciler reconciles a KagiCertificate object.
type KagiCertificateReconciler struct {
	client.Client
	Scheme *runtime.Scheme

	// KagiAPIURL is the base URL of the Kagi API.
	KagiAPIURL string

	// APIReader reads from the API server instead of the informer cache. The
	// deletion of a managed Secret reads through it, so the ownership it checks
	// before deleting is current. When nil, Client is used.
	APIReader client.Reader

	// Recorder emits Warning Events on a KagiCertificate whose deletion left
	// its managed Secret in place or could not delete it. When nil, no Event
	// is emitted; the log line or returned error still reports it.
	Recorder record.EventRecorder

	// OperatorNamespace is the namespace the operator runs in. Only a
	// KagiCertificate in it may name a token Secret or a managed Secret in
	// another namespace; see checkSecretReferences. When empty, no
	// KagiCertificate may.
	OperatorNamespace string

	// DefaultTokenSecretName is the name of the K8s Secret containing the default PAT.
	DefaultTokenSecretName string

	// DefaultTokenSecretNamespace is the namespace of the default token Secret.
	DefaultTokenSecretNamespace string

	// DefaultTokenSecretKey is the key within the default token Secret holding
	// the PAT. When empty, KAGI_TOKEN is tried and then token. When set, that key
	// is used exclusively and its absence is an error -- see tokenFromSecret.
	//
	// It applies to the DEFAULT token Secret only. A per-object
	// spec.tokenSecret names a Secret the object's author controls, and the CRD
	// gives them no way to declare a key, so those keep the fallback.
	DefaultTokenSecretKey string

	// WorkloadTokens is set when the operator runs with --kagi-auth exchange.
	// The exchange grants (app, environment) pairs and a certificate is not
	// one, so under it a KagiCertificate must name its own spec.tokenSecret.
	WorkloadTokens kagi.TokenSource

	// FailureBackoffBase and FailureBackoffMax bound the per-object retry delay
	// after a reconcile returns an error. Same semantics and flags as the
	// matching KagiSecretReconciler fields; see newFailureRateLimiter.
	FailureBackoffBase time.Duration
	FailureBackoffMax  time.Duration
}

// +kubebuilder:rbac:groups=kagi.pw,resources=kagicertificates,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=kagi.pw,resources=kagicertificates/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=kagi.pw,resources=kagicertificates/finalizers,verbs=update
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch;create;update;patch;delete

// Reconcile syncs TLS certificates from the Kagi API into a managed K8s TLS Secret.
func (r *KagiCertificateReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	// Fetch the KagiCertificate CR.
	var kagiCert kagiv1alpha1.KagiCertificate
	if err := r.Get(ctx, req.NamespacedName, &kagiCert); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	// Handle deletion with finalizer.
	if !kagiCert.DeletionTimestamp.IsZero() {
		if controllerutil.ContainsFinalizer(&kagiCert, certFinalizerName) {
			if err := r.cleanupManagedSecret(ctx, &kagiCert); err != nil {
				return ctrl.Result{}, err
			}
			controllerutil.RemoveFinalizer(&kagiCert, certFinalizerName)
			if err := r.Update(ctx, &kagiCert); err != nil {
				return ctrl.Result{}, err
			}
		}
		return ctrl.Result{}, nil
	}

	// Add finalizer if not present. See the matching comment in
	// kagisecret_controller.go -- the predicate on SetupWithManager drops
	// metadata-only changes, so without an explicit Requeue the CR never gets
	// re-reconciled after the finalizer write and the managed Secret is never
	// created until the operator restarts.
	if !controllerutil.ContainsFinalizer(&kagiCert, certFinalizerName) {
		controllerutil.AddFinalizer(&kagiCert, certFinalizerName)
		if err := r.Update(ctx, &kagiCert); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{RequeueAfter: time.Second}, nil
	}

	// Snapshot the current status so we can diff and only write when something
	// actually changed. See the matching comment in kagisecret_controller.go
	// for why this matters (avoids a self-inflicted reconcile loop).
	previousStatus := *kagiCert.Status.DeepCopy()

	// spec.organization is sent verbatim as the X-Organization-ID cross-check, so a
	// value that is not a UUID can never match a Kagi organization id. The CRD's
	// Pattern enforces this at admission; guard here too, because admission only
	// runs on a write: an object stored before the pattern landed (or written by a
	// client that skips validation) keeps its bad value and would otherwise be sent
	// on every reconcile forever. Neither way the API answers names the typo --
	// under tenancy enforcement STRICT it is a 403 on every request, and under
	// OFF/SHADOW the mismatch is logged server-side while the request proceeds on
	// the token's own organization, so the cross-check the author asked for
	// silently never happens. Refusing here puts the cause in the CR's status
	// instead of leaving it to be inferred from the API's behaviour.
	if err := kagi.ValidateOrganizationID(kagiCert.Spec.Organization); err != nil {
		validationErr := fmt.Errorf("spec.organization is invalid: %w", err)
		setReadyCondition(&kagiCert.Status.Conditions, kagiCert.Generation, metav1.ConditionFalse, reasonInvalidSpec, validationErr.Error())
		kagiCert.Status.LastErrorMessage = validationErr.Error()
		if err := r.patchStatusIfChanged(ctx, &kagiCert, &previousStatus); err != nil {
			log.Error(err, "Failed to update status")
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, validationErr
	}

	// Refuse before the token Secret or the managed Secret is read: a Secret
	// type the operator does not write, or a Secret in another namespace named
	// from outside the operator's namespace.
	if err := r.checkSecretReferences(&kagiCert); err != nil {
		setReadyCondition(&kagiCert.Status.Conditions, kagiCert.Generation, metav1.ConditionFalse, managedSecretFailureReason(err), err.Error())
		kagiCert.Status.LastErrorMessage = err.Error()
		r.patchFailureStatus(ctx, &kagiCert, &previousStatus)
		return ctrl.Result{}, err
	}

	// Under the workload exchange only a per-object token Secret can read a
	// certificate. Retrying cannot change that, so the object waits for a
	// spec edit.
	if r.WorkloadTokens != nil && kagiCert.Spec.TokenSecret == nil {
		setReadyCondition(&kagiCert.Status.Conditions, kagiCert.Generation, metav1.ConditionFalse, reasonWorkloadTokenCannotResolve, certificateUnderExchangeMessage)
		kagiCert.Status.LastErrorMessage = certificateUnderExchangeMessage
		if err := r.patchStatusIfChanged(ctx, &kagiCert, &previousStatus); err != nil {
			log.Error(err, "Failed to update status")
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}

	// Resolve the auth token.
	token, err := r.resolveToken(ctx, &kagiCert)
	if err != nil {
		setReadyCondition(&kagiCert.Status.Conditions, kagiCert.Generation, metav1.ConditionFalse, reasonTokenResolutionFailed, err.Error())
		kagiCert.Status.LastErrorMessage = err.Error()
		r.patchFailureStatus(ctx, &kagiCert, &previousStatus)
		return ctrl.Result{}, err
	}

	// Create SDK client. When spec.Organization is set it is sent as an
	// X-Organization-ID cross-check; the Kagi API rejects (403) the request if it
	// does not match the PAT's bound org. Empty == use the token's org (identical
	// to pre-multi-org behavior).
	log.Info("Reconciling KagiCertificate", "certificateID", kagiCert.Spec.CertificateID, "folderPath", kagiCert.Spec.FolderPath, "organization", kagiCert.Spec.Organization)
	kagiClient := kagi.NewClient(r.KagiAPIURL, token, kagiClientOptions(kagiCert.Spec.Organization)...)

	// Resolve the durable certificate ID. spec.certificateID is the primary,
	// stable binding; when it is absent we resolve spec.folderPath (the full
	// certificate node path) to a certificate ID once via the SDK. This mirrors
	// how KagiSecret resolves its app ID.
	certificateID, err := r.resolveCertificateID(ctx, kagiClient, &kagiCert)
	if err != nil {
		setReadyCondition(&kagiCert.Status.Conditions, kagiCert.Generation, metav1.ConditionFalse, "CertificateResolutionFailed", err.Error())
		kagiCert.Status.LastErrorMessage = err.Error()
		r.patchFailureStatus(ctx, &kagiCert, &previousStatus)
		return ctrl.Result{}, err
	}
	kagiCert.Status.ResolvedCertificateID = certificateID

	// Refuse before fetching: a managed Secret that another resource owns, or
	// that the operator did not create, is never written, so the certificate and
	// its private key are never fetched for it either.
	if err := guardManagedSecret(ctx, r.Client, certManagedSecretKey(&kagiCert), r.managedSecretClaim(&kagiCert, certificateID)); err != nil {
		setReadyCondition(&kagiCert.Status.Conditions, kagiCert.Generation, metav1.ConditionFalse, managedSecretFailureReason(err), err.Error())
		kagiCert.Status.LastErrorMessage = err.Error()
		r.patchFailureStatus(ctx, &kagiCert, &previousStatus)
		return ctrl.Result{}, err
	}

	// Fetch TLS content by the durable certificate ID.
	certData, err := kagiClient.FetchCertificateByID(ctx, certificateID)
	if err != nil {
		// Distinguish a 404 (no certificate with this id) so the status condition
		// tells operators the binding is stale, rather than reading as a generic
		// fetch failure.
		reason := "FetchFailed"
		message := err.Error()
		var apiErr *kagi.APIError
		if errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusNotFound {
			reason = "CertificateNotFound"
			message = fmt.Sprintf(
				"no certificate found for id %q; the certificate may have been deleted "+
					"(set spec.certificateID to an existing certificate, or spec.folderPath to its node path): %s",
				certificateID, err.Error())
		}
		setReadyCondition(&kagiCert.Status.Conditions, kagiCert.Generation, metav1.ConditionFalse, reason, message)
		kagiCert.Status.LastErrorMessage = message
		r.patchFailureStatus(ctx, &kagiCert, &previousStatus)
		return ctrl.Result{}, err
	}

	// Create or update the managed K8s TLS Secret.
	secretChanged, err := r.reconcileManagedSecret(ctx, &kagiCert, certificateID, certData)
	if err != nil {
		setReadyCondition(&kagiCert.Status.Conditions, kagiCert.Generation, metav1.ConditionFalse, managedSecretFailureReason(err), err.Error())
		kagiCert.Status.LastErrorMessage = err.Error()
		r.patchFailureStatus(ctx, &kagiCert, &previousStatus)
		return ctrl.Result{}, err
	}

	// Parse certificate to extract metadata for status.
	thumbprint, notAfter, expiresInDays := parseCertificateMetadata(certData.TLSCrt)

	if secretChanged || kagiCert.Status.LastSyncTime == nil {
		now := metav1.Now()
		kagiCert.Status.LastSyncTime = &now
	}
	kagiCert.Status.Thumbprint = thumbprint
	kagiCert.Status.NotAfter = notAfter
	kagiCert.Status.ExpiresInDays = expiresInDays
	kagiCert.Status.LastErrorMessage = ""
	setReadyCondition(&kagiCert.Status.Conditions, kagiCert.Generation, metav1.ConditionTrue, "SyncSuccessful", "Certificate synced successfully")

	if err := r.patchStatusIfChanged(ctx, &kagiCert, &previousStatus); err != nil {
		log.Error(err, "Failed to update status")
		return ctrl.Result{}, err
	}

	if secretChanged {
		log.Info("Successfully synced certificate", "certificateID", certificateID, "thumbprint", thumbprint, "expiresInDays", expiresInDays)
	}
	return ctrl.Result{RequeueAfter: kagiCertificateResyncInterval}, nil
}

// patchFailureStatus records a failed reconcile on the CR status. A failed write is
// logged, not returned: the caller returns the reconcile error that caused the
// failure, and the requeue it triggers retries the status write as well.
func (r *KagiCertificateReconciler) patchFailureStatus(
	ctx context.Context, kagiCert *kagiv1alpha1.KagiCertificate, previous *kagiv1alpha1.KagiCertificateStatus,
) {
	if err := r.patchStatusIfChanged(ctx, kagiCert, previous); err != nil {
		logf.FromContext(ctx).Error(err, "Failed to update status")
	}
}

// patchStatusIfChanged writes the CR status back only when it differs from the
// snapshot. See kagisecret_controller.go for rationale.
func (r *KagiCertificateReconciler) patchStatusIfChanged(ctx context.Context, kagiCert *kagiv1alpha1.KagiCertificate, previous *kagiv1alpha1.KagiCertificateStatus) error {
	if equality.Semantic.DeepEqual(previous, &kagiCert.Status) {
		return nil
	}
	return r.Status().Update(ctx, kagiCert)
}

// resolveToken resolves the Kagi API token from the spec or defaults.
func (r *KagiCertificateReconciler) resolveToken(ctx context.Context, kagiCert *kagiv1alpha1.KagiCertificate) (string, error) {
	// Try spec.tokenSecret first.
	if kagiCert.Spec.TokenSecret != nil {
		ns := kagiCert.Spec.TokenSecret.Namespace
		if ns == "" {
			ns = kagiCert.Namespace
		}
		return r.readTokenFromSecret(ctx, kagiCert.Spec.TokenSecret.Name, ns, "")
	}

	// Try default token secret.
	if r.DefaultTokenSecretName != "" {
		ns := r.DefaultTokenSecretNamespace
		if ns == "" {
			ns = kagiCert.Namespace
		}
		return r.readTokenFromSecret(ctx, r.DefaultTokenSecretName, ns, r.DefaultTokenSecretKey)
	}

	// Fall back to environment variable.
	token := os.Getenv("KAGI_DEFAULT_TOKEN")
	if token == "" {
		return "", fmt.Errorf("no token configured: set spec.tokenSecret, --default-token-secret, or KAGI_DEFAULT_TOKEN env var")
	}
	return token, nil
}

// readTokenFromSecret reads the PAT from a K8s Secret. An empty key selects the
// KAGI_TOKEN -> token fallback; see tokenFromSecret.
func (r *KagiCertificateReconciler) readTokenFromSecret(ctx context.Context, name, namespace, key string) (string, error) {
	var secret corev1.Secret
	if err := r.Get(ctx, types.NamespacedName{Name: name, Namespace: namespace}, &secret); err != nil {
		return "", fmt.Errorf("failed to read token secret %s/%s: %w", namespace, name, err)
	}
	return tokenFromSecret(&secret, key)
}

// resolveCertificateID determines the stable certificate ID to fetch TLS content
// with. spec.certificateID is the primary, durable binding and is used verbatim
// when present. When it is absent, spec.folderPath (the full certificate node
// path) is resolved to a certificate ID via the SDK (a one-time path -> id
// lookup). At least one of the two fields is guaranteed present by the CRD's
// XValidation, but we guard here too. Mirrors KagiSecretReconciler.resolveAppID.
func (r *KagiCertificateReconciler) resolveCertificateID(ctx context.Context, kagiClient *kagi.Client, kagiCert *kagiv1alpha1.KagiCertificate) (string, error) {
	if kagiCert.Spec.CertificateID != "" {
		return kagiCert.Spec.CertificateID, nil
	}
	if kagiCert.Spec.FolderPath == "" {
		return "", fmt.Errorf("neither spec.certificateID nor spec.folderPath is set")
	}
	certificateID, err := kagiClient.ResolveCertificate(ctx, kagiCert.Spec.FolderPath)
	if err != nil {
		return "", fmt.Errorf("failed to resolve folderPath %q to a certificate ID: %w", kagiCert.Spec.FolderPath, err)
	}
	return certificateID, nil
}

// certManagedSecretKey returns the name and namespace of a KagiCertificate's
// managed Secret. An empty spec.managedSecret.namespace falls back to the
// KagiCertificate's own namespace.
func certManagedSecretKey(kagiCert *kagiv1alpha1.KagiCertificate) types.NamespacedName {
	key := types.NamespacedName{Name: kagiCert.Spec.ManagedSecret.Name, Namespace: kagiCert.Spec.ManagedSecret.Namespace}
	if key.Namespace == "" {
		key.Namespace = kagiCert.Namespace
	}
	return key
}

// certManagedSecretReference is the namespace reference of spec.managedSecret.
func certManagedSecretReference(kagiCert *kagiv1alpha1.KagiCertificate) secretReference {
	return secretReference{field: "spec.managedSecret.namespace", namespace: kagiCert.Spec.ManagedSecret.Namespace}
}

// checkSecretReferences refuses a KagiCertificate whose spec.managedSecret.type
// the operator does not write, or that names a token Secret or a managed
// Secret the KagiCertificate may not reference; see checkManagedSecretType and
// the package-level checkSecretReferences.
func (r *KagiCertificateReconciler) checkSecretReferences(kagiCert *kagiv1alpha1.KagiCertificate) error {
	if err := checkManagedSecretType(kagiCert.Spec.ManagedSecret.Type); err != nil {
		return err
	}
	refs := []secretReference{certManagedSecretReference(kagiCert)}
	if kagiCert.Spec.TokenSecret != nil {
		refs = append(refs, secretReference{field: "spec.tokenSecret.namespace", namespace: kagiCert.Spec.TokenSecret.Namespace})
	}
	return checkSecretReferences(kagiCert, kindKagiCertificate, r.OperatorNamespace, refs...)
}

// managedSecretClaim returns what kagiCert, bound to the resolved
// certificateID, claims about its managed Secret. An empty certificateID
// yields a claim without an identity, which adopts no Secret.
func (r *KagiCertificateReconciler) managedSecretClaim(kagiCert *kagiv1alpha1.KagiCertificate, certificateID string) *managedSecretClaim {
	claim := &managedSecretClaim{
		kind:              kindKagiCertificate,
		owner:             managedSecretOwner(kindKagiCertificate, kagiCert),
		namespace:         kagiCert.Namespace,
		operatorNamespace: r.OperatorNamespace,
	}
	if certificateID != "" {
		claim.identity = map[string]string{labelCertificateID: certificateID}
	}
	return claim
}

// reconcileManagedSecret creates or updates the managed K8s TLS Secret.
// Returns true when the Secret was created or updated. A Secret this
// KagiCertificate does not own is left untouched; see writeManagedSecret.
func (r *KagiCertificateReconciler) reconcileManagedSecret(ctx context.Context, kagiCert *kagiv1alpha1.KagiCertificate, certificateID string, certData *kagi.CertificateEntry) (bool, error) {
	spec := kagiCert.Spec.ManagedSecret

	// A certificate stored without a private key arrives with a null tlsKey; it is
	// written as an empty tls.key, as before the key became a nullable field.
	tlsKey := ""
	if certData.TLSKey != nil {
		tlsKey = *certData.TLSKey
	}

	secretData := map[string][]byte{
		"tls.crt": []byte(certData.TLSCrt),
		"tls.key": []byte(tlsKey),
	}

	// Compute hash of certificate data for change detection.
	dataHash := computeDataHash(map[string]string{
		"tls.crt": certData.TLSCrt,
		"tls.key": tlsKey,
	})

	// Determine the secret type; default to kubernetes.io/tls for certificates.
	secretType := corev1.SecretType(spec.Type)
	if spec.Type == "" || spec.Type == "Opaque" {
		secretType = corev1.SecretTypeTLS
	}

	return writeManagedSecret(ctx, r.Client, &desiredManagedSecret{
		key:        certManagedSecretKey(kagiCert),
		claim:      r.managedSecretClaim(kagiCert, certificateID),
		dataHash:   dataHash,
		data:       secretData,
		secretType: secretType,
	})
}

// cleanupManagedSecret deletes the managed K8s Secret during CR deletion, when
// this KagiCertificate owns it, or when an earlier release wrote it for the
// certificate in status.resolvedCertificateID and this KagiCertificate could
// adopt it. A non-nil error means the finalizer must stay; see
// managedSecretRelease.release.
func (r *KagiCertificateReconciler) cleanupManagedSecret(ctx context.Context, kagiCert *kagiv1alpha1.KagiCertificate) error {
	release := &managedSecretRelease{
		reader:            liveReader(r.APIReader, r.Client),
		writer:            r.Client,
		recorder:          r.Recorder,
		operatorNamespace: r.OperatorNamespace,
	}
	claim := r.managedSecretClaim(kagiCert, kagiCert.Status.ResolvedCertificateID)
	return release.release(ctx, kagiCert, claim, certManagedSecretKey(kagiCert), certManagedSecretReference(kagiCert))
}

// parseCertificateMetadata extracts thumbprint, notAfter, and expiresInDays from a PEM certificate.
func parseCertificateMetadata(certPEM string) (thumbprint string, notAfter *metav1.Time, expiresInDays int) {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return "", nil, 0
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", nil, 0
	}

	// Compute SHA-256 thumbprint of the DER-encoded certificate.
	hash := sha256.Sum256(cert.Raw)
	thumbprint = fmt.Sprintf("%x", hash[:])

	// Set notAfter.
	na := metav1.NewTime(cert.NotAfter)
	notAfter = &na

	// Compute days until expiry.
	daysLeft := time.Until(cert.NotAfter).Hours() / 24
	expiresInDays = int(math.Max(0, math.Floor(daysLeft)))

	return thumbprint, notAfter, expiresInDays
}

// SetupWithManager sets up the controller with the Manager.
//
// See the matching comment on KagiSecretReconciler.SetupWithManager for why
// this event filter exists -- same status-update feedback loop fix -- and
// for why the error-retry rate limiter is replaced. MaxConcurrentReconciles
// is deliberately left at controller-runtime's default of 1.
func (r *KagiCertificateReconciler) SetupWithManager(mgr ctrl.Manager) error {
	rateLimiter, err := newFailureRateLimiter(r.FailureBackoffBase, r.FailureBackoffMax)
	if err != nil {
		return fmt.Errorf("configure KagiCertificate retry backoff: %w", err)
	}
	return ctrl.NewControllerManagedBy(mgr).
		For(&kagiv1alpha1.KagiCertificate{}).
		WithEventFilter(predicate.Or(
			predicate.GenerationChangedPredicate{},
			predicate.AnnotationChangedPredicate{},
			predicate.LabelChangedPredicate{},
		)).
		WithOptions(controller.Options{RateLimiter: rateLimiter}).
		Named("kagicertificate").
		Complete(r)
}
