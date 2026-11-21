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
	"errors"
	"fmt"
	"hash/fnv"
	"os"
	"sort"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
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

// kagiSecretResyncInterval is the fixed cadence at which each KagiSecret is
// re-reconciled when no spec/annotation change triggered it. Kept short enough
// for humans to feel responsive; long enough to keep kagi-api idle.
const kagiSecretResyncInterval = 5 * time.Minute

// kagiSecretResyncJitter is the maximum +/- offset applied to the steady-state
// resync so a large population of KagiSecrets does not requeue in lockstep.
const kagiSecretResyncJitter = 60 * time.Second

const (
	finalizerName = "kagi.pw/secret-cleanup"

	labelManagedBy = "app.kubernetes.io/managed-by"
	labelAppID     = "kagi.pw/app-id"
	labelEnv       = "kagi.pw/environment"
	annotationHash = "kagi.pw/data-hash"
	managedByValue = "kagi-operator"

	// modeInjected is the spec.mode value that delivers secrets directly to
	// workloads (via the injection webhook + kagi-init) instead of materializing
	// a managed Kubernetes Secret. Any other value (including the empty default)
	// is Secret mode.
	modeInjected = "Injected"

	// annotationSecretsVersion is stamped on a rollout target's pod template in
	// Injected mode when the upstream secrets version changes, producing a
	// native, health-gated rolling restart that makes kagi-init re-fetch.
	annotationSecretsVersion = "kagi.pw/secrets-version"
)

// KagiSecretReconciler reconciles a KagiSecret object.
type KagiSecretReconciler struct {
	client.Client
	Scheme *runtime.Scheme

	// KagiAPIURL is the base URL of the Kagi API.
	KagiAPIURL string

	// APIReader reads from the API server instead of the informer cache. The
	// deletion of a managed Secret reads through it, so the ownership it checks
	// before deleting is current. When nil, Client is used.
	APIReader client.Reader

	// Recorder emits Warning Events on a KagiSecret whose deletion left its
	// managed Secret in place or could not delete it. When nil, no Event is
	// emitted; the log line or returned error still reports it.
	Recorder record.EventRecorder

	// OperatorNamespace is the namespace the operator runs in. Only a
	// KagiSecret in it may name a token Secret or a managed Secret in another
	// namespace; see checkSecretReferences. When empty, no KagiSecret may.
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

	// WorkloadTokens, when set, replaces the default token Secret: the
	// operator exchanges its projected ServiceAccount token for a token per
	// (app, environment) pair (--kagi-auth exchange). A per-object
	// spec.tokenSecret still wins. Nil keeps the token Secret flow.
	WorkloadTokens kagi.TokenSource

	// MaxConcurrentReconciles bounds how many KagiSecret objects reconcile in
	// parallel. Higher values drain a large backlog faster at the cost of more
	// concurrent load on kagi-api. Defaults to 1 when unset (controller-runtime
	// default); main wires it from the --max-concurrent-reconciles flag.
	MaxConcurrentReconciles int

	// FailureBackoffBase and FailureBackoffMax bound the per-object retry delay
	// after a reconcile returns an error (for example FetchFailed during a
	// backend incident): the first retry waits FailureBackoffBase, each further
	// consecutive failure doubles it, and FailureBackoffMax caps it. Zero
	// selects DefaultFailureBackoffBase / DefaultFailureBackoffMax; main wires
	// them from --failure-backoff-base and --failure-backoff-max. See
	// newFailureRateLimiter.
	FailureBackoffBase time.Duration
	FailureBackoffMax  time.Duration
}

// +kubebuilder:rbac:groups=kagi.pw,resources=kagisecrets,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=kagi.pw,resources=kagisecrets/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=kagi.pw,resources=kagisecrets/finalizers,verbs=update
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=apps,resources=deployments,verbs=get;list;watch;patch

// Reconcile syncs secrets from the Kagi API into a managed K8s Secret.
func (r *KagiSecretReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	// Fetch the KagiSecret CR.
	var kagiSecret kagiv1alpha1.KagiSecret
	if err := r.Get(ctx, req.NamespacedName, &kagiSecret); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	// Handle deletion with finalizer.
	if !kagiSecret.DeletionTimestamp.IsZero() {
		return ctrl.Result{}, r.finalize(ctx, &kagiSecret)
	}

	// Add finalizer if not present. The follow-up Requeue is required because
	// SetupWithManager filters Update events through a Generation/Annotation/
	// Label predicate -- adding a finalizer is a metadata-only change that the
	// predicate drops, so the CR would otherwise sit in a zombie state
	// (finalizer set, status empty, no managed Secret) until the operator
	// restarts. Requesting a requeue here re-enters Reconcile on the next
	// workqueue tick with the finalizer in place.
	if !controllerutil.ContainsFinalizer(&kagiSecret, finalizerName) {
		controllerutil.AddFinalizer(&kagiSecret, finalizerName)
		if err := r.Update(ctx, &kagiSecret); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{RequeueAfter: time.Second}, nil
	}

	// Snapshot the current status so we can diff and only write when something
	// actually changed. Status-only self-writes were the primary source of
	// reconcile loop churn against the Kagi API.
	previousStatus := *kagiSecret.Status.DeepCopy()

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
	if err := kagi.ValidateOrganizationID(kagiSecret.Spec.Organization); err != nil {
		validationErr := fmt.Errorf("spec.organization is invalid: %w", err)
		setReadyCondition(&kagiSecret.Status.Conditions, kagiSecret.Generation, metav1.ConditionFalse, reasonInvalidSpec, validationErr.Error())
		kagiSecret.Status.LastErrorMessage = validationErr.Error()
		if err := r.patchStatusIfChanged(ctx, &kagiSecret, &previousStatus); err != nil {
			log.Error(err, "Failed to update status")
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, validationErr
	}

	// Refuse before the token Secret or the managed Secret is read: a Secret
	// type the operator does not write, or a Secret in another namespace named
	// from outside the operator's namespace.
	if err := r.checkSecretReferences(&kagiSecret); err != nil {
		setReadyCondition(&kagiSecret.Status.Conditions, kagiSecret.Generation, metav1.ConditionFalse, managedSecretFailureReason(err), err.Error())
		kagiSecret.Status.LastErrorMessage = err.Error()
		r.patchFailureStatus(ctx, &kagiSecret, &previousStatus)
		return ctrl.Result{}, err
	}

	// Create the SDK client: a PAT, or the workload exchange per pair.
	kagiClient, err := r.kagiClientFor(ctx, &kagiSecret)
	if err != nil {
		return r.failCredential(ctx, &kagiSecret, &previousStatus, err)
	}
	log.Info("Reconciling KagiSecret", "appId", kagiSecret.Spec.AppID, "folderPath", kagiSecret.Spec.FolderPath, "environment", kagiSecret.Spec.Environment, "organization", kagiSecret.Spec.Organization)

	// Resolve the durable app ID. spec.appId is the primary binding; when it is
	// absent we resolve spec.folderPath to an app ID once via the SDK.
	appID, err := r.resolveAppID(ctx, kagiClient, &kagiSecret)
	if err != nil {
		setReadyCondition(&kagiSecret.Status.Conditions, kagiSecret.Generation, metav1.ConditionFalse, "AppResolutionFailed", err.Error())
		kagiSecret.Status.LastErrorMessage = err.Error()
		r.patchFailureStatus(ctx, &kagiSecret, &previousStatus)
		return ctrl.Result{}, err
	}
	kagiSecret.Status.ResolvedAppID = appID

	// Cheap, decrypt-free version probe. It tells us whether the upstream secret
	// set changed since our last successful sync without paying for a full fetch
	// (and its server-side decrypt). A backend that predates the version route
	// returns an error; we degrade to always-fetch so the operator keeps working
	// against an older kagi-api.
	version, versionKnown, err := r.probeSecretsVersion(ctx, kagiClient, appID, kagiSecret.Spec.Environment)
	if err != nil {
		return r.failExchange(ctx, &kagiSecret, &previousStatus, appID, err)
	}

	// Injected mode: never materialize a Secret. On a version change, stamp the
	// rollout targets to trigger a native rolling restart; kagi-init re-fetches
	// at pod start. This returns before any Secret-mode logic runs, so the
	// Secret-mode path below is byte-for-byte unchanged.
	if isInjectedMode(&kagiSecret) {
		return r.reconcileInjected(ctx, &kagiSecret, &previousStatus, appID, version, versionKnown)
	}

	// Secret mode requires a managed Secret target. The CRD's XValidation
	// enforces this at admission; guard here too so a CR that somehow reaches
	// reconcile without one (created before the rule, or via a client that
	// skips validation) fails loudly with the same validation error rather than
	// operating on an empty Secret name.
	if kagiSecret.Spec.ManagedSecret == nil {
		validationErr := fmt.Errorf("spec.managedSecret is required in Secret mode")
		setReadyCondition(&kagiSecret.Status.Conditions, kagiSecret.Generation, metav1.ConditionFalse, reasonInvalidSpec, validationErr.Error())
		kagiSecret.Status.LastErrorMessage = validationErr.Error()
		if err := r.patchStatusIfChanged(ctx, &kagiSecret, &previousStatus); err != nil {
			log.Error(err, "Failed to update status")
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, validationErr
	}

	// Refuse before fetching: a managed Secret that another resource owns, or
	// that the operator did not create, is never written, so its secrets are
	// never fetched either.
	if err := guardManagedSecret(ctx, r.Client, managedSecretKey(&kagiSecret), r.managedSecretClaim(&kagiSecret, appID)); err != nil {
		setReadyCondition(&kagiSecret.Status.Conditions, kagiSecret.Generation, metav1.ConditionFalse, managedSecretFailureReason(err), err.Error())
		kagiSecret.Status.LastErrorMessage = err.Error()
		r.patchFailureStatus(ctx, &kagiSecret, &previousStatus)
		return ctrl.Result{}, err
	}

	// Skip guard: the upstream version matches what we last synced AND our
	// managed Secret is still present and intact. In that case there is nothing
	// to do -- no fetch, no decrypt, no write. This is the primary scale fix.
	// The data-hash write-skip inside reconcileManagedSecret remains as a second
	// guard for the reconciles that do fetch.
	if versionKnown && version == kagiSecret.Status.LastVersion {
		intact, checkErr := r.managedSecretIntact(ctx, &kagiSecret)
		if checkErr == nil && intact {
			kagiSecret.Status.LastErrorMessage = ""
			setReadyCondition(&kagiSecret.Status.Conditions, kagiSecret.Generation, metav1.ConditionTrue, "SyncSkipped", "Secrets unchanged (version match); fetch skipped")
			if err := r.patchStatusIfChanged(ctx, &kagiSecret, &previousStatus); err != nil {
				log.Error(err, "Failed to update status")
				return ctrl.Result{}, err
			}
			return ctrl.Result{RequeueAfter: r.requeueAfter(&kagiSecret)}, nil
		}
	}

	secrets, err := r.fetchSecrets(ctx, kagiClient, appID, kagiSecret.Spec.Environment)
	if err != nil {
		return r.failExchange(ctx, &kagiSecret, &previousStatus, appID, err)
	}

	// Create or update the managed K8s Secret. The helper is already a no-op
	// when the content hash matches, so a resync that yields identical secrets
	// does not produce a write to the managed Secret.
	secretChanged, err := r.reconcileManagedSecret(ctx, &kagiSecret, appID, secrets)
	if err != nil {
		setReadyCondition(&kagiSecret.Status.Conditions, kagiSecret.Generation, metav1.ConditionFalse, managedSecretFailureReason(err), err.Error())
		kagiSecret.Status.LastErrorMessage = err.Error()
		r.patchFailureStatus(ctx, &kagiSecret, &previousStatus)
		return ctrl.Result{}, err
	}

	// Mark the CR ready. We keep LastSyncTime pinned to the previous value when
	// the underlying Secret did not change; bumping it on every pass would be
	// a second source of status churn that a naive watcher could still react
	// to (even with our predicate in place).
	if secretChanged || kagiSecret.Status.LastSyncTime == nil {
		now := metav1.Now()
		kagiSecret.Status.LastSyncTime = &now
	}
	kagiSecret.Status.SecretCount = len(secrets)
	// Record the version we just synced so the next reconcile can short-circuit.
	// Only when the probe succeeded: on the always-fetch fallback we leave the
	// prior value untouched rather than clobbering a good token with "".
	if versionKnown {
		kagiSecret.Status.LastVersion = version
	}
	kagiSecret.Status.LastErrorMessage = ""
	setReadyCondition(&kagiSecret.Status.Conditions, kagiSecret.Generation, metav1.ConditionTrue, "SyncSuccessful", "Secrets synced successfully")

	if err := r.patchStatusIfChanged(ctx, &kagiSecret, &previousStatus); err != nil {
		log.Error(err, "Failed to update status")
		return ctrl.Result{}, err
	}

	if secretChanged {
		log.Info("Successfully synced secrets", "count", len(secrets), "appId", appID, "environment", kagiSecret.Spec.Environment)
	}
	return ctrl.Result{RequeueAfter: r.requeueAfter(&kagiSecret)}, nil
}

// probeSecretsVersion asks kagi-api for the opaque secrets version token for an
// app environment. It returns (version, true, nil) on success and ("", false,
// nil) when the probe fails -- e.g. an older backend without the route, or a
// transient error -- which signals the caller to fall back to an unconditional
// fetch. That failure is logged at debug level only, since it is an expected
// degrade path.
//
// A failed token exchange is returned as the error instead: no later call can
// authenticate either, and in Injected mode the degrade path would report the
// object Ready while the operator cannot read the pair at all.
func (r *KagiSecretReconciler) probeSecretsVersion(ctx context.Context, kagiClient *kagi.Client, appID, environment string) (string, bool, error) {
	log := logf.FromContext(ctx)
	version, err := kagiClient.GetSecretsVersion(ctx, appID, environment)
	if err != nil {
		if kagi.IsExchangeError(err) {
			return "", false, err
		}
		log.V(1).Info("Secrets version probe unavailable; falling back to full fetch", "appId", appID, "environment", environment, "error", err.Error())
		return "", false, nil
	}
	return version, true, nil
}

// usesWorkloadExchange reports whether kagiSecret authenticates through the
// workload token exchange: the operator runs with --kagi-auth exchange and the
// object names no token Secret of its own.
func (r *KagiSecretReconciler) usesWorkloadExchange(kagiSecret *kagiv1alpha1.KagiSecret) bool {
	return r.WorkloadTokens != nil && kagiSecret.Spec.TokenSecret == nil
}

// errFolderPathUnderExchange refuses a KagiSecret the workload exchange cannot
// serve because it names its app by folder path only.
var errFolderPathUnderExchange = errors.New(folderPathUnderExchangeMessage)

// kagiClientFor builds the Kagi client of one reconcile. Under the workload
// exchange it authenticates each pair through r.WorkloadTokens; otherwise it
// uses the PAT resolveToken finds. When spec.Organization is set it is sent as
// an X-Organization-ID cross-check; the Kagi API rejects (403) the request if
// it does not match the token's bound org. Empty == use the token's org.
func (r *KagiSecretReconciler) kagiClientFor(ctx context.Context, kagiSecret *kagiv1alpha1.KagiSecret) (*kagi.Client, error) {
	opts := kagiClientOptions(kagiSecret.Spec.Organization)
	if r.usesWorkloadExchange(kagiSecret) {
		// The exchange can only be asked for an app id the object already has.
		if kagiSecret.Spec.AppID == "" {
			return nil, errFolderPathUnderExchange
		}
		return kagi.NewClient(r.KagiAPIURL, "", append(opts, kagi.WithTokenSource(r.WorkloadTokens))...), nil
	}
	token, err := r.resolveToken(ctx, kagiSecret)
	if err != nil {
		return nil, err
	}
	return kagi.NewClient(r.KagiAPIURL, token, opts...), nil
}

// failCredential records why no Kagi client could be built. A KagiSecret the
// exchange cannot serve is WorkloadTokenCannotResolve and is not retried: only a
// spec edit can fix it, and that edit triggers a reconcile. Any other failure is
// TokenResolutionFailed and backs off.
func (r *KagiSecretReconciler) failCredential(
	ctx context.Context, kagiSecret *kagiv1alpha1.KagiSecret, previous *kagiv1alpha1.KagiSecretStatus, err error,
) (ctrl.Result, error) {
	if errors.Is(err, errFolderPathUnderExchange) {
		setReadyCondition(&kagiSecret.Status.Conditions, kagiSecret.Generation, metav1.ConditionFalse, reasonWorkloadTokenCannotResolve, err.Error())
		kagiSecret.Status.LastErrorMessage = err.Error()
		if patchErr := r.patchStatusIfChanged(ctx, kagiSecret, previous); patchErr != nil {
			logf.FromContext(ctx).Error(patchErr, "Failed to update status")
			return ctrl.Result{}, patchErr
		}
		return ctrl.Result{}, nil
	}
	setReadyCondition(&kagiSecret.Status.Conditions, kagiSecret.Generation, metav1.ConditionFalse, reasonTokenResolutionFailed, err.Error())
	kagiSecret.Status.LastErrorMessage = err.Error()
	r.patchFailureStatus(ctx, kagiSecret, previous)
	return ctrl.Result{}, err
}

// failExchange records a failed read of the pair and returns the error, so the
// reconcile backs off through the failure rate limiter. A refused exchange is
// WorkloadAccessDenied with the pair and where the admin grants it, any other
// exchange failure TokenResolutionFailed, and every other error FetchFailed.
func (r *KagiSecretReconciler) failExchange(
	ctx context.Context, kagiSecret *kagiv1alpha1.KagiSecret, previous *kagiv1alpha1.KagiSecretStatus, appID string, err error,
) (ctrl.Result, error) {
	reason, message, ok := exchangeFailure(err, appID, kagiSecret.Spec.Environment)
	if !ok {
		reason, message = "FetchFailed", err.Error()
	}
	setReadyCondition(&kagiSecret.Status.Conditions, kagiSecret.Generation, metav1.ConditionFalse, reason, message)
	kagiSecret.Status.LastErrorMessage = message
	r.patchFailureStatus(ctx, kagiSecret, previous)
	return ctrl.Result{}, err
}

// isInjectedMode reports whether the CR delivers secrets via the injection
// webhook (mode: Injected) rather than by materializing a managed Secret. Any
// value other than the exact "Injected" string -- including the empty default --
// is Secret mode, preserving full backward compatibility.
func isInjectedMode(kagiSecret *kagiv1alpha1.KagiSecret) bool {
	return kagiSecret.Spec.Mode == modeInjected
}

// reconcileInjected handles the Injected delivery mode. It creates and manages
// no Kubernetes Secret at all: it reuses the cheap version probe and, on a
// version change, patches the secrets-version annotation onto the rollout
// targets to drive a health-gated rolling restart. The injected pods re-fetch
// their secrets from kagi-api at start.
func (r *KagiSecretReconciler) reconcileInjected(ctx context.Context, kagiSecret *kagiv1alpha1.KagiSecret, previousStatus *kagiv1alpha1.KagiSecretStatus, appID, version string, versionKnown bool) (ctrl.Result, error) {
	log := logf.FromContext(ctx)
	kagiSecret.Status.ResolvedAppID = appID

	// Without a working version probe we cannot detect a change, and Injected
	// mode deliberately never performs a decrypting fetch into the operator (a
	// fetch would reintroduce in-cluster persistence). Degrade gracefully: leave
	// running pods untouched, keep the resource Ready, and retry on the next
	// resync. This mirrors the Secret-mode always-fetch fallback minus the fetch.
	if !versionKnown {
		kagiSecret.Status.LastErrorMessage = ""
		setReadyCondition(&kagiSecret.Status.Conditions, kagiSecret.Generation, metav1.ConditionTrue, "VersionProbeUnavailable", "Injected mode: secrets version probe unavailable; no rollout evaluated")
		if err := r.patchStatusIfChanged(ctx, kagiSecret, previousStatus); err != nil {
			log.Error(err, "Failed to update status")
			return ctrl.Result{}, err
		}
		return ctrl.Result{RequeueAfter: r.requeueAfter(kagiSecret)}, nil
	}

	// On first observation we only record the version -- the injected pods are
	// presumed already current (they fetched at their own start), so adopting
	// Injected mode must not stampede the fleet with an immediate restart. Only a
	// subsequent change from a known-good version triggers a rollout.
	firstObservation := kagiSecret.Status.LastVersion == ""
	changed := version != kagiSecret.Status.LastVersion

	if changed && !firstObservation {
		if err := r.rolloutInjectedTargets(ctx, kagiSecret, version); err != nil {
			setReadyCondition(&kagiSecret.Status.Conditions, kagiSecret.Generation, metav1.ConditionFalse, "RolloutFailed", err.Error())
			kagiSecret.Status.LastErrorMessage = err.Error()
			r.patchFailureStatus(ctx, kagiSecret, previousStatus)
			return ctrl.Result{}, err
		}
		now := metav1.Now()
		kagiSecret.Status.LastRolloutTime = &now
		log.Info("Triggered rollout for injected secrets version change", "appId", appID, "environment", kagiSecret.Spec.Environment, "version", version)
	}

	kagiSecret.Status.LastVersion = version
	kagiSecret.Status.LastErrorMessage = ""
	setReadyCondition(&kagiSecret.Status.Conditions, kagiSecret.Generation, metav1.ConditionTrue, "InjectedSynced", "Injected mode: rollout targets tracking current secrets version")

	if err := r.patchStatusIfChanged(ctx, kagiSecret, previousStatus); err != nil {
		log.Error(err, "Failed to update status")
		return ctrl.Result{}, err
	}
	return ctrl.Result{RequeueAfter: r.requeueAfter(kagiSecret)}, nil
}

// rolloutInjectedTargets stamps the secrets-version annotation on every rollout
// target named or selected by spec.rollout, in the CR's effective namespace. A
// changed annotation on the pod template makes the Deployment controller perform
// a native, health-gated rolling restart. With no rollout configured this is a
// no-op: such pods rely on their own restart or kagi-init --watch-version.
func (r *KagiSecretReconciler) rolloutInjectedTargets(ctx context.Context, kagiSecret *kagiv1alpha1.KagiSecret, version string) error {
	rollout := kagiSecret.Spec.Rollout
	if rollout == nil {
		return nil
	}

	// Injected mode may omit managedSecret entirely, so derive the rollout
	// namespace from managedSecret only when present, otherwise from the CR.
	ns := kagiSecret.Namespace
	if kagiSecret.Spec.ManagedSecret != nil && kagiSecret.Spec.ManagedSecret.Namespace != "" {
		ns = kagiSecret.Spec.ManagedSecret.Namespace
	}

	patchedByName := make(map[string]struct{}, len(rollout.Deployments))
	for _, name := range rollout.Deployments {
		if name == "" {
			continue
		}
		var deployment appsv1.Deployment
		if err := r.Get(ctx, types.NamespacedName{Namespace: ns, Name: name}, &deployment); err != nil {
			return fmt.Errorf("failed to get rollout target deployment %s/%s: %w", ns, name, err)
		}
		if err := r.stampDeploymentVersion(ctx, &deployment, version); err != nil {
			return err
		}
		patchedByName[name] = struct{}{}
	}

	if rollout.WorkloadSelector != nil {
		selector, err := metav1.LabelSelectorAsSelector(rollout.WorkloadSelector)
		if err != nil {
			return fmt.Errorf("failed to parse rollout workloadSelector: %w", err)
		}
		var list appsv1.DeploymentList
		if err := r.List(ctx, &list, client.InNamespace(ns), client.MatchingLabelsSelector{Selector: selector}); err != nil {
			return fmt.Errorf("failed to list rollout targets by selector in namespace %s: %w", ns, err)
		}
		for i := range list.Items {
			deployment := &list.Items[i]
			if _, done := patchedByName[deployment.Name]; done {
				continue
			}
			if err := r.stampDeploymentVersion(ctx, deployment, version); err != nil {
				return err
			}
		}
	}
	return nil
}

// stampDeploymentVersion sets the secrets-version annotation on a Deployment's
// pod template and patches it. It is a no-op (no write, no rollout) when the
// annotation already equals version, so a retried reconcile does not restart the
// workload twice.
func (r *KagiSecretReconciler) stampDeploymentVersion(ctx context.Context, deployment *appsv1.Deployment, version string) error {
	if deployment.Spec.Template.Annotations[annotationSecretsVersion] == version {
		return nil
	}
	patch := client.MergeFrom(deployment.DeepCopy())
	if deployment.Spec.Template.Annotations == nil {
		deployment.Spec.Template.Annotations = map[string]string{}
	}
	deployment.Spec.Template.Annotations[annotationSecretsVersion] = version
	if err := r.Patch(ctx, deployment, patch); err != nil {
		return fmt.Errorf("failed to patch secrets-version annotation on deployment %s/%s: %w", deployment.Namespace, deployment.Name, err)
	}
	return nil
}

// managedSecretIntact reports whether the managed K8s Secret still exists, is
// owned by this KagiSecret (managed-by label + owner annotation naming it),
// carries a non-empty data-hash annotation AND its current data still hashes to
// that annotation. It gates the version-match skip: if the Secret was deleted,
// stripped of its hash, or had its data tampered with out-of-band, we must fetch
// and rebuild it rather than trust a matching upstream version. A Secret this
// KagiSecret does not own is never intact: an unclaimed one falls through to the
// write that adopts it, and any other is refused there. A genuine NotFound is
// not an error here -- it just means "not intact".
func (r *KagiSecretReconciler) managedSecretIntact(ctx context.Context, kagiSecret *kagiv1alpha1.KagiSecret) (bool, error) {
	var existing corev1.Secret
	if err := r.Get(ctx, managedSecretKey(kagiSecret), &existing); err != nil {
		if apierrors.IsNotFound(err) {
			return false, nil
		}
		return false, err
	}
	if classifySecretOwnership(&existing, managedSecretOwner(kindKagiSecret, kagiSecret)) != secretOwned {
		return false, nil
	}
	recordedHash := existing.Annotations[annotationHash]
	if recordedHash == "" {
		return false, nil
	}
	// Self-heal against out-of-band data edits: if the current data no longer
	// hashes to the recorded annotation, the Secret was tampered with and must
	// be rebuilt even though the upstream version is unchanged.
	if computeDataHashBytes(existing.Data) != recordedHash {
		return false, nil
	}
	return true, nil
}

// requeueAfter returns the steady-state resync delay for a KagiSecret with
// per-object jitter applied, so a large population of CRs does not resync in
// lockstep and stampede kagi-api.
func (r *KagiSecretReconciler) requeueAfter(kagiSecret *kagiv1alpha1.KagiSecret) time.Duration {
	return jitteredDuration(kagiSecretResyncInterval, kagiSecretResyncJitter, string(kagiSecret.UID)+kagiSecret.Namespace+"/"+kagiSecret.Name)
}

// jitteredDuration returns base offset by a deterministic amount in the range
// [-maxJitter, +maxJitter], derived from key. Determinism (a hash rather than a
// global RNG) keeps the offset stable across operator restarts and makes tests
// reproducible, while distinct keys still spread objects across a 2*maxJitter
// window -- the anti-thundering-herd property we want. base stays a parameter
// so the bounds tests state the window they check.
//
//nolint:unparam
func jitteredDuration(base, maxJitter time.Duration, key string) time.Duration {
	if maxJitter <= 0 {
		return base
	}
	// A 64-bit hash is required here: a 32-bit hash maxes out at ~4.3s in
	// nanoseconds, which is smaller than any realistic 2*maxJitter span, so the
	// modulo would never wrap and every offset would collapse into a few-second
	// band at -maxJitter instead of spreading across the full window.
	h := fnv.New64a()
	_, _ = h.Write([]byte(key))
	span := uint64(2*maxJitter) + 1
	offset := time.Duration(h.Sum64()%span) - maxJitter
	return base + offset
}

// patchFailureStatus records a failed reconcile on the CR status. A failed write is
// logged, not returned: the caller returns the reconcile error that caused the
// failure, and the requeue it triggers retries the status write as well.
func (r *KagiSecretReconciler) patchFailureStatus(
	ctx context.Context, kagiSecret *kagiv1alpha1.KagiSecret, previous *kagiv1alpha1.KagiSecretStatus,
) {
	if err := r.patchStatusIfChanged(ctx, kagiSecret, previous); err != nil {
		logf.FromContext(ctx).Error(err, "Failed to update status")
	}
}

// patchStatusIfChanged writes the CR status back only when it differs from the
// snapshot. Writing unconditionally bumps resourceVersion which, without a
// predicate, re-triggers reconcile and creates a self-inflicted hot loop.
func (r *KagiSecretReconciler) patchStatusIfChanged(ctx context.Context, kagiSecret *kagiv1alpha1.KagiSecret, previous *kagiv1alpha1.KagiSecretStatus) error {
	if equality.Semantic.DeepEqual(previous, &kagiSecret.Status) {
		return nil
	}
	return r.Status().Update(ctx, kagiSecret)
}

// resolveToken resolves the Kagi API token from the spec or defaults.
func (r *KagiSecretReconciler) resolveToken(ctx context.Context, kagiSecret *kagiv1alpha1.KagiSecret) (string, error) {
	// Try spec.tokenSecret first.
	if kagiSecret.Spec.TokenSecret != nil {
		ns := kagiSecret.Spec.TokenSecret.Namespace
		if ns == "" {
			ns = kagiSecret.Namespace
		}
		return r.readTokenFromSecret(ctx, kagiSecret.Spec.TokenSecret.Name, ns, "")
	}

	// Try default token secret.
	if r.DefaultTokenSecretName != "" {
		ns := r.DefaultTokenSecretNamespace
		if ns == "" {
			ns = kagiSecret.Namespace
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
func (r *KagiSecretReconciler) readTokenFromSecret(ctx context.Context, name, namespace, key string) (string, error) {
	var secret corev1.Secret
	if err := r.Get(ctx, types.NamespacedName{Name: name, Namespace: namespace}, &secret); err != nil {
		return "", fmt.Errorf("failed to read token secret %s/%s: %w", namespace, name, err)
	}
	return tokenFromSecret(&secret, key)
}

// resolveAppID determines the stable app ID to address secrets with. spec.appId
// is the primary, durable binding and is used verbatim when present. When it is
// absent, spec.folderPath is resolved to an app ID via the SDK (a one-time
// path -> id lookup that browses the folder's parent). At least one of the two
// fields is guaranteed present by the CRD's XValidation, but we guard here too.
func (r *KagiSecretReconciler) resolveAppID(ctx context.Context, kagiClient *kagi.Client, kagiSecret *kagiv1alpha1.KagiSecret) (string, error) {
	if kagiSecret.Spec.AppID != "" {
		return kagiSecret.Spec.AppID, nil
	}
	if kagiSecret.Spec.FolderPath == "" {
		return "", fmt.Errorf("neither spec.appId nor spec.folderPath is set")
	}
	appID, err := kagiClient.ResolveApp(ctx, kagiSecret.Spec.FolderPath)
	if err != nil {
		return "", fmt.Errorf("failed to resolve folderPath %q to an app ID: %w", kagiSecret.Spec.FolderPath, err)
	}
	return appID, nil
}

// fetchSecrets fetches secrets for a resolved app ID + environment slug via the
// SDK's app-id-addressed fetch route
// (/kagi/apps/{appId}/environments/{environmentSlug}/secrets/fetch).
func (r *KagiSecretReconciler) fetchSecrets(ctx context.Context, kagiClient *kagi.Client, appID, environment string) (map[string]string, error) {
	secrets, err := kagiClient.FetchSecrets(ctx, appID, environment)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch secrets: %w", err)
	}
	return secrets, nil
}

// managedSecretKey returns the name and namespace of a Secret-mode KagiSecret's
// managed Secret. spec.managedSecret.namespace is used as written: unlike
// KagiCertificate, KagiSecret does not fall back to its own namespace.
func managedSecretKey(kagiSecret *kagiv1alpha1.KagiSecret) types.NamespacedName {
	spec := kagiSecret.Spec.ManagedSecret
	return types.NamespacedName{Name: spec.Name, Namespace: spec.Namespace}
}

// managedSecretReference is the namespace reference of spec.managedSecret,
// which also places the Injected-mode rollout targets.
func managedSecretReference(kagiSecret *kagiv1alpha1.KagiSecret) secretReference {
	return secretReference{field: "spec.managedSecret.namespace", namespace: kagiSecret.Spec.ManagedSecret.Namespace}
}

// checkSecretReferences refuses a KagiSecret whose spec.managedSecret.type the
// operator does not write, or that names a token Secret or a managed Secret
// the KagiSecret may not reference; see checkManagedSecretType and the
// package-level checkSecretReferences.
func (r *KagiSecretReconciler) checkSecretReferences(kagiSecret *kagiv1alpha1.KagiSecret) error {
	refs := make([]secretReference, 0, 2)
	if kagiSecret.Spec.TokenSecret != nil {
		refs = append(refs, secretReference{field: "spec.tokenSecret.namespace", namespace: kagiSecret.Spec.TokenSecret.Namespace})
	}
	if kagiSecret.Spec.ManagedSecret != nil {
		if err := checkManagedSecretType(kagiSecret.Spec.ManagedSecret.Type); err != nil {
			return err
		}
		refs = append(refs, managedSecretReference(kagiSecret))
	}
	return checkSecretReferences(kagiSecret, kindKagiSecret, r.OperatorNamespace, refs...)
}

// managedSecretClaim returns what kagiSecret, bound to the resolved appID,
// claims about its managed Secret. An empty appID yields a claim without an
// identity, which adopts no Secret.
func (r *KagiSecretReconciler) managedSecretClaim(kagiSecret *kagiv1alpha1.KagiSecret, appID string) *managedSecretClaim {
	claim := &managedSecretClaim{
		kind:              kindKagiSecret,
		owner:             managedSecretOwner(kindKagiSecret, kagiSecret),
		namespace:         kagiSecret.Namespace,
		operatorNamespace: r.OperatorNamespace,
	}
	if appID != "" {
		claim.identity = map[string]string{
			labelAppID: appID,
			labelEnv:   kagiSecret.Spec.Environment,
		}
	}
	return claim
}

// reconcileManagedSecret creates or updates the managed K8s Secret. Returns
// true when the Secret was created or updated, so callers can decide whether
// to refresh LastSyncTime and emit a log line. A Secret this KagiSecret does
// not own is left untouched; see writeManagedSecret.
func (r *KagiSecretReconciler) reconcileManagedSecret(ctx context.Context, kagiSecret *kagiv1alpha1.KagiSecret, appID string, secrets map[string]string) (bool, error) {
	// Convert string map to byte map.
	secretData := make(map[string][]byte, len(secrets))
	for k, v := range secrets {
		secretData[k] = []byte(v)
	}

	return writeManagedSecret(ctx, r.Client, &desiredManagedSecret{
		key:        managedSecretKey(kagiSecret),
		claim:      r.managedSecretClaim(kagiSecret, appID),
		dataHash:   computeDataHash(secrets),
		data:       secretData,
		secretType: corev1.SecretType(kagiSecret.Spec.ManagedSecret.Type),
	})
}

// finalize releases the managed Secret of a KagiSecret that is being deleted
// and then removes the finalizer. When the release fails the finalizer stays
// and the error goes back to the rate limiter, so the deletion is retried
// instead of leaving behind a Secret nothing manages any more.
func (r *KagiSecretReconciler) finalize(ctx context.Context, ks *kagiv1alpha1.KagiSecret) error {
	if !controllerutil.ContainsFinalizer(ks, finalizerName) {
		return nil
	}
	// Injected mode never materializes a managed Secret, so there is
	// nothing to delete -- and issuing a delete on the name would remove
	// an unrelated Secret that happens to match ManagedSecret.Name.
	if !isInjectedMode(ks) {
		if err := r.cleanupManagedSecret(ctx, ks); err != nil {
			return err
		}
	}
	controllerutil.RemoveFinalizer(ks, finalizerName)
	return r.Update(ctx, ks)
}

// cleanupManagedSecret deletes the managed K8s Secret during CR deletion, when
// this KagiSecret owns it, or when an earlier release wrote it for the app ID
// in status.resolvedAppID and this KagiSecret could adopt it. A non-nil error
// means the finalizer must stay; see managedSecretRelease.release.
func (r *KagiSecretReconciler) cleanupManagedSecret(ctx context.Context, kagiSecret *kagiv1alpha1.KagiSecret) error {
	// A Secret-mode CR without a managedSecret never materialized one, so there
	// is nothing to clean up (and no name to safely target).
	if kagiSecret.Spec.ManagedSecret == nil {
		return nil
	}
	release := &managedSecretRelease{
		reader:            liveReader(r.APIReader, r.Client),
		writer:            r.Client,
		recorder:          r.Recorder,
		operatorNamespace: r.OperatorNamespace,
	}
	claim := r.managedSecretClaim(kagiSecret, kagiSecret.Status.ResolvedAppID)
	return release.release(ctx, kagiSecret, claim, managedSecretKey(kagiSecret), managedSecretReference(kagiSecret))
}

// setReadyCondition sets the Ready condition on a conditions slice. It does
// not stamp LastTransitionTime explicitly -- meta.SetStatusCondition preserves
// the old timestamp when the Status field is unchanged, which keeps status
// diffs stable across no-op reconciles. Exported as a package-level helper so
// both controllers (KagiSecret, KagiCertificate) share the same behavior.
func setReadyCondition(conditions *[]metav1.Condition, generation int64, status metav1.ConditionStatus, reason, message string) {
	meta.SetStatusCondition(conditions, metav1.Condition{
		Type:               "Ready",
		Status:             status,
		ObservedGeneration: generation,
		Reason:             reason,
		Message:            message,
	})
}

// kagiClientOptions builds the SDK client options for a CR's configured
// organization. When organization is empty it returns no options, so the client
// sends no X-Organization-ID header and the request behaves exactly as it did
// before multi-org (the org is resolved from the PAT). When set, the org UUID is
// sent as a cross-check that must match the PAT's bound org or the API returns
// 403. Shared by both reconcilers (KagiSecret, KagiCertificate).
func kagiClientOptions(organization string) []kagi.Option {
	if organization == "" {
		return nil
	}
	return []kagi.Option{kagi.WithOrganization(organization)}
}

// computeDataHashBytes computes the SHA256 data hash over a Secret's raw
// map[string][]byte data by reusing computeDataHash, so the tamper-detection
// path in managedSecretIntact hashes with the exact same algorithm used when the
// annotation is written in reconcileManagedSecret.
func computeDataHashBytes(data map[string][]byte) string {
	secrets := make(map[string]string, len(data))
	for k, v := range data {
		secrets[k] = string(v)
	}
	return computeDataHash(secrets)
}

// computeDataHash computes a SHA256 hash of the secret data for change detection.
func computeDataHash(secrets map[string]string) string {
	// Sort keys for deterministic hashing.
	keys := make([]string, 0, len(secrets))
	for k := range secrets {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	h := sha256.New()
	for _, k := range keys {
		h.Write([]byte(k))
		h.Write([]byte("="))
		h.Write([]byte(secrets[k]))
		h.Write([]byte("\n"))
	}
	return fmt.Sprintf("%x", h.Sum(nil))
}

// SetupWithManager sets up the controller with the Manager.
//
// The event filter is the fix for the status-update feedback loop that was
// saturating kagi-api at ~6 req/s. The default watch reconciles on every
// resourceVersion bump, including our own r.Status().Update calls. By
// filtering to only Generation/Annotation/Label changes, status-only writes
// are dropped and periodic resyncs are driven solely by RequeueAfter.
//
// Generic+Create+Delete events are kept (the predicate.Or default passes
// those through); the filter only affects Update events.
//
// The rate limiter replaces controller-runtime's 5ms-based default so that an
// object whose reconcile fails backs off from FailureBackoffBase instead of
// retrying roughly ten times in its first five seconds. It only governs error
// retries; the RequeueAfter resync and the post-finalizer requeue are
// unaffected.
func (r *KagiSecretReconciler) SetupWithManager(mgr ctrl.Manager) error {
	rateLimiter, err := newFailureRateLimiter(r.FailureBackoffBase, r.FailureBackoffMax)
	if err != nil {
		return fmt.Errorf("configure KagiSecret retry backoff: %w", err)
	}
	return ctrl.NewControllerManagedBy(mgr).
		For(&kagiv1alpha1.KagiSecret{}).
		WithEventFilter(predicate.Or(
			predicate.GenerationChangedPredicate{},
			predicate.AnnotationChangedPredicate{},
			predicate.LabelChangedPredicate{},
		)).
		WithOptions(controller.Options{
			MaxConcurrentReconciles: r.MaxConcurrentReconciles,
			RateLimiter:             rateLimiter,
		}).
		Named("kagisecret").
		Complete(r)
}
