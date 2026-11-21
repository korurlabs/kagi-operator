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

// Package certs makes the operator own the TLS serving certificate of its
// pod-injection mutating webhook, so nobody has to install, configure, or renew
// one. It is the same pattern Istio, OPA Gatekeeper and cert-manager's own
// webhook use, and it deliberately replaces the two paths the chart used to
// offer:
//
//   - cert-manager, which was an undeclared hard dependency: `helm install`
//     failed on clusters without it, and the released install.yaml only
//     partially applied, leaving a failurePolicy: Fail
//     MutatingWebhookConfiguration with an empty caBundle and no operator
//     running -- which made every pod labeled kagi.pw/inject: "true"
//     un-creatable.
//   - Helm's genSelfSignedCert + lookup, which works under real Helm but not
//     under `helm template` (ArgoCD/Flux), where lookup always returns empty
//     and every render therefore minted a fresh keypair -- permanent OutOfSync
//     plus a window where the caBundle and the served cert disagree.
//
// The cert lifecycle is delegated to github.com/open-policy-agent/cert-controller
// (what Gatekeeper runs): it owns a CA + leaf keypair in a Secret in the
// operator's own namespace, patches the caBundle onto every webhook entry of
// the MutatingWebhookConfiguration, re-checks on an interval and rotates ahead
// of expiry. The Secret is the shared source of truth, so multiple operator
// replicas converge instead of corrupting each other.
//
// What this package adds on top is the startup ordering and the loud failure
// paths cert-controller does not provide:
//
//   - EnsureCertSecret creates the Secret when it is absent (cert-controller
//     only ever Updates an existing one, and errors out at startup otherwise).
//   - AwaitWebhookCABundle blocks until the caBundle the API server will use
//     actually matches the CA the operator wrote, and fails loudly on timeout.
//     cert-controller's own readiness signal reports "injected" even when the
//     named MutatingWebhookConfiguration does not exist at all, so a typo'd
//     --mutating-webhook-name would otherwise silently leave a fail-closed
//     webhook with an empty caBundle.
//
// There is one opt-in escape hatch, for organizations whose policy mandates
// that every in-cluster certificate chain to their own PKI. Setting
// Options.UserSuppliedCertificate (chart: injection.existingCertSecret,
// flag: --webhook-cert-managed=false) makes the operator consume a
// user-supplied certificate Secret instead: it generates nothing, rotates
// nothing, and never writes to that Secret. It still publishes the caBundle --
// from THEIR ca.crt -- because admission cannot work otherwise, and it keeps
// republishing on an interval so their own rotation does not silently strand a
// stale caBundle. See CABundleSyncer. Everything about the default path is
// unchanged by that option existing.
package certs

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"sync"
	"time"

	"github.com/open-policy-agent/cert-controller/pkg/rotator"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/retry"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"
)

// DefaultCertDir is controller-runtime's compiled-in webhook CertDir. The
// operator defaults --webhook-cert-path to it when pod injection is enabled so
// a bare `--enable-pod-injection=true` is a working configuration.
const DefaultCertDir = "/tmp/k8s-webhook-server/serving-certs"

// Secret keys. caCertKey is what cert-controller writes the CA certificate to,
// and the value that must end up verbatim in every webhook entry's
// clientConfig.caBundle. All three are REQUIRED of a user-supplied certificate
// Secret on the unmanaged path -- a Secret missing any of them is rejected at
// startup rather than allowed to produce a fail-closed webhook with an empty
// caBundle.
const (
	caCertKey  = "ca.crt"
	caKeyKey   = "ca.key"
	tlsCertKey = "tls.crt"
	tlsKeyKey  = "tls.key"
)

// caName is the CommonName (and sole DNS name) of the self-signed CA the
// operator mints. It never leaves the cluster and is only ever used to sign the
// webhook's leaf cert, so its name is cosmetic -- but it is what shows up in
// `openssl x509 -text` when someone debugs an admission TLS failure.
const caName = "kagi-operator-ca"

// caOrganization is the O= field of the self-signed CA.
const caOrganization = "kagi.pw"

// fieldOwner identifies the operator as the field manager of the caBundle it
// patches, so a `kubectl get mutatingwebhookconfiguration -o yaml
// --show-managed-fields` makes it obvious who owns that field.
const fieldOwner = "kagi-operator"

// Poll cadence and log cadence for AwaitWebhookCABundle. The poll is cheap (two
// Gets) but the log line is noisy, so they are deliberately different.
const (
	caBundlePollInterval = 2 * time.Second
	caBundleLogInterval  = 30 * time.Second
)

// unmanagedSyncInterval is how often the unmanaged (bring-your-own-certificate)
// path re-reads the supplied Secret and re-publishes its ca.crt to the
// MutatingWebhookConfiguration.
//
// An external PKI rotates on its own schedule and updates the Secret underneath
// us with no notification. Treating that Secret as static is how you get a
// stale caBundle and a fail-closed admission outage weeks after the change that
// caused it. One minute bounds the exposure; the cost is two Gets a minute, and
// a re-Update only happens when ca.crt actually differs. Note that the common
// case -- a new leaf signed by the SAME CA -- does not change ca.crt at all and
// needs no patch: the kubelet reprojects the Secret and controller-runtime's
// cert watcher reloads the leaf on its own.
const unmanagedSyncInterval = time.Minute

// Certificate lifetimes for the operator-managed path. Pinned here rather than
// inherited from cert-controller's defaults (10y CA, 1y leaf, 90d lookahead,
// 12h check) so the operator's crypto posture is visible in this tree and does
// not shift on a dependency bump.
//
// A 90-day leaf renewed 30 days out means a rotation roughly every 60 days --
// frequent enough that the rotation path stays exercised rather than being a
// once-a-year surprise, and short enough to bound the damage from a leaked key.
// The CA outlives it by years because rotating the CA is the disruptive half
// (it invalidates the published caBundle until the new one lands).
const (
	caCertDuration         = 5 * 365 * 24 * time.Hour
	serverCertDuration     = 90 * 24 * time.Hour
	rotationLookahead      = 30 * 24 * time.Hour
	rotationCheckFrequency = 12 * time.Hour
)

// Options describes the certificate the operator issues to itself and the
// objects it has to keep in sync with it. Every field is required: there is no
// defaulting here, because a silently defaulted Secret/Service/webhook name
// would resolve to an object that does not exist and produce exactly the
// fail-closed-with-empty-caBundle outage this package exists to prevent.
type Options struct {
	// Namespace is the operator's own namespace (Downward API POD_NAMESPACE).
	// The cert Secret lives here, and it is half of the webhook Service's DNS
	// name.
	Namespace string
	// SecretName is the Secret holding the CA + leaf keypair
	// (--webhook-cert-secret). It is the shared source of truth across
	// replicas and across restarts.
	SecretName string
	// ServiceName is the Service fronting the webhook server
	// (--webhook-service-name). It determines the leaf certificate's SANs.
	ServiceName string
	// MutatingWebhookName is the MutatingWebhookConfiguration whose entries get
	// the caBundle patched (--mutating-webhook-name).
	MutatingWebhookName string
	// CertDir is the directory controller-runtime's webhook server reads the
	// serving cert from (--webhook-cert-path). The cert Secret is mounted here,
	// and cert-controller waits for the kubelet to project it before reporting
	// ready.
	CertDir string
	// CABundleWaitTimeout bounds how long AwaitWebhookCABundle waits for the
	// caBundle to converge before giving up (and, at the call site, exiting).
	CABundleWaitTimeout time.Duration
	// UserSuppliedCertificate opts out of operator-managed certificates
	// (--webhook-cert-managed=false, chart: injection.existingCertSecret).
	//
	// Deliberately phrased so the ZERO VALUE is the safe, default path: a
	// caller who forgets this field gets operator-managed certificates, not a
	// silent expectation that somebody else populated the Secret.
	//
	// false (default): the operator issues the certificate, writes it to
	// SecretName, and rotates it ahead of expiry.
	//
	// true: SecretName names a certificate the USER supplied, typically issued
	// by an organization's internal PKI because policy requires every
	// in-cluster certificate to chain to their own CA. The operator then
	// generates nothing, rotates nothing, and NEVER writes to that Secret -- it
	// only reads it and keeps the MutatingWebhookConfiguration's caBundle in
	// sync with the supplied ca.crt. Rotation is the user's responsibility;
	// keeping admission working across their rotation is ours.
	UserSuppliedCertificate bool
}

// caPolicy selects how strictly this deployment's ca.crt is judged. The managed
// path can demand exactly one certificate because the operator minted it; a
// user-supplied bundle legitimately carries a chain.
func (o Options) caPolicy() caPolicy {
	if o.UserSuppliedCertificate {
		return caPolicyUserSupplied
	}
	return caPolicyOperatorIssued
}

// Mode is a human-readable description of who owns the certificate, for log
// lines where "managed" vs "user-supplied" is the first thing you want to know.
func (o Options) Mode() string {
	if o.UserSuppliedCertificate {
		return "user-supplied"
	}
	return "operator-managed"
}

// Validate reports the first missing field. Callers are expected to turn the
// error into a startup failure rather than proceeding with a partial config.
func (o Options) Validate() error {
	switch {
	case o.Namespace == "":
		return fmt.Errorf("webhook cert bootstrap requires the operator's own namespace: " +
			"expose it via the Downward API as POD_NAMESPACE")
	case o.SecretName == "":
		return fmt.Errorf("webhook cert bootstrap requires a Secret name (--webhook-cert-secret)")
	case o.ServiceName == "":
		return fmt.Errorf("webhook cert bootstrap requires the webhook Service name (--webhook-service-name)")
	case o.MutatingWebhookName == "":
		return fmt.Errorf("webhook cert bootstrap requires the MutatingWebhookConfiguration name (--mutating-webhook-name)")
	case o.CertDir == "":
		return fmt.Errorf("webhook cert bootstrap requires a certificate directory (--webhook-cert-path)")
	case o.CABundleWaitTimeout <= 0:
		return fmt.Errorf("webhook cert bootstrap requires a positive caBundle wait timeout, got %s", o.CABundleWaitTimeout)
	}
	return nil
}

// SecretKey is the cert Secret's namespaced name.
func (o Options) SecretKey() types.NamespacedName {
	return types.NamespacedName{Namespace: o.Namespace, Name: o.SecretName}
}

// DNSName is the primary SAN: the in-cluster name the API server dials, and the
// name cert-controller validates the leaf against when deciding whether it
// still matches the current configuration.
func (o Options) DNSName() string {
	return fmt.Sprintf("%s.%s.svc", o.ServiceName, o.Namespace)
}

// ExtraDNSNames are the additional SANs baked into the leaf certificate. The
// fully qualified form is included because a cluster may be configured to dial
// the webhook by it.
func (o Options) ExtraDNSNames() []string {
	return []string{fmt.Sprintf("%s.%s.svc.cluster.local", o.ServiceName, o.Namespace)}
}

// The rotator's informer needs collection verbs on MutatingWebhookConfigurations,
// which cannot be restricted by name -- list and watch have no resourceNames.
//
// The WRITE verbs deliberately are NOT declared here. Cluster-wide update on
// this resource is a cluster-takeover primitive: anyone who can run a pod in the
// operator's namespace could mount its ServiceAccount token and rewrite ANY
// webhook in the cluster (rules: */*, empty objectSelector, clientConfig
// pointing at their own pod) -- including other vendors' webhooks. The operator
// only ever writes its OWN object, so get and update are granted separately,
// restricted with resourceNames, in config/rbac/webhook_scope_patch.yaml and in
// the chart's templates/rbac.yaml. controller-gen cannot emit resourceNames,
// which is why they live outside this marker.
//
// patch is not granted at all: every write on both paths is a full Get+Update
// (cert-controller's ReconcileWH.ensureCerts, and CABundleSyncer.SyncOnce).
// +kubebuilder:rbac:groups=admissionregistration.k8s.io,resources=mutatingwebhookconfigurations,verbs=list;watch

// The cert Secret itself is covered by the operator's existing cluster-wide
// Secret rule (create/delete/get/list/patch/update/watch, declared on the
// KagiSecret reconciler), so no extra namespaced Role is generated for it.

// ManagedCertMonitor records a Warning Event when it finds the certificate
// Secret tampered with. The chart already granted this; the marker exists so
// the kustomize-generated role.yaml (and therefore dist/install.yaml) grants it
// too -- it previously did not, so an Event would have been silently dropped
// there.
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch

// EnsureCertSecret makes sure the cert Secret exists before the rotator starts.
//
// cert-controller only ever Updates the Secret -- its first refresh does a Get
// and returns an error when the Secret is absent, which takes the whole manager
// down. Creating it here (empty; the rotator fills in ca.crt/ca.key/tls.crt/
// tls.key) is what lets a fresh install converge without anyone pre-creating
// anything.
//
// A concurrent replica winning the create race is not an error: the Secret is
// the shared source of truth and whichever replica created it wrote the same
// empty shell.
func EnsureCertSecret(ctx context.Context, c client.Client, key types.NamespacedName) error {
	existing := &corev1.Secret{}
	err := c.Get(ctx, key, existing)
	if err == nil {
		return nil
	}
	if !apierrors.IsNotFound(err) {
		return fmt.Errorf("failed to read webhook cert Secret %s: %w", key, err)
	}

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      key.Name,
			Namespace: key.Namespace,
			Labels: map[string]string{
				"app.kubernetes.io/managed-by": fieldOwner,
			},
		},
		// Opaque rather than kubernetes.io/tls: the Secret starts empty and
		// kubernetes.io/tls would reject it for missing tls.crt/tls.key. An
		// already-existing Secret (e.g. left behind by the old cert-manager or
		// genSelfSignedCert path) keeps whatever type it has -- Secret.type is
		// immutable, and the rotator only ever writes data keys.
		Type: corev1.SecretTypeOpaque,
	}
	if err := c.Create(ctx, secret); err != nil {
		if apierrors.IsAlreadyExists(err) {
			return nil
		}
		return fmt.Errorf("failed to create webhook cert Secret %s: %w", key, err)
	}
	return nil
}

// ValidateSuppliedCertSecret checks that a user-supplied certificate Secret
// carries all three keys the webhook needs and returns its ca.crt.
//
// A half-populated Secret is rejected here, loudly and by name, rather than
// tolerated: a Secret with tls.crt but no ca.crt would leave the operator
// serving TLS behind a MutatingWebhookConfiguration with an empty caBundle,
// which -- with failurePolicy: Fail -- makes every pod labeled
// kagi.pw/inject: "true" un-creatable. Refusing to start is the only safe
// answer, and it puts the cause in the operator's logs instead of in a confused
// bug report about pods that will not schedule.
// Beyond presence, the material is actually verified: tls.crt and tls.key must
// be a real keypair, tls.crt must chain to ca.crt as a server certificate, and
// it must be currently valid for the webhook Service's DNS name. Presence alone
// would let a Secret whose ca.crt is an UNRELATED CA be published verbatim into
// the API server's trust store -- which, since the docs invite delegating write
// access to this Secret, hands admission control over every injected pod to
// whoever can write it. It also catches the mistake a bring-your-own user is
// most likely to make: getting the <svc>.<ns>.svc name wrong, which otherwise
// produces a healthy-looking operator and silently broken admission.
func ValidateSuppliedCertSecret(secret *corev1.Secret, key types.NamespacedName, dnsName string) ([]byte, error) {
	for _, required := range []string{tlsCertKey, tlsKeyKey, caCertKey} {
		if len(secret.Data[required]) == 0 {
			return nil, fmt.Errorf("user-supplied webhook certificate Secret %s is missing required key %q "+
				"(it must carry %q, %q and %q; %q is the CA the API server is told to trust)",
				key, required, tlsCertKey, tlsKeyKey, caCertKey, caCertKey)
		}
	}

	if err := verifyServingCert(secret.Data[tlsCertKey], secret.Data[tlsKeyKey], secret.Data[caCertKey],
		dnsName, caPolicyUserSupplied); err != nil {
		return nil, fmt.Errorf("user-supplied webhook certificate Secret %s is not usable: %w", key, err)
	}
	return secret.Data[caCertKey], nil
}

// LoadSuppliedCertSecret reads and verifies a user-supplied certificate Secret,
// returning the ca.crt that is safe to publish as the caBundle. Used both at
// startup -- so a missing or bogus Secret fails the operator immediately instead
// of at first admission -- and on every sync, so a post-startup swap of the
// Secret's contents is caught rather than trusted.
func LoadSuppliedCertSecret(ctx context.Context, reader client.Reader, key types.NamespacedName, dnsName string) ([]byte, error) {
	secret := &corev1.Secret{}
	if err := reader.Get(ctx, key, secret); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, fmt.Errorf("user-supplied webhook certificate Secret %s does not exist: create it "+
				"(type kubernetes.io/tls, with %q, %q and %q) before enabling injection, or unset "+
				"injection.existingCertSecret to let the operator issue its own", key, tlsCertKey, tlsKeyKey, caCertKey)
		}
		return nil, fmt.Errorf("failed to read user-supplied webhook certificate Secret %s: %w", key, err)
	}
	return ValidateSuppliedCertSecret(secret, key, dnsName)
}

// CABundleSyncer publishes a user-supplied CA to the MutatingWebhookConfiguration
// and keeps it there. It is the unmanaged path's replacement for the rotator: it
// generates nothing, rotates nothing, and never writes to the certificate
// Secret.
type CABundleSyncer struct {
	client    client.Client
	opts      Options
	interval  time.Duration
	ready     chan struct{}
	readyOnce sync.Once
}

var _ manager.Runnable = &CABundleSyncer{}
var _ manager.LeaderElectionRunnable = &CABundleSyncer{}

// NewCABundleSyncer builds the syncer. ready is closed after the first
// successful publish, mirroring the rotator's IsReady contract so the caller can
// gate webhook registration on either path identically.
func NewCABundleSyncer(c client.Client, opts Options, ready chan struct{}) *CABundleSyncer {
	return &CABundleSyncer{client: c, opts: opts, interval: unmanagedSyncInterval, ready: ready}
}

// NeedLeaderElection reports false. The syncer closes the ready channel that
// gates webhook registration, so a non-leader replica that never ran it would
// block on that channel forever and never serve admission at all.
func (s *CABundleSyncer) NeedLeaderElection() bool { return false }

// Start publishes the supplied CA immediately, then re-publishes on an interval
// for as long as the manager runs.
//
// The FIRST publish failing is fatal -- it means the configuration is wrong and
// admission would never work, so the operator should die visibly rather than
// linger. Later failures are logged at error level and retried instead: by then
// the API server already holds a working caBundle, so admission keeps
// functioning, and killing the operator over a transient API error would be a
// worse outcome than a loud log line and another attempt a minute later.
func (s *CABundleSyncer) Start(ctx context.Context) error {
	log := logf.FromContext(ctx).WithName("webhook-cert-bundle-syncer")

	if err := s.SyncOnce(ctx); err != nil {
		return fmt.Errorf("failed to publish the user-supplied webhook CA bundle: %w", err)
	}
	log.Info("Published user-supplied webhook CA bundle",
		"secret", s.opts.SecretKey().String(),
		"mutatingWebhookConfiguration", s.opts.MutatingWebhookName)
	s.readyOnce.Do(func() { close(s.ready) })

	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if err := s.SyncOnce(ctx); err != nil {
				// Never swallowed: the current caBundle still works, but the
				// next rotation of their PKI will break admission if this keeps
				// failing, so it has to be visible now.
				log.Error(err, "Failed to re-publish the user-supplied webhook CA bundle; "+
					"the caBundle may go stale when your PKI next rotates the CA",
					"secret", s.opts.SecretKey().String(),
					"mutatingWebhookConfiguration", s.opts.MutatingWebhookName)
			}
		}
	}
}

// SyncOnce re-verifies the supplied Secret and, when its ca.crt differs from
// what the MutatingWebhookConfiguration currently advertises, updates every
// webhook entry to match. It is a no-op write-wise when already in sync, so the
// steady state costs two Gets and no API writes. It never writes to the Secret.
//
// The Secret is re-verified on EVERY sync, not just at startup: validating only
// once would let someone swap the Secret's contents afterwards and have an
// unrelated CA published into the API server's trust store within a minute. On a
// verification failure the caBundle is deliberately left untouched -- the
// currently published CA still works, so refusing the change is strictly safer
// than applying an unverified one.
func (s *CABundleSyncer) SyncOnce(ctx context.Context) error {
	ca, err := LoadSuppliedCertSecret(ctx, s.client, s.opts.SecretKey(), s.opts.DNSName())
	if err != nil {
		return fmt.Errorf("refusing to publish an unverified CA bundle: %w", err)
	}

	// Read-modify-write against an object ArgoCD, another replica, or a human
	// may touch concurrently, so a 409 is expected rather than exceptional --
	// and Start treats a first-sync failure as fatal, which would otherwise turn
	// a routine conflict into a crash at startup.
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		webhookConfig := &admissionregistrationv1.MutatingWebhookConfiguration{}
		if err := s.client.Get(ctx, types.NamespacedName{Name: s.opts.MutatingWebhookName}, webhookConfig); err != nil {
			return fmt.Errorf("failed to read MutatingWebhookConfiguration %q to publish the CA bundle: %w",
				s.opts.MutatingWebhookName, err)
		}
		if len(webhookConfig.Webhooks) == 0 {
			return fmt.Errorf("MutatingWebhookConfiguration %q declares no webhook entries to publish a CA bundle to",
				s.opts.MutatingWebhookName)
		}

		changed := false
		for i := range webhookConfig.Webhooks {
			if !bytes.Equal(webhookConfig.Webhooks[i].ClientConfig.CABundle, ca) {
				webhookConfig.Webhooks[i].ClientConfig.CABundle = ca
				changed = true
			}
		}
		if !changed {
			return nil
		}

		if err := s.client.Update(ctx, webhookConfig, client.FieldOwner(fieldOwner)); err != nil {
			// Returned unwrapped so RetryOnConflict can recognise a 409;
			// wrapping it would defeat the retry.
			if apierrors.IsConflict(err) {
				return err
			}
			return fmt.Errorf("failed to publish the CA bundle to MutatingWebhookConfiguration %q: %w",
				s.opts.MutatingWebhookName, err)
		}
		return nil
	})
}

// Setup registers the certificate rotator with the manager. The rotator
// bootstraps the CA + leaf keypair into the cert Secret, keeps the
// MutatingWebhookConfiguration's caBundle in sync with it, and rotates ahead of
// expiry on a timer. ready is closed once the certs are present in CertDir and
// the rotator believes the CA has been injected -- callers MUST gate webhook
// handler registration on it (plus AwaitWebhookCABundle) so the operator never
// serves on a certificate the API server will not trust.
//
// Leader election is deliberately NOT required, and the reason is narrower than
// it looks: IsReady is closed only by the rotator's own Start, so a replica that
// never ran it would block on that channel forever and never register the
// webhook. (It is NOT because replicas need to write their own CertDir -- the
// rotator never writes CertDir at all; the kubelet projects the Secret there and
// the rotator only polls for the file to appear.)
//
// The multi-replica write path is honest but not elegant: replicas contend on
// the Secret with optimistic concurrency, and a loser re-reads through its own
// informer cache, which may still be stale, so it can mint a fresh CA on each of
// its ~10 backoff retries before settling. RestartOnSecretRefresh below bounds
// the damage by taking each writer out immediately, and the readiness gate in
// cmd/main.go keeps a replica out of the Service until what it serves actually
// matches what it published. replicaCount stays 1 by default.
func Setup(mgr ctrl.Manager, opts Options, ready chan struct{}) error {
	if err := opts.Validate(); err != nil {
		return err
	}

	// Unmanaged: the certificate belongs to the user's PKI. Skip the rotator
	// entirely -- it would generate a keypair and overwrite their Secret -- and
	// run only the publisher that keeps the caBundle tracking their ca.crt.
	// An uncached client so a read always reflects what their PKI just wrote.
	if opts.UserSuppliedCertificate {
		c, err := client.New(mgr.GetConfig(), client.Options{Scheme: mgr.GetScheme()})
		if err != nil {
			return fmt.Errorf("failed to build a client to publish the user-supplied CA bundle: %w", err)
		}
		return mgr.Add(NewCABundleSyncer(c, opts, ready))
	}

	// Watches the Secret the operator owns and repairs it if it is tampered
	// with. It is started ALONGSIDE the rotator, not before it -- registration
	// order buys nothing, because controller-runtime starts non-leader-election
	// runnables concurrently -- but it checks immediately on start rather than
	// waiting out its interval, so a poisoned Secret is normally repaired before
	// the readiness gate is reached rather than after the gate has timed out.
	//
	// The gate does not depend on winning that race: caBundleMatches enforces
	// the same ca.crt/ca.key rule the monitor does, so a Secret the monitor has
	// not got to yet holds the gate shut instead of slipping through it.
	monitorClient, err := client.New(mgr.GetConfig(), client.Options{Scheme: mgr.GetScheme()})
	if err != nil {
		return fmt.Errorf("failed to build a client for the webhook certificate monitor: %w", err)
	}
	// The monitor emits core/v1 Events through record.EventRecorder, which the
	// operator's RBAC grants. The events.k8s.io recorder that replaces
	// GetEventRecorderFor has a different interface and needs its own RBAC rule.
	recorder := mgr.GetEventRecorderFor("kagi-operator-cert-monitor") //nolint:staticcheck
	if err := mgr.Add(NewManagedCertMonitor(monitorClient, recorder, opts)); err != nil {
		return fmt.Errorf("failed to register the webhook certificate monitor: %w", err)
	}

	return rotator.AddRotator(mgr, &rotator.CertRotator{
		SecretKey:      opts.SecretKey(),
		CertDir:        opts.CertDir,
		CAName:         caName,
		CAOrganization: caOrganization,
		DNSName:        opts.DNSName(),
		ExtraDNSNames:  opts.ExtraDNSNames(),
		IsReady:        ready,
		Webhooks: []rotator.WebhookInfo{{
			Name: opts.MutatingWebhookName,
			Type: rotator.Mutating,
		}},
		FieldOwner:            fieldOwner,
		RequireLeaderElection: false,

		// Pinned rather than left to the library's defaults (10y CA, 1y leaf,
		// 90d lookahead, 12h check). Those are reasonable, but leaving them
		// implicit means the operator's certificate lifetimes are invisible in
		// this tree and can change under us on a dependency bump.
		CaCertDuration:         caCertDuration,
		ServerCertDuration:     serverCertDuration,
		LookaheadInterval:      rotationLookahead,
		RotationCheckFrequency: rotationCheckFrequency,

		// Exit as soon as the Secret is rewritten, so the kubelet reprojects and
		// the process comes back up reading the new material.
		//
		// Without this the process keeps serving the PREVIOUS leaf out of its
		// projected volume -- up to a minute behind -- while the caBundle has
		// already been patched to the new CA, so the API server rejects the
		// handshake and, with failurePolicy: Fail, labeled pods cannot be
		// created. Restarting does not shorten the kubelet's projection delay,
		// but it stops the pod from claiming Ready while serving a certificate
		// nothing trusts: the readiness gate in cmd/main.go only lets it back
		// into the Service once the on-disk leaf verifies against the published
		// CA. Costs one restart on a fresh install, when the first keypair is
		// minted -- expected, not a crash.
		RestartOnSecretRefresh: true,
	})
}

// AwaitWebhookCABundle blocks until the webhook is genuinely serveable: every
// entry of the MutatingWebhookConfiguration advertises the CA from the cert
// Secret, AND the certificate on disk actually chains to that CA and covers the
// Service's DNS name. It gives up after the configured timeout.
//
// This is the check cert-controller does not do. Its readiness signal flips to
// "CA injected" even when the named MutatingWebhookConfiguration was never
// found (a missing webhook is logged and skipped, not treated as a failure), so
// without this the operator would happily serve while the API server holds a
// fail-closed webhook with an empty caBundle -- exactly the outage this whole
// change exists to eliminate. Reads are intentionally uncached so the result
// reflects what the API server will actually enforce.
//
// Comparing the two byte strings is deliberately NOT enough. It passes when
// ca.crt, tls.crt, tls.key and the caBundle are all set to the same
// non-certificate string, and on the user-supplied path it is tautological
// anyway -- the syncer would just be comparing its own write against itself.
// Verifying the served material against the published CA is what actually
// answers the question "will the API server complete this handshake", and it is
// what makes the certificate rotation window safe: the check keeps failing
// while the kubelet still has the previous leaf projected.
//
// The returned error names the last observed reason so the operator's crash
// message is actionable (wrong --mutating-webhook-name is the likely cause).
func AwaitWebhookCABundle(ctx context.Context, reader client.Reader, opts Options) error {
	if err := opts.Validate(); err != nil {
		return err
	}

	log := logf.FromContext(ctx).WithName("webhook-cert-bootstrap")
	deadline := time.Now().Add(opts.CABundleWaitTimeout)
	lastLogged := time.Now()

	for {
		ok, reason := caBundleMatches(ctx, reader, opts)
		if ok {
			log.Info("Webhook CA bundle is in sync with the operator-issued certificate",
				"mutatingWebhookConfiguration", opts.MutatingWebhookName, "secret", opts.SecretKey().String())
			return nil
		}

		remaining := time.Until(deadline)
		if remaining <= 0 {
			return fmt.Errorf("MutatingWebhookConfiguration %q caBundle did not converge with the CA in Secret %s "+
				"within %s: %s (check --mutating-webhook-name and the operator's "+
				"admissionregistration.k8s.io RBAC)",
				opts.MutatingWebhookName, opts.SecretKey(), opts.CABundleWaitTimeout, reason)
		}

		if time.Since(lastLogged) >= caBundleLogInterval {
			log.Info("Waiting for the webhook CA bundle to be reconciled",
				"mutatingWebhookConfiguration", opts.MutatingWebhookName, "reason", reason)
			lastLogged = time.Now()
		}

		// Never sleep past the deadline: the caller is blocked on this, and an
		// overshoot only delays the loud failure.
		wait := min(caBundlePollInterval, remaining)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(wait):
		}
	}
}

// caBundleMatches reports whether the webhook is genuinely serveable. The second
// return value explains a false result and is surfaced in the timeout error --
// it is never swallowed.
//
// Three things must hold, in order: the Secret carries a CA, every webhook entry
// advertises exactly that CA, and the certificate the webhook server is actually
// serving verifies against it for the Service's DNS name.
func caBundleMatches(ctx context.Context, reader client.Reader, opts Options) (bool, string) {
	secret := &corev1.Secret{}
	if err := reader.Get(ctx, opts.SecretKey(), secret); err != nil {
		return false, fmt.Sprintf("cert Secret %s is not readable: %v", opts.SecretKey(), err)
	}
	ca := secret.Data[caCertKey]
	if len(ca) == 0 {
		return false, fmt.Sprintf("cert Secret %s has no %q entry yet", opts.SecretKey(), caCertKey)
	}

	// Managed path: ca.crt must still be the CA whose private key we hold. The
	// gate and ManagedCertMonitor have to enforce the SAME rules or the weaker
	// one defines the security of the path -- and without this the gate accepts a
	// ca.crt replaced by a single rogue root with a cross-certificate hidden in
	// tls.crt: cardinality is satisfied (one certificate) and the chain verifies,
	// so the operator would go Ready with a rogue anchor published and only the
	// monitor would catch it, up to its 5-minute interval later.
	//
	// Guarded on ca.key being present for the same reason the monitor guards it:
	// during bootstrap the Secret is a half-written shell, which is not tampering.
	if !opts.UserSuppliedCertificate && len(secret.Data[caKeyKey]) > 0 {
		if _, err := tls.X509KeyPair(ca, secret.Data[caKeyKey]); err != nil {
			return false, fmt.Sprintf("%q in Secret %s no longer matches the CA private key in %q: %v",
				caCertKey, opts.SecretKey(), caKeyKey, err)
		}
	}

	webhookConfig := &admissionregistrationv1.MutatingWebhookConfiguration{}
	if err := reader.Get(ctx, types.NamespacedName{Name: opts.MutatingWebhookName}, webhookConfig); err != nil {
		return false, fmt.Sprintf("MutatingWebhookConfiguration %q is not readable: %v", opts.MutatingWebhookName, err)
	}
	if len(webhookConfig.Webhooks) == 0 {
		return false, fmt.Sprintf("MutatingWebhookConfiguration %q declares no webhook entries", opts.MutatingWebhookName)
	}

	for i := range webhookConfig.Webhooks {
		hook := &webhookConfig.Webhooks[i]
		if len(hook.ClientConfig.CABundle) == 0 {
			return false, fmt.Sprintf("webhook entry %q has an empty caBundle", hook.Name)
		}
		if !bytes.Equal(hook.ClientConfig.CABundle, ca) {
			return false, fmt.Sprintf("webhook entry %q caBundle does not match %q in Secret %s",
				hook.Name, caCertKey, opts.SecretKey())
		}
	}

	// The published CA and the served certificate agreeing is the only form of
	// "in sync" that means anything to the API server. This is also what holds
	// the gate shut during a rotation, while the kubelet still has the previous
	// leaf projected into CertDir.
	//
	// It is additionally what protects the OPERATOR-MANAGED path from a poisoned
	// ca.crt. Appending a rogue CA to the Secret disturbs nothing else:
	// cert-controller's validCACert only decodes the first block, so it declines
	// to re-mint and then republishes the bundle verbatim, and the byte
	// comparison above happily agrees with it. verifyServedCertOnDisk ->
	// verifyCertChain is the only step that reads EVERY certificate in the
	// bundle and rejects anything that is not part of the chain being verified.
	if err := verifyServedCertOnDisk(opts.CertDir, ca, opts.DNSName(), opts.caPolicy()); err != nil {
		return false, err.Error()
	}
	return true, ""
}
