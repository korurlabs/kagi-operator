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

package certs

import (
	"context"
	"crypto/tls"
	"fmt"
	"time"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	"k8s.io/client-go/util/retry"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"
)

// managedCertCheckInterval is how often the operator re-examines the
// certificate Secret it owns.
//
// Without this the detection latency for a poisoned ca.crt is min(next restart,
// never): cert-controller's validCACert only decodes the FIRST PEM block, so an
// appended CA leaves it satisfied and it declines to re-mint, and the ~60-day
// leaf rotation propagates the poisoned bundle verbatim
// (buildArtifactsFromSecret reads ca.crt whole, writeSecret writes it back).
const managedCertCheckInterval = 5 * time.Minute

// Event reason for a tampered certificate Secret.
const eventReasonCertTampered = "WebhookCertificateTampered"

// ManagedCertMonitor watches the certificate Secret the OPERATOR owns and
// repairs it when it has been tampered with.
//
// It deliberately does NOT fail closed. Crashing on detection would drop the
// operator out of the webhook Service's Endpoints while leaving the poisoned
// caBundle published -- so an attacker already running a pod that matches the
// Service selector would inherit the admission traffic uncontested. Failing
// closed here is worse than useless.
//
// Instead, in order: refuse to trust it, say so loudly, and re-mint. The
// operator holds ca.key on this path, so it can restore a clean single-anchor CA
// without an outage and without human involvement -- which also evicts the
// attacker's anchor from the API server's trust store.
type ManagedCertMonitor struct {
	client   client.Client
	recorder record.EventRecorder
	opts     Options
	interval time.Duration
}

var _ manager.Runnable = &ManagedCertMonitor{}
var _ manager.LeaderElectionRunnable = &ManagedCertMonitor{}

// NewManagedCertMonitor builds the monitor. recorder may be nil, in which case
// tampering is logged but no Event is emitted.
func NewManagedCertMonitor(c client.Client, recorder record.EventRecorder, opts Options) *ManagedCertMonitor {
	return &ManagedCertMonitor{client: c, recorder: recorder, opts: opts, interval: managedCertCheckInterval}
}

// NeedLeaderElection reports false: every replica serves admission from this
// Secret, so every replica should notice when it goes bad.
func (m *ManagedCertMonitor) NeedLeaderElection() bool { return false }

// Start checks immediately, then on an interval, for as long as the manager
// runs. It never returns an error: a failure here must not take the manager
// down, for the reason in the type comment.
//
// The immediate first check matters on a restart. If the Secret is already
// poisoned, the readiness gate will refuse to open and the operator would
// eventually exit(1) with the poisoned bundle still published -- exactly the
// shape that hands an attacker the endpoint. Repairing on startup gets ahead of
// that.
func (m *ManagedCertMonitor) Start(ctx context.Context) error {
	m.check(ctx)

	ticker := time.NewTicker(m.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			m.check(ctx)
		}
	}
}

func (m *ManagedCertMonitor) check(ctx context.Context) {
	log := logf.FromContext(ctx).WithName("webhook-cert-monitor")
	repaired, err := m.CheckOnce(ctx)
	switch {
	case err != nil:
		log.Error(err, "Could not verify the operator-issued webhook certificate Secret",
			"secret", m.opts.SecretKey().String())
	case repaired:
		log.Info("Re-minted the webhook certificate after detecting tampering",
			"secret", m.opts.SecretKey().String())
	}
}

// CheckOnce verifies the certificate Secret and, if it does not hold exactly the
// material the operator issued, forces a re-mint. It reports whether a repair
// was triggered.
//
// A repair is triggered by invalidating ca.key rather than by minting here.
// cert-controller owns the minting, and its validCACert fails on an empty key,
// so clearing it makes the very next reconcile -- which this write itself
// triggers -- call refreshCerts(true) and write a clean, single-certificate
// ca.crt. Reusing its code path means there is exactly one certificate-issuing
// implementation in the operator, and the repair is self-healing even if the
// process dies midway: the invalid CA is re-minted on the next startup.
func (m *ManagedCertMonitor) CheckOnce(ctx context.Context) (bool, error) {
	secret := &corev1.Secret{}
	if err := m.client.Get(ctx, m.opts.SecretKey(), secret); err != nil {
		return false, fmt.Errorf("failed to read the webhook certificate Secret %s: %w", m.opts.SecretKey(), err)
	}

	// No ca.key. Usually bootstrap -- the shell exists but the rotator has not
	// filled it in yet -- which is neither tampering nor ours to repair.
	//
	// It needs more than a blanket early return, though, because deleting ca.key
	// is EXACTLY how forceReMint below asks cert-controller to re-mint. An
	// attacker who poisons ca.crt and then removes ca.key lands in the same shape
	// as a bootstrap, and used to get a completely silent repair: cert-controller
	// re-minted (correct) but no Event was ever emitted (wrong) -- the one case
	// where the monitor should shout loudest was the one case it said nothing.
	//
	// Intent is not observable from here, so the two are separated by the
	// CERTIFICATE instead: a clean bootstrap has no ca.crt at all, or one that
	// verifies. A ca.crt that is present and fails verification while its key is
	// gone is reported, and stays quiet otherwise.
	if len(secret.Data[caKeyKey]) == 0 {
		if reason := m.keylessTamperReason(secret); reason != "" {
			m.report(ctx, reason)
		}
		// Not a repair either way: a missing ca.key is already the state
		// forceReMint would create, so there is nothing to write and the repair
		// cannot loop. cert-controller's next reconcile mints over it.
		return false, nil
	}
	if len(secret.Data[caCertKey]) == 0 {
		return false, nil
	}

	if reason := m.tamperReason(secret); reason != "" {
		m.report(ctx, reason)
		if err := m.forceReMint(ctx); err != nil {
			return false, fmt.Errorf("detected tampering (%s) but could not force a re-mint: %w", reason, err)
		}
		return true, nil
	}
	return false, nil
}

// keylessTamperReason judges a Secret whose ca.key is absent, and returns "" for
// anything that could be an honest bootstrap. See CheckOnce for why this case
// cannot simply be skipped.
//
// The CA-keypair check that tamperReason leads with is necessarily skipped here
// -- there is no key left to compare ca.crt against. What remains is
// cardinality, chain, SANs and expiry over the serving material, which is what
// catches the shape this exists for: a ca.crt with a rogue anchor appended, or
// swapped for one the served leaf does not chain to.
//
// A half-written Secret is not tampering, so the full serving set has to be
// present before anything is judged. The rotator writes all four entries in one
// update, so ca.crt + tls.crt + tls.key with no ca.key is not a state it
// produces -- only a repair already in flight, or someone else's write.
func (m *ManagedCertMonitor) keylessTamperReason(secret *corev1.Secret) string {
	if len(secret.Data[caCertKey]) == 0 ||
		len(secret.Data[tlsCertKey]) == 0 ||
		len(secret.Data[tlsKeyKey]) == 0 {
		return ""
	}
	if err := verifyServingCert(secret.Data[tlsCertKey], secret.Data[tlsKeyKey], secret.Data[caCertKey],
		m.opts.DNSName(), caPolicyOperatorIssued); err != nil {
		return err.Error()
	}
	return ""
}

// tamperReason returns a human-readable reason when the Secret is not the
// material the operator issued, or "" when it is healthy.
func (m *ManagedCertMonitor) tamperReason(secret *corev1.Secret) string {
	// ca.crt must still be the CA whose private key we hold. This catches
	// substitution of ca.crt ALONE -- including the variant where a
	// cross-certificate is smuggled into tls.crt and ca.crt is replaced by the
	// attacker's root, which passes both chain verification and the cardinality
	// rule because it is internally consistent.
	//
	// It is NOT a defence against someone who can write the Secret: ca.key lives
	// in the SAME Secret, so anyone able to replace ca.crt can replace ca.key
	// alongside it. What it bounds is PARTIAL tampering, which is the realistic
	// shape. See the trust-boundary note at the top of verify.go.
	//
	// caBundleMatches enforces this same rule at the readiness gate, so a
	// poisoned Secret does not merely get repaired within the check interval --
	// it also keeps this replica out of the Service until it is. The two must
	// stay in step: whichever is weaker defines the security of the path.
	if _, err := tls.X509KeyPair(secret.Data[caCertKey], secret.Data[caKeyKey]); err != nil {
		return fmt.Sprintf("%q no longer matches the CA private key in %q (%v)", caCertKey, caKeyKey, err)
	}

	// Keypair, cardinality, chain, SANs and expiry.
	//
	// Cardinality does the heavy lifting here: caPolicyOperatorIssued rejects
	// anything other than a single certificate in ca.crt, which makes every
	// ca.crt-side append and cross-sign shape unreachable on this path -- the
	// chain-participation rule inside verifyCertChain is likewise reached but
	// vacuous, since one root that the chain terminates at always participates.
	// The cross-signature scan is NOT dead here, though: it covers the union of
	// ca.crt and the trailing certificates of tls.crt, and cardinality says
	// nothing about tls.crt. See the who-enforces-what table in verify.go.
	if err := verifyServingCert(secret.Data[tlsCertKey], secret.Data[tlsKeyKey], secret.Data[caCertKey],
		m.opts.DNSName(), caPolicyOperatorIssued); err != nil {
		return err.Error()
	}
	return ""
}

// report logs and emits a Warning Event on the MutatingWebhookConfiguration, so
// tampering is visible in `kubectl describe` and to anything watching Events --
// at no cost to availability.
func (m *ManagedCertMonitor) report(ctx context.Context, reason string) {
	log := logf.FromContext(ctx).WithName("webhook-cert-monitor")
	log.Error(fmt.Errorf("%s", reason), "Webhook certificate Secret has been tampered with; re-minting",
		"secret", m.opts.SecretKey().String())

	if m.recorder == nil {
		return
	}
	webhookConfig := &admissionregistrationv1.MutatingWebhookConfiguration{}
	if err := m.client.Get(ctx, types.NamespacedName{Name: m.opts.MutatingWebhookName}, webhookConfig); err != nil {
		// The Event is a courtesy; losing it must not stop the repair.
		log.Error(err, "Could not read the MutatingWebhookConfiguration to record a tampering Event")
		return
	}
	m.recorder.Eventf(webhookConfig, corev1.EventTypeWarning, eventReasonCertTampered,
		"Certificate Secret %s does not hold the material this operator issued (%s); re-minting the CA",
		m.opts.SecretKey(), reason)
}

// forceReMint invalidates the CA private key so cert-controller's next reconcile
// mints a fresh CA and leaf. See CheckOnce for why it is done this way.
func (m *ManagedCertMonitor) forceReMint(ctx context.Context) error {
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		secret := &corev1.Secret{}
		if err := m.client.Get(ctx, m.opts.SecretKey(), secret); err != nil {
			return err
		}
		if secret.Data == nil {
			secret.Data = map[string][]byte{}
		}
		delete(secret.Data, caKeyKey)
		return m.client.Update(ctx, secret, client.FieldOwner(fieldOwner))
	})
}
