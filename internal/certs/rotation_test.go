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
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/open-policy-agent/cert-controller/pkg/rotator"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

// -----------------------------------------------------------------------------
// Options
// -----------------------------------------------------------------------------

func TestOptionsValidateRejectsIncompleteConfiguration(t *testing.T) {
	tests := map[string]func(o *Options){
		"missing namespace":    func(o *Options) { o.Namespace = "" },
		"missing secret name":  func(o *Options) { o.SecretName = "" },
		"missing service name": func(o *Options) { o.ServiceName = "" },
		"missing webhook name": func(o *Options) { o.MutatingWebhookName = "" },
		"missing cert dir":     func(o *Options) { o.CertDir = "" },
		"zero wait timeout":    func(o *Options) { o.CABundleWaitTimeout = 0 },
	}

	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			opts := testOptions()
			mutate(&opts)
			if err := opts.Validate(); err == nil {
				t.Fatalf("expected %s to be rejected, got nil error", name)
			}
		})
	}

	if err := testOptions().Validate(); err != nil {
		t.Fatalf("expected a complete configuration to validate, got %v", err)
	}
}

func TestOptionsDeriveServiceDNSNames(t *testing.T) {
	opts := testOptions()

	if got, want := opts.DNSName(), "kagi-operator-webhook.kagi-operator-system.svc"; got != want {
		t.Fatalf("DNSName() = %q, want %q", got, want)
	}
	extra := opts.ExtraDNSNames()
	if len(extra) != 1 || extra[0] != "kagi-operator-webhook.kagi-operator-system.svc.cluster.local" {
		t.Fatalf("ExtraDNSNames() = %v, want the cluster.local form", extra)
	}
	if got, want := opts.SecretKey().String(), "kagi-operator-system/kagi-operator-webhook-server-cert"; got != want {
		t.Fatalf("SecretKey() = %q, want %q", got, want)
	}
}

func TestOptionsModeNamesTheCertificateOwner(t *testing.T) {
	const managed, supplied = "operator-managed", "user-supplied"

	// The zero value must land on the safe, operator-managed path: a caller who
	// forgets the field must not silently opt into expecting somebody else to
	// have populated the Secret.
	if got := (Options{}).Mode(); got != managed {
		t.Fatalf("the zero-value Options must default to %s, got %q", managed, got)
	}
	if got := testOptions().Mode(); got != managed {
		t.Fatalf("Mode() = %q, want %q", got, managed)
	}
	if got := unmanagedOptions().Mode(); got != supplied {
		t.Fatalf("Mode() with UserSuppliedCertificate = %q, want %q", got, supplied)
	}
}

// -----------------------------------------------------------------------------
// Secret bootstrap
// -----------------------------------------------------------------------------

func TestEnsureCertSecretCreatesSecretWhenAbsent(t *testing.T) {
	opts := testOptions()
	c := newFakeClient(t)

	if err := EnsureCertSecret(context.Background(), c, opts.SecretKey()); err != nil {
		t.Fatalf("EnsureCertSecret: %v", err)
	}

	created := &corev1.Secret{}
	if err := c.Get(context.Background(), opts.SecretKey(), created); err != nil {
		t.Fatalf("expected the cert Secret to have been created: %v", err)
	}
	// Opaque, not kubernetes.io/tls: the shell is empty until the rotator fills
	// it in, and kubernetes.io/tls would be rejected without tls.crt/tls.key.
	if created.Type != corev1.SecretTypeOpaque {
		t.Fatalf("created Secret type = %q, want %q", created.Type, corev1.SecretTypeOpaque)
	}
}

func TestEnsureCertSecretPreservesAnExistingSecret(t *testing.T) {
	opts := testOptions()
	existing := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: opts.SecretName, Namespace: opts.Namespace},
		// An upgrade from the old cert-manager / genSelfSignedCert chart leaves
		// a kubernetes.io/tls Secret behind. Secret.type is immutable, so the
		// bootstrap must never try to replace it.
		Type: corev1.SecretTypeTLS,
		Data: map[string][]byte{tlsCertKey: []byte("existing"), tlsKeyKey: []byte("existing")},
	}
	c := newFakeClient(t, existing)

	if err := EnsureCertSecret(context.Background(), c, opts.SecretKey()); err != nil {
		t.Fatalf("EnsureCertSecret: %v", err)
	}

	got := &corev1.Secret{}
	if err := c.Get(context.Background(), opts.SecretKey(), got); err != nil {
		t.Fatalf("get secret: %v", err)
	}
	if got.Type != corev1.SecretTypeTLS {
		t.Fatalf("Secret type changed to %q; an existing Secret must be left alone", got.Type)
	}
	if string(got.Data[tlsCertKey]) != "existing" {
		t.Fatalf("existing cert material was overwritten: %q", got.Data[tlsCertKey])
	}
}

func TestEnsureCertSecretToleratesLosingTheCreateRace(t *testing.T) {
	opts := testOptions()
	// Two replicas start together, both see NotFound, both Create. The loser
	// gets AlreadyExists -- which is success, not an error: the Secret is the
	// shared source of truth and the winner wrote the same empty shell.
	c := newFakeClientWithInterceptor(t, interceptor.Funcs{
		Create: func(_ context.Context, _ client.WithWatch, obj client.Object, _ ...client.CreateOption) error {
			return apierrors.NewAlreadyExists(schema.GroupResource{Resource: "secrets"}, obj.GetName())
		},
	})

	if err := EnsureCertSecret(context.Background(), c, opts.SecretKey()); err != nil {
		t.Fatalf("losing the create race must not fail startup, got %v", err)
	}
}

func TestEnsureCertSecretSurfacesUnexpectedCreateErrors(t *testing.T) {
	opts := testOptions()
	c := newFakeClientWithInterceptor(t, interceptor.Funcs{
		Create: func(_ context.Context, _ client.WithWatch, _ client.Object, _ ...client.CreateOption) error {
			return apierrors.NewForbidden(schema.GroupResource{Resource: "secrets"}, "x", nil)
		},
	})

	if err := EnsureCertSecret(context.Background(), c, opts.SecretKey()); err == nil {
		t.Fatal("a Forbidden on create must fail startup rather than be swallowed")
	}
}

// -----------------------------------------------------------------------------
// Certificate generation and expiry-triggered rotation
// -----------------------------------------------------------------------------

func TestGeneratedCertificateCoversBothServiceSANs(t *testing.T) {
	opts := testOptions()
	pair := issueFor(t, opts)

	block, _ := pem.Decode(pair.certPEM)
	if block == nil {
		t.Fatal("issued certificate is not valid PEM")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse issued certificate: %v", err)
	}

	want := append([]string{opts.DNSName()}, opts.ExtraDNSNames()...)
	for _, dnsName := range want {
		if !slices.Contains(leaf.DNSNames, dnsName) {
			t.Fatalf("issued certificate SANs %v are missing %q", leaf.DNSNames, dnsName)
		}
	}
	if !leaf.NotAfter.After(time.Now()) {
		t.Fatalf("issued certificate is already expired at %s", leaf.NotAfter)
	}
}

func TestGeneratedCertificateIsTrustedForTheWebhookServiceName(t *testing.T) {
	opts := testOptions()
	pair := issueFor(t, opts)
	usages := &[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}

	valid, err := rotator.ValidCert(pair.caPEM, pair.certPEM, pair.keyPEM, opts.DNSName(), usages, time.Now())
	if err != nil || !valid {
		t.Fatalf("issued certificate should be valid for %q, got valid=%v err=%v", opts.DNSName(), valid, err)
	}

	// A certificate issued for a different Service name must NOT satisfy this
	// one -- that is what makes a Service rename trigger a re-issue instead of
	// silently serving a cert the API server rejects.
	renamed := opts
	renamed.ServiceName = "some-other-webhook"
	valid, _ = rotator.ValidCert(pair.caPEM, pair.certPEM, pair.keyPEM, renamed.DNSName(), usages, time.Now())
	if valid {
		t.Fatalf("certificate for %q unexpectedly validated for %q", opts.DNSName(), renamed.DNSName())
	}
}

func TestCertificateNearingExpiryIsConsideredInvalidAtTheRotationLookahead(t *testing.T) {
	opts := testOptions()
	usages := &[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}

	// The operator pins LookaheadInterval to rotationLookahead: a cert is
	// refreshed once it would no longer be valid that far out. Issue one that
	// outlives "now" but not the lookahead, and assert both verdicts.
	now := time.Now()
	pair := issueForWindow(t, opts, now.Add(-time.Hour), now.Add(24*time.Hour))

	valid, err := rotator.ValidCert(pair.caPEM, pair.certPEM, pair.keyPEM, opts.DNSName(), usages, now)
	if err != nil || !valid {
		t.Fatalf("certificate should still be valid now, got valid=%v err=%v", valid, err)
	}

	valid, err = rotator.ValidCert(pair.caPEM, pair.certPEM, pair.keyPEM, opts.DNSName(), usages, now.Add(rotationLookahead))
	if valid || err == nil {
		t.Fatalf("a certificate expiring in 24h must be invalid at the %s rotation lookahead, "+
			"otherwise it would never be rotated before it expires", rotationLookahead)
	}
}

func TestPinnedCertificateLifetimesAreCoherent(t *testing.T) {
	// These are a security posture, not an implementation detail: assert the
	// relationships that make rotation actually happen before expiry, so a
	// future edit to one constant cannot quietly break the others.
	if rotationLookahead >= serverCertDuration {
		t.Fatalf("lookahead %s must be shorter than the leaf lifetime %s, or every freshly issued "+
			"certificate is immediately considered stale", rotationLookahead, serverCertDuration)
	}
	if rotationCheckFrequency >= rotationLookahead {
		t.Fatalf("check frequency %s must be far shorter than the lookahead %s, or a rotation can be "+
			"missed entirely", rotationCheckFrequency, rotationLookahead)
	}
	if caCertDuration <= serverCertDuration {
		t.Fatalf("the CA (%s) must outlive the leaf (%s)", caCertDuration, serverCertDuration)
	}
}

// -----------------------------------------------------------------------------
// caBundle gate
// -----------------------------------------------------------------------------

func awaitWithTimeout(t *testing.T, c client.Client, opts Options, timeout time.Duration) error {
	t.Helper()
	opts.CABundleWaitTimeout = timeout
	return AwaitWebhookCABundle(context.Background(), c, opts)
}

func TestAwaitWebhookCABundleAcceptsAFullyPatchedConfiguration(t *testing.T) {
	opts := testOptions()
	pair := issueFor(t, opts)
	opts.CertDir = certDirWith(t, pair)
	c := newFakeClient(t, managedSecret(opts, pair), mutatingWebhookConfig(opts, pair.caPEM, pair.caPEM))

	if err := awaitWithTimeout(t, c, opts, time.Minute); err != nil {
		t.Fatalf("expected a patched caBundle plus a matching served cert to be accepted, got %v", err)
	}
}

func TestAwaitWebhookCABundleRejectsAnEmptyCABundle(t *testing.T) {
	opts := testOptions()
	pair := issueFor(t, opts)
	opts.CertDir = certDirWith(t, pair)
	// This is the released install.yaml failure mode: a fail-closed webhook
	// with no caBundle at all.
	c := newFakeClient(t, managedSecret(opts, pair), mutatingWebhookConfig(opts, nil))

	err := awaitWithTimeout(t, c, opts, 20*time.Millisecond)
	if err == nil {
		t.Fatal("expected an empty caBundle to fail")
	}
	if !strings.Contains(err.Error(), "empty caBundle") {
		t.Fatalf("error should name the empty caBundle, got %v", err)
	}
}

func TestAwaitWebhookCABundleRejectsAStaleCABundleOnAnyWebhookEntry(t *testing.T) {
	opts := testOptions()
	pair := issueFor(t, opts)
	other := issueFor(t, opts)
	opts.CertDir = certDirWith(t, pair)
	// First entry patched, second left on a previous CA: partial patching is
	// still a broken webhook, so it must not be accepted.
	c := newFakeClient(t, managedSecret(opts, pair), mutatingWebhookConfig(opts, pair.caPEM, other.caPEM))

	err := awaitWithTimeout(t, c, opts, 20*time.Millisecond)
	if err == nil {
		t.Fatal("expected a stale caBundle on a second webhook entry to fail")
	}
	if !strings.Contains(err.Error(), "second.kagi.pw") {
		t.Fatalf("error should name the offending webhook entry, got %v", err)
	}
}

func TestAwaitWebhookCABundleFailsLoudlyWhenTheWebhookConfigurationIsMissing(t *testing.T) {
	opts := testOptions()
	pair := issueFor(t, opts)
	opts.CertDir = certDirWith(t, pair)
	// The typo'd --mutating-webhook-name case. cert-controller logs and skips a
	// missing webhook and still reports "CA injected", so this wait is the only
	// thing standing between a misconfiguration and a silent admission outage.
	c := newFakeClient(t, managedSecret(opts, pair))

	err := awaitWithTimeout(t, c, opts, 20*time.Millisecond)
	if err == nil {
		t.Fatal("expected a missing MutatingWebhookConfiguration to fail")
	}
	if !strings.Contains(err.Error(), opts.MutatingWebhookName) {
		t.Fatalf("error should name the MutatingWebhookConfiguration it looked for, got %v", err)
	}
	if !strings.Contains(err.Error(), "--mutating-webhook-name") {
		t.Fatalf("error should point at the flag to fix, got %v", err)
	}
}

func TestAwaitWebhookCABundleWaitsForTheCertSecretToBePopulated(t *testing.T) {
	opts := testOptions()
	// The Secret exists (EnsureCertSecret created the empty shell) but the
	// rotator has not written the CA yet.
	empty := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: opts.SecretName, Namespace: opts.Namespace},
		Type:       corev1.SecretTypeOpaque,
	}
	c := newFakeClient(t, empty, mutatingWebhookConfig(opts, nil))

	err := awaitWithTimeout(t, c, opts, 20*time.Millisecond)
	if err == nil {
		t.Fatal("expected an unpopulated cert Secret to fail the wait")
	}
	if !strings.Contains(err.Error(), caCertKey) {
		t.Fatalf("error should name the missing %q entry, got %v", caCertKey, err)
	}
}

func TestAwaitWebhookCABundleRejectsNonCertificateGarbage(t *testing.T) {
	opts := testOptions()
	// Byte equality alone reports "in sync" here: ca.crt, tls.crt, tls.key and
	// the caBundle are all the same string, and none of them is a certificate.
	//
	// Where it dies is the served KEYPAIR check, before ca.crt is looked at at
	// all -- tls.crt and tls.key are garbage, so X509KeyPair fails and
	// verifyCertChain is never reached. That is the honest reach of this case;
	// ca.crt's own parsing is pinned by TestParseCertsRejectsMalformedBundles
	// below, which drives parseCerts directly.
	garbage := []byte("this is not a certificate at all")
	opts.CertDir = certDirWith(t, keyPair{certPEM: garbage, keyPEM: garbage})
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: opts.SecretName, Namespace: opts.Namespace},
		Data:       map[string][]byte{caCertKey: garbage, tlsCertKey: garbage, tlsKeyKey: garbage},
	}
	c := newFakeClient(t, secret, mutatingWebhookConfig(opts, garbage))

	err := awaitWithTimeout(t, c, opts, 20*time.Millisecond)
	if err == nil {
		t.Fatal("non-certificate garbage must not be accepted as an in-sync caBundle")
	}
	if !strings.Contains(err.Error(), "are not a matching keypair") {
		t.Fatalf("error should come from the served keypair check, got %v", err)
	}
}

// TestParseCertsRejectsMalformedBundles covers parseCerts' two error paths. Both
// decide what the API server will trust, and neither was reachable from any
// other test: the gate's garbage case dies at the keypair check first, and every
// remaining case feeds parseCerts well-formed PEM.
func TestParseCertsRejectsMalformedBundles(t *testing.T) {
	privateKeyOnly := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: []byte("not a key either")})

	cases := []struct {
		name    string
		bundle  []byte
		wantErr string
	}{
		{
			// A CERTIFICATE block whose DER does not parse. Skipping past it and
			// using "most of" the bundle is not a state worth proceeding from,
			// so it is a hard error rather than a filtered entry.
			name:    "unparseable CERTIFICATE block",
			bundle:  pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("not DER")}),
			wantErr: "unparseable certificate",
		},
		{
			name:    "no PEM structure at all",
			bundle:  []byte("this is not a certificate at all"),
			wantErr: "no PEM-encoded certificate",
		},
		{
			// Well-formed PEM carrying no CERTIFICATE block: the non-certificate
			// blocks are skipped, and skipping everything must not read as an
			// empty-but-fine bundle.
			name:    "PEM blocks but none of them a certificate",
			bundle:  privateKeyOnly,
			wantErr: "no PEM-encoded certificate",
		},
		{
			// A valid certificate followed by junk PEM still parses: the junk is
			// skipped and the certificate stands. This is the boundary that keeps
			// the two error paths above from being over-eager.
			name:   "valid certificate alongside a non-certificate block",
			bundle: concatPEM(newTestCA(t, "corp-root-ca").pem, privateKeyOnly),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			certs, err := parseCerts(tc.bundle)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("expected the bundle to parse, got %v", err)
				}
				if len(certs) != 1 {
					t.Fatalf("expected exactly the one certificate in the bundle, got %d", len(certs))
				}
				return
			}
			if err == nil {
				t.Fatalf("expected %q to be rejected", tc.name)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error should explain %q, got %v", tc.wantErr, err)
			}
		})
	}
}

func TestAwaitWebhookCABundleRejectsAServedCertThatDoesNotChainToThePublishedCA(t *testing.T) {
	opts := testOptions()
	published := issueFor(t, opts)
	// The caBundle and the Secret agree, but the pod is still serving the
	// PREVIOUS leaf out of its kubelet-projected volume -- the rotation window.
	// The API server would reject that handshake, so the gate must stay shut.
	stale := issueFor(t, opts)
	opts.CertDir = certDirWith(t, stale)
	c := newFakeClient(t, managedSecret(opts, published), mutatingWebhookConfig(opts, published.caPEM))

	err := awaitWithTimeout(t, c, opts, 20*time.Millisecond)
	if err == nil {
		t.Fatal("a served certificate that does not chain to the published CA must not be reported in sync")
	}
	if !strings.Contains(err.Error(), "does not match the published caBundle") {
		t.Fatalf("error should explain the served/published mismatch, got %v", err)
	}
}

func TestAwaitWebhookCABundleStopsOnContextCancellation(t *testing.T) {
	opts := testOptions()
	pair := issueFor(t, opts)
	opts.CertDir = certDirWith(t, pair)
	c := newFakeClient(t, managedSecret(opts, pair))

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if err := AwaitWebhookCABundle(ctx, c, opts); err != context.Canceled {
		t.Fatalf("expected context.Canceled on shutdown, got %v", err)
	}
}

func TestAwaitWebhookCABundleRejectsAnIncompleteConfiguration(t *testing.T) {
	opts := testOptions()
	opts.MutatingWebhookName = ""

	if err := AwaitWebhookCABundle(context.Background(), newFakeClient(t), opts); err == nil {
		t.Fatal("expected an incomplete Options to be rejected before polling")
	}
}

// -----------------------------------------------------------------------------
// Bring-your-own-certificate (UserSuppliedCertificate)
// -----------------------------------------------------------------------------

func TestLoadSuppliedCertSecretAcceptsAValidCertificate(t *testing.T) {
	opts := unmanagedOptions()
	pair := issueFor(t, opts)
	c := newFakeClient(t, suppliedCertSecret(opts, pair))

	ca, err := LoadSuppliedCertSecret(context.Background(), c, opts.SecretKey(), opts.DNSName())
	if err != nil {
		t.Fatalf("a correctly issued certificate must be accepted, got %v", err)
	}
	if !bytes.Equal(ca, pair.caPEM) {
		t.Fatal("the returned CA must be the supplied ca.crt verbatim")
	}
}

func TestLoadSuppliedCertSecretFailsLoudlyWhenTheSecretDoesNotExist(t *testing.T) {
	opts := unmanagedOptions()

	_, err := LoadSuppliedCertSecret(context.Background(), newFakeClient(t), opts.SecretKey(), opts.DNSName())
	if err == nil {
		t.Fatal("expected a missing user-supplied Secret to fail startup")
	}
	if !strings.Contains(err.Error(), opts.SecretKey().String()) {
		t.Fatalf("error should name the Secret it looked for, got %v", err)
	}
	if !strings.Contains(err.Error(), "injection.existingCertSecret") {
		t.Fatalf("error should tell the operator how to opt back out, got %v", err)
	}
}

func TestLoadSuppliedCertSecretFailsLoudlyOnEveryMissingKey(t *testing.T) {
	opts := unmanagedOptions()
	pair := issueFor(t, opts)

	for _, missing := range []string{tlsCertKey, tlsKeyKey, caCertKey} {
		t.Run("missing "+missing, func(t *testing.T) {
			secret := suppliedCertSecret(opts, pair)
			delete(secret.Data, missing)

			_, err := LoadSuppliedCertSecret(context.Background(), newFakeClient(t, secret),
				opts.SecretKey(), opts.DNSName())
			if err == nil {
				t.Fatalf("expected a Secret missing %q to fail startup", missing)
			}
			if !strings.Contains(err.Error(), missing) {
				t.Fatalf("error should name the missing key %q, got %v", missing, err)
			}
			if !strings.Contains(err.Error(), opts.SecretKey().String()) {
				t.Fatalf("error should name the Secret, got %v", err)
			}
		})
	}
}

func TestLoadSuppliedCertSecretRejectsAnUnrelatedCA(t *testing.T) {
	opts := unmanagedOptions()
	genuine := issueFor(t, opts)
	attacker := issueFor(t, opts)

	// The demonstrated exploit: a well-formed leaf and key, but ca.crt is an
	// unrelated CA. Presence checks accept it and the operator publishes it into
	// the API server's trust store, handing admission control over every
	// injected pod to whoever can write this Secret.
	secret := suppliedCertSecret(opts, keyPair{
		certPEM: genuine.certPEM,
		keyPEM:  genuine.keyPEM,
		caPEM:   attacker.caPEM,
	})

	_, err := LoadSuppliedCertSecret(context.Background(), newFakeClient(t, secret),
		opts.SecretKey(), opts.DNSName())
	if err == nil {
		t.Fatal("a ca.crt unrelated to tls.crt must be refused: publishing it hands over admission control")
	}
	if !strings.Contains(err.Error(), "does not chain") {
		t.Fatalf("error should explain the chain failure, got %v", err)
	}
}

func TestLoadSuppliedCertSecretRejectsAMismatchedKey(t *testing.T) {
	opts := unmanagedOptions()
	first := issueFor(t, opts)
	second := issueFor(t, opts)

	secret := suppliedCertSecret(opts, keyPair{
		certPEM: first.certPEM,
		keyPEM:  second.keyPEM,
		caPEM:   first.caPEM,
	})

	_, err := LoadSuppliedCertSecret(context.Background(), newFakeClient(t, secret),
		opts.SecretKey(), opts.DNSName())
	if err == nil {
		t.Fatal("tls.crt and tls.key that are not a pair must be refused")
	}
	if !strings.Contains(err.Error(), "matching keypair") {
		t.Fatalf("error should explain the keypair mismatch, got %v", err)
	}
}

func TestLoadSuppliedCertSecretRejectsAWrongServiceName(t *testing.T) {
	opts := unmanagedOptions()
	// The likeliest honest mistake: a certificate issued for the wrong
	// <svc>.<ns>.svc name. Without SAN verification this produces a
	// healthy-looking operator and silently broken admission.
	wrong := opts
	wrong.ServiceName = "guessed-the-name-wrong"
	pair := issueFor(t, wrong)

	_, err := LoadSuppliedCertSecret(context.Background(), newFakeClient(t, suppliedCertSecret(opts, pair)),
		opts.SecretKey(), opts.DNSName())
	if err == nil {
		t.Fatal("a certificate that does not cover the webhook Service DNS name must be refused")
	}
	if !strings.Contains(err.Error(), opts.DNSName()) {
		t.Fatalf("error should name the DNS name the certificate must cover, got %v", err)
	}
}

func TestLoadSuppliedCertSecretRejectsAnExpiredCertificate(t *testing.T) {
	opts := unmanagedOptions()
	past := time.Now().Add(-48 * time.Hour)
	pair := issueForWindow(t, opts, past, past.Add(time.Hour))

	_, err := LoadSuppliedCertSecret(context.Background(), newFakeClient(t, suppliedCertSecret(opts, pair)),
		opts.SecretKey(), opts.DNSName())
	if err == nil {
		t.Fatal("an expired certificate must be refused")
	}
	if !strings.Contains(err.Error(), "expired") {
		t.Fatalf("error should say the certificate expired, got %v", err)
	}
}

func TestSuppliedCertValidationRejectsTheEmptyShellTheManagedPathCreates(t *testing.T) {
	opts := unmanagedOptions()
	// EnsureCertSecret (the managed path) creates an EMPTY Secret for the
	// rotator to fill in. Pointing injection.existingCertSecret at one of those
	// by mistake must be caught at startup, not discovered when admission
	// fail-closes.
	c := newFakeClient(t)
	if err := EnsureCertSecret(context.Background(), c, opts.SecretKey()); err != nil {
		t.Fatalf("EnsureCertSecret: %v", err)
	}

	if _, err := LoadSuppliedCertSecret(context.Background(), c, opts.SecretKey(), opts.DNSName()); err == nil {
		t.Fatal("an empty operator-managed Secret must not be accepted as a user-supplied certificate")
	}
}

func TestCABundleSyncerPublishesTheSuppliedCAAndNeverWritesTheSecret(t *testing.T) {
	opts := unmanagedOptions()
	pair := issueFor(t, opts)
	c := newFakeClient(t, suppliedCertSecret(opts, pair), mutatingWebhookConfig(opts, nil, nil))

	before := &corev1.Secret{}
	if err := c.Get(context.Background(), opts.SecretKey(), before); err != nil {
		t.Fatalf("get secret: %v", err)
	}

	syncer := NewCABundleSyncer(c, opts, make(chan struct{}))
	if err := syncer.SyncOnce(context.Background()); err != nil {
		t.Fatalf("SyncOnce: %v", err)
	}

	config := &admissionregistrationv1.MutatingWebhookConfiguration{}
	if err := c.Get(context.Background(), types.NamespacedName{Name: opts.MutatingWebhookName}, config); err != nil {
		t.Fatalf("get webhook config: %v", err)
	}
	for i := range config.Webhooks {
		// Their CA, not one we minted.
		if !bytes.Equal(config.Webhooks[i].ClientConfig.CABundle, pair.caPEM) {
			t.Fatalf("webhook entry %q caBundle is not the supplied ca.crt", config.Webhooks[i].Name)
		}
	}

	after := &corev1.Secret{}
	if err := c.Get(context.Background(), opts.SecretKey(), after); err != nil {
		t.Fatalf("get secret: %v", err)
	}
	if after.ResourceVersion != before.ResourceVersion {
		t.Fatalf("the user-supplied Secret was written to (resourceVersion %s -> %s); it is theirs, never ours",
			before.ResourceVersion, after.ResourceVersion)
	}
}

func TestCABundleSyncerRepublishesWhenTheSuppliedCAChanges(t *testing.T) {
	opts := unmanagedOptions()
	first := issueFor(t, opts)
	c := newFakeClient(t, suppliedCertSecret(opts, first), mutatingWebhookConfig(opts, nil))

	syncer := NewCABundleSyncer(c, opts, make(chan struct{}))
	if err := syncer.SyncOnce(context.Background()); err != nil {
		t.Fatalf("first SyncOnce: %v", err)
	}

	// Their PKI rotates the CA underneath us -- no notification, no restart. A
	// stale caBundle here is a fail-closed outage weeks after the fact.
	rotated := issueFor(t, opts)
	live := &corev1.Secret{}
	if err := c.Get(context.Background(), opts.SecretKey(), live); err != nil {
		t.Fatalf("get secret: %v", err)
	}
	live.Data[caCertKey] = rotated.caPEM
	live.Data[tlsCertKey] = rotated.certPEM
	live.Data[tlsKeyKey] = rotated.keyPEM
	if err := c.Update(context.Background(), live); err != nil {
		t.Fatalf("simulate PKI rotation: %v", err)
	}

	if err := syncer.SyncOnce(context.Background()); err != nil {
		t.Fatalf("second SyncOnce: %v", err)
	}

	config := &admissionregistrationv1.MutatingWebhookConfiguration{}
	if err := c.Get(context.Background(), types.NamespacedName{Name: opts.MutatingWebhookName}, config); err != nil {
		t.Fatalf("get webhook config: %v", err)
	}
	if !bytes.Equal(config.Webhooks[0].ClientConfig.CABundle, rotated.caPEM) {
		t.Fatal("caBundle was not republished after the supplied CA rotated")
	}
}

func TestCABundleSyncerRefusesAPostStartupSwapToAnUnrelatedCA(t *testing.T) {
	opts := unmanagedOptions()
	good := issueFor(t, opts)
	c := newFakeClient(t, suppliedCertSecret(opts, good), mutatingWebhookConfig(opts, nil))

	syncer := NewCABundleSyncer(c, opts, make(chan struct{}))
	if err := syncer.SyncOnce(context.Background()); err != nil {
		t.Fatalf("first SyncOnce: %v", err)
	}

	// Validating only at startup would let this land in the API server's trust
	// store within a minute.
	attacker := issueFor(t, opts)
	live := &corev1.Secret{}
	if err := c.Get(context.Background(), opts.SecretKey(), live); err != nil {
		t.Fatalf("get secret: %v", err)
	}
	live.Data[caCertKey] = attacker.caPEM
	if err := c.Update(context.Background(), live); err != nil {
		t.Fatalf("simulate swap: %v", err)
	}

	if err := syncer.SyncOnce(context.Background()); err == nil {
		t.Fatal("a post-startup swap to an unrelated CA must be refused")
	}

	config := &admissionregistrationv1.MutatingWebhookConfiguration{}
	if err := c.Get(context.Background(), types.NamespacedName{Name: opts.MutatingWebhookName}, config); err != nil {
		t.Fatalf("get webhook config: %v", err)
	}
	if !bytes.Equal(config.Webhooks[0].ClientConfig.CABundle, good.caPEM) {
		t.Fatal("the previously published caBundle must be left untouched when verification fails")
	}
}

func TestCABundleSyncerDoesNotWriteWhenAlreadyInSync(t *testing.T) {
	opts := unmanagedOptions()
	pair := issueFor(t, opts)
	c := newFakeClient(t, suppliedCertSecret(opts, pair), mutatingWebhookConfig(opts, pair.caPEM))

	before := &admissionregistrationv1.MutatingWebhookConfiguration{}
	if err := c.Get(context.Background(), types.NamespacedName{Name: opts.MutatingWebhookName}, before); err != nil {
		t.Fatalf("get webhook config: %v", err)
	}

	syncer := NewCABundleSyncer(c, opts, make(chan struct{}))
	if err := syncer.SyncOnce(context.Background()); err != nil {
		t.Fatalf("SyncOnce: %v", err)
	}

	after := &admissionregistrationv1.MutatingWebhookConfiguration{}
	if err := c.Get(context.Background(), types.NamespacedName{Name: opts.MutatingWebhookName}, after); err != nil {
		t.Fatalf("get webhook config: %v", err)
	}
	if after.ResourceVersion != before.ResourceVersion {
		t.Fatalf("steady-state sync issued a needless write (resourceVersion %s -> %s)",
			before.ResourceVersion, after.ResourceVersion)
	}
}

func TestCABundleSyncerRetriesOnConflict(t *testing.T) {
	opts := unmanagedOptions()
	pair := issueFor(t, opts)

	// ArgoCD, a human, or another replica touches the object between our Get and
	// our Update. Start treats a first-sync failure as fatal, so without a retry
	// a routine 409 would crash the operator at startup.
	conflicts := 0
	c := newFakeClientWithInterceptor(t, interceptor.Funcs{
		Update: func(ctx context.Context, cl client.WithWatch, obj client.Object, o ...client.UpdateOption) error {
			if _, isWebhook := obj.(*admissionregistrationv1.MutatingWebhookConfiguration); isWebhook && conflicts < 2 {
				conflicts++
				return apierrors.NewConflict(
					schema.GroupResource{Group: "admissionregistration.k8s.io", Resource: "mutatingwebhookconfigurations"},
					obj.GetName(), context.Canceled)
			}
			return cl.Update(ctx, obj, o...)
		},
	}, suppliedCertSecret(opts, pair), mutatingWebhookConfig(opts, nil))

	syncer := NewCABundleSyncer(c, opts, make(chan struct{}))
	if err := syncer.SyncOnce(context.Background()); err != nil {
		t.Fatalf("a conflict must be retried, not surfaced: %v", err)
	}
	if conflicts != 2 {
		t.Fatalf("expected 2 simulated conflicts to be consumed, got %d", conflicts)
	}

	config := &admissionregistrationv1.MutatingWebhookConfiguration{}
	if err := c.Get(context.Background(), types.NamespacedName{Name: opts.MutatingWebhookName}, config); err != nil {
		t.Fatalf("get webhook config: %v", err)
	}
	if !bytes.Equal(config.Webhooks[0].ClientConfig.CABundle, pair.caPEM) {
		t.Fatal("the caBundle should have been published once the conflict cleared")
	}
}

func TestCABundleSyncerFailsWhenTheWebhookConfigurationIsMissing(t *testing.T) {
	opts := unmanagedOptions()
	pair := issueFor(t, opts)
	c := newFakeClient(t, suppliedCertSecret(opts, pair))

	syncer := NewCABundleSyncer(c, opts, make(chan struct{}))
	err := syncer.SyncOnce(context.Background())
	if err == nil {
		t.Fatal("expected a missing MutatingWebhookConfiguration to be an error, not a silent skip")
	}
	if !strings.Contains(err.Error(), opts.MutatingWebhookName) {
		t.Fatalf("error should name the MutatingWebhookConfiguration, got %v", err)
	}
}

func TestAwaitWebhookCABundleAcceptsAUserSuppliedCABundle(t *testing.T) {
	opts := unmanagedOptions()
	pair := issueFor(t, opts)
	opts.CertDir = certDirWith(t, pair)
	// The gate in cmd/main.go is identical on both paths -- only the origin of
	// the material differs.
	c := newFakeClient(t, suppliedCertSecret(opts, pair), mutatingWebhookConfig(opts, pair.caPEM))

	if err := awaitWithTimeout(t, c, opts, time.Minute); err != nil {
		t.Fatalf("expected a published user-supplied caBundle to be accepted, got %v", err)
	}
}

// -----------------------------------------------------------------------------
// Trust-anchor addition
//
// APPENDING to ca.crt leaves the legitimate chain verifying, so admission keeps
// working, no log line fires, and the operator reports Ready -- while the API
// server silently gains a second trust anchor whose key the attacker holds. From
// there they serve a leaf under their own CA from anything matching the webhook
// Service selector and become the admission mutator for every injected pod.
//
// Substitution is NOT the noisy alternative this might imply: a coherent
// replacement of the whole Secret is equally silent, on both paths. See the
// trust-boundary note at the top of verify.go -- write access to the cert Secret
// IS control of admission, and these rules bound partial tampering, not that.
//
// Both paths must reject the append, including the operator-managed one, which
// needs no existingCertSecret opt-in to reach.
// -----------------------------------------------------------------------------

func TestLoadSuppliedCertSecretRejectsAnAppendedRogueCA(t *testing.T) {
	opts := unmanagedOptions()
	legitimate := issueFor(t, opts)
	rogue := issueFor(t, opts)

	secret := suppliedCertSecret(opts, keyPair{
		certPEM: legitimate.certPEM,
		keyPEM:  legitimate.keyPEM,
		caPEM:   poisonedWith(legitimate, rogue),
	})

	_, err := LoadSuppliedCertSecret(context.Background(), newFakeClient(t, secret),
		opts.SecretKey(), opts.DNSName())
	if err == nil {
		t.Fatal("a ca.crt with an appended rogue CA must be refused: the real chain still verifies, " +
			"so nothing else would ever notice")
	}
	if !strings.Contains(err.Error(), "not part of the chain") {
		t.Fatalf("error should explain that the extra anchor is not part of the chain, got %v", err)
	}
}

func TestCABundleSyncerRefusesAPostStartupAppendOfARogueCA(t *testing.T) {
	opts := unmanagedOptions()
	legitimate := issueFor(t, opts)
	c := newFakeClient(t, suppliedCertSecret(opts, legitimate), mutatingWebhookConfig(opts, nil))

	syncer := NewCABundleSyncer(c, opts, make(chan struct{}))
	if err := syncer.SyncOnce(context.Background()); err != nil {
		t.Fatalf("first SyncOnce: %v", err)
	}

	rogue := issueFor(t, opts)
	live := &corev1.Secret{}
	if err := c.Get(context.Background(), opts.SecretKey(), live); err != nil {
		t.Fatalf("get secret: %v", err)
	}
	live.Data[caCertKey] = poisonedWith(legitimate, rogue)
	if err := c.Update(context.Background(), live); err != nil {
		t.Fatalf("simulate append: %v", err)
	}

	if err := syncer.SyncOnce(context.Background()); err == nil {
		t.Fatal("appending a rogue CA after startup must be refused")
	}

	config := &admissionregistrationv1.MutatingWebhookConfiguration{}
	if err := c.Get(context.Background(), types.NamespacedName{Name: opts.MutatingWebhookName}, config); err != nil {
		t.Fatalf("get webhook config: %v", err)
	}
	if !bytes.Equal(config.Webhooks[0].ClientConfig.CABundle, legitimate.caPEM) {
		t.Fatal("the published caBundle must still be the un-poisoned one")
	}
}

func TestAwaitWebhookCABundleRejectsAnAppendedRogueCAOnTheUserSuppliedPath(t *testing.T) {
	// The chain-PARTICIPATION rule, exercised where it is actually the rule that
	// fires. This case used to run on testOptions(), where cardinality rejects
	// any second certificate before participation is consulted -- so it asserted
	// on the cardinality message while its comment described participation, and
	// duplicated TestManagedPathRejectsAnyCABundleCardinalityOtherThanOne. On the
	// user-supplied path multi-certificate bundles are legitimate, so
	// participation is the only thing standing between an appended anchor and the
	// API server trusting it.
	//
	// It is the GATE that is under test here, not LoadSuppliedCertSecret: those
	// are two separate entry points into the same rules, and the gate is what
	// decides whether this replica joins the webhook Service's Endpoints.
	opts := unmanagedOptions()
	legitimate := issueFor(t, opts)
	rogue := issueFor(t, opts)
	opts.CertDir = certDirWith(t, legitimate)

	poisoned := poisonedWith(legitimate, rogue)
	secret := suppliedCertSecret(opts, legitimate)
	secret.Data[caCertKey] = poisoned
	c := newFakeClient(t, secret, mutatingWebhookConfig(opts, poisoned))

	err := awaitWithTimeout(t, c, opts, 20*time.Millisecond)
	if err == nil {
		t.Fatal("an appended rogue CA must not pass the readiness gate on the user-supplied path")
	}
	if !strings.Contains(err.Error(), "not part of the chain") {
		t.Fatalf("error should explain that the extra anchor is not part of the chain, got %v", err)
	}
}

// -----------------------------------------------------------------------------
// Legitimate multi-level chains must keep working
// -----------------------------------------------------------------------------

func TestLoadSuppliedCertSecretAcceptsALeafIntermediateRootChain(t *testing.T) {
	opts := unmanagedOptions()
	chain := issueChain(t, []string{opts.DNSName(), opts.ExtraDNSNames()[0]})

	// The usual enterprise shape: tls.crt carries leaf + intermediate, ca.crt
	// carries the root.
	secret := suppliedCertSecret(opts, keyPair{
		certPEM: chain.leafWithIntermediate(),
		keyPEM:  chain.leafKeyPEM,
		caPEM:   chain.rootPEM,
	})

	if _, err := LoadSuppliedCertSecret(context.Background(), newFakeClient(t, secret),
		opts.SecretKey(), opts.DNSName()); err != nil {
		t.Fatalf("a legitimate leaf -> intermediate -> root chain must be accepted, got %v", err)
	}
}

func TestLoadSuppliedCertSecretAcceptsACABundleCarryingIntermediateAndRoot(t *testing.T) {
	opts := unmanagedOptions()
	chain := issueChain(t, []string{opts.DNSName(), opts.ExtraDNSNames()[0]})

	// Also common: tls.crt is the leaf alone and ca.crt carries the whole trust
	// path. Verification terminates at the intermediate (it is in the root
	// pool), so the root only appears in a chain because ca.crt's certificates
	// are offered as intermediates too. Without that, the "nothing beyond the
	// chain" rule would reject this perfectly valid bundle.
	secret := suppliedCertSecret(opts, keyPair{
		certPEM: chain.leafPEM,
		keyPEM:  chain.leafKeyPEM,
		caPEM:   chain.intermediateAndRoot(),
	})

	if _, err := LoadSuppliedCertSecret(context.Background(), newFakeClient(t, secret),
		opts.SecretKey(), opts.DNSName()); err != nil {
		t.Fatalf("a ca.crt carrying both intermediate and root must be accepted, got %v", err)
	}
}

func TestSuppliedMultiLevelChainStillRejectsAnAppendedRogueCA(t *testing.T) {
	opts := unmanagedOptions()
	chain := issueChain(t, []string{opts.DNSName(), opts.ExtraDNSNames()[0]})
	rogue := issueFor(t, opts)

	secret := suppliedCertSecret(opts, keyPair{
		certPEM: chain.leafWithIntermediate(),
		keyPEM:  chain.leafKeyPEM,
		caPEM:   append(append([]byte{}, chain.rootPEM...), rogue.caPEM...),
	})

	_, err := LoadSuppliedCertSecret(context.Background(), newFakeClient(t, secret),
		opts.SecretKey(), opts.DNSName())
	if err == nil {
		t.Fatal("the anchor rule must still hold for multi-level chains")
	}
	if !strings.Contains(err.Error(), "not part of the chain") {
		t.Fatalf("error should explain the extra anchor, got %v", err)
	}
}

// -----------------------------------------------------------------------------
// Cross-signature bypass
//
// The append rule alone is defeated by cross-signing: the attacker mints a rogue
// root R, re-issues the legitimate CA's identity (same subject, same PUBLIC key
// -- readable straight out of the caBundle) under R, and appends both. R is then
// a genuine ancestor of the real chain, so it "participates" and looks used.
//
// Managed path: killed outright by the cardinality rule -- the operator issues
// exactly one certificate. User-supplied path: killed by the cross-signature
// rule, which is hygiene rather than a boundary (see the trust-boundary note in
// verify.go).
// -----------------------------------------------------------------------------

func crossSignedBundle(t *testing.T, dnsNames []string) (pair keyPair, poisoned []byte) {
	t.Helper()
	legit := newTestCA(t, "kagi-operator-ca")
	rogue := newTestCA(t, "ATTACKER-ROOT")
	pair = legit.issueLeaf(t, dnsNames)
	return pair, concatPEM(legit.pem, rogue.crossSign(t, legit), rogue.pem)
}

func TestLoadSuppliedCertSecretRejectsACrossSignedAppend(t *testing.T) {
	opts := unmanagedOptions()
	pair, poisoned := crossSignedBundle(t, []string{opts.DNSName(), opts.ExtraDNSNames()[0]})

	secret := suppliedCertSecret(opts, keyPair{
		certPEM: pair.certPEM,
		keyPEM:  pair.keyPEM,
		caPEM:   poisoned,
	})

	_, err := LoadSuppliedCertSecret(context.Background(), newFakeClient(t, secret),
		opts.SecretKey(), opts.DNSName())
	if err == nil {
		t.Fatal("a cross-signed append must be refused: the rogue root genuinely participates in a " +
			"verified chain, so the participation rule alone accepts it")
	}
	if !strings.Contains(err.Error(), "cross-signature") {
		t.Fatalf("error should name the cross-signature, got %v", err)
	}
}

func TestAwaitWebhookCABundleRejectsACrossSignedAppendOnTheUserSuppliedPath(t *testing.T) {
	// The CROSS-SIGNATURE rule, exercised where it is the rule that actually
	// fires. This case used to run on testOptions(), where cardinality rejects
	// the three-certificate bundle before the cross-signature scan is consulted
	// -- so it asserted on the cardinality message ("holds 3 certificates")
	// while its name promised cross-signature coverage, and pinned nothing that
	// TestManagedPathRejectsAnyCABundleCardinalityOtherThanOne does not already
	// pin. The managed path's defence against this bundle IS cardinality, and
	// that is the test which covers it.
	//
	// It is the GATE under test here, not LoadSuppliedCertSecret: those are two
	// separate entry points into the same rules, and the gate is what decides
	// whether this replica joins the webhook Service's Endpoints.
	opts := unmanagedOptions()
	pair, poisoned := crossSignedBundle(t, []string{opts.DNSName(), opts.ExtraDNSNames()[0]})
	opts.CertDir = certDirWith(t, pair)

	secret := suppliedCertSecret(opts, pair)
	secret.Data[caCertKey] = poisoned
	c := newFakeClient(t, secret, mutatingWebhookConfig(opts, poisoned))

	err := awaitWithTimeout(t, c, opts, 20*time.Millisecond)
	if err == nil {
		t.Fatal("a cross-signed append must not pass the readiness gate on the user-supplied path")
	}
	if !strings.Contains(err.Error(), "cross-signature") {
		t.Fatalf("error should name the cross-signature, got %v", err)
	}
}

func TestManagedPathRejectsAnyCABundleCardinalityOtherThanOne(t *testing.T) {
	opts := testOptions()
	first := issueFor(t, opts)
	second := issueFor(t, opts)
	opts.CertDir = certDirWith(t, first)

	// Two legitimately-issued CAs. Neither is rogue, but the operator mints
	// exactly one, so anything else means the Secret is not what it wrote.
	bundle := concatPEM(first.caPEM, second.caPEM)
	secret := managedSecret(opts, first)
	secret.Data[caCertKey] = bundle
	c := newFakeClient(t, secret, mutatingWebhookConfig(opts, bundle))

	err := awaitWithTimeout(t, c, opts, 20*time.Millisecond)
	if err == nil {
		t.Fatal("the managed path must accept exactly one certificate in ca.crt")
	}
	if !strings.Contains(err.Error(), "operator issues exactly one") {
		t.Fatalf("error should explain the cardinality rule, got %v", err)
	}
}

func TestUserSuppliedPathStillAcceptsLegitimateMultiCertBundles(t *testing.T) {
	// The cardinality rule must NOT leak onto the user-supplied path, where
	// multi-certificate bundles are the normal enterprise shape.
	opts := unmanagedOptions()
	chain := issueChain(t, []string{opts.DNSName(), opts.ExtraDNSNames()[0]})

	secret := suppliedCertSecret(opts, keyPair{
		certPEM: chain.leafPEM,
		keyPEM:  chain.leafKeyPEM,
		caPEM:   chain.intermediateAndRoot(),
	})

	if _, err := LoadSuppliedCertSecret(context.Background(), newFakeClient(t, secret),
		opts.SecretKey(), opts.DNSName()); err != nil {
		t.Fatalf("a two-certificate user-supplied bundle must still be accepted, got %v", err)
	}
}

// -----------------------------------------------------------------------------
// ManagedCertMonitor
// -----------------------------------------------------------------------------

func healthyManagedSecret(t *testing.T, opts Options) (*corev1.Secret, testCA) {
	t.Helper()
	ca := newTestCA(t, "kagi-operator-ca")
	leaf := ca.issueLeaf(t, []string{opts.DNSName(), opts.ExtraDNSNames()[0]})
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: opts.SecretName, Namespace: opts.Namespace},
		Type:       corev1.SecretTypeOpaque,
		Data: map[string][]byte{
			caCertKey:  ca.pem,
			caKeyKey:   pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(ca.key)}),
			tlsCertKey: leaf.certPEM,
			tlsKeyKey:  leaf.keyPEM,
		},
	}
	return secret, ca
}

func TestManagedCertMonitorLeavesAHealthySecretAlone(t *testing.T) {
	opts := testOptions()
	secret, _ := healthyManagedSecret(t, opts)
	c := newFakeClient(t, secret)

	repaired, err := NewManagedCertMonitor(c, nil, opts).CheckOnce(context.Background())
	if err != nil {
		t.Fatalf("CheckOnce: %v", err)
	}
	if repaired {
		t.Fatal("a healthy Secret must not be touched")
	}

	after := &corev1.Secret{}
	if err := c.Get(context.Background(), opts.SecretKey(), after); err != nil {
		t.Fatalf("get secret: %v", err)
	}
	if len(after.Data[caKeyKey]) == 0 {
		t.Fatal("the CA key was cleared on a healthy Secret")
	}
}

func TestManagedCertMonitorRepairsAnAppendedRogueCAViaTheCardinalityRule(t *testing.T) {
	opts := testOptions()
	secret, _ := healthyManagedSecret(t, opts)
	rogue := newTestCA(t, "ATTACKER-ROOT")
	secret.Data[caCertKey] = concatPEM(secret.Data[caCertKey], rogue.pem)
	c := newFakeClient(t, secret)

	monitor := NewManagedCertMonitor(c, nil, opts)

	// Which rule fires matters, because the obvious guess is wrong. The CA-key
	// check tamperReason leads with does NOT catch an append: X509KeyPair reads
	// only the FIRST certificate block, so legit||rogue against the legitimate
	// ca.key still pairs up cleanly. What rejects this Secret is cardinality --
	// the operator issues exactly one certificate -- so that is what the test
	// has to assert on, or it silently pins the wrong rule.
	if reason := monitor.tamperReason(secret); !strings.Contains(reason, "operator issues exactly one") {
		t.Fatalf("an appended rogue CA must be caught by the cardinality rule, got %q", reason)
	}

	repaired, err := monitor.CheckOnce(context.Background())
	if err != nil {
		t.Fatalf("CheckOnce must repair rather than error: %v", err)
	}
	if !repaired {
		t.Fatal("an appended rogue CA must trigger a repair")
	}

	// The repair invalidates ca.key, which is what makes cert-controller's next
	// reconcile mint a fresh single-certificate CA. Crucially it does NOT exit:
	// crashing would drop the operator out of Endpoints while the poisoned
	// caBundle stayed published, handing an attacker the admission traffic.
	after := &corev1.Secret{}
	if err := c.Get(context.Background(), opts.SecretKey(), after); err != nil {
		t.Fatalf("get secret: %v", err)
	}
	if len(after.Data[caKeyKey]) != 0 {
		t.Fatal("the CA key should have been invalidated to force a re-mint")
	}
}

func TestManagedCertMonitorRepairsASubstitutedCACertThatChainVerificationAccepts(t *testing.T) {
	opts := testOptions()
	secret, legit := healthyManagedSecret(t, opts)

	// The variant that defeats both the cardinality rule and chain verification:
	// smuggle a cross-certificate into tls.crt and replace ca.crt with the rogue
	// root alone. ca.crt then holds exactly one certificate and the served chain
	// verifies against it -- internally consistent. What it cannot fake is the CA
	// private key the operator still holds.
	rogue := newTestCA(t, "ATTACKER-ROOT")
	secret.Data[tlsCertKey] = concatPEM(secret.Data[tlsCertKey], rogue.crossSign(t, legit))
	secret.Data[caCertKey] = rogue.pem
	c := newFakeClient(t, secret)

	repaired, err := NewManagedCertMonitor(c, nil, opts).CheckOnce(context.Background())
	if err != nil {
		t.Fatalf("CheckOnce: %v", err)
	}
	if !repaired {
		t.Fatal("a substituted ca.crt must be detected via the CA private key it no longer matches")
	}
}

func TestManagedCertMonitorIgnoresAnUnpopulatedSecret(t *testing.T) {
	opts := testOptions()
	// Bootstrap in progress: EnsureCertSecret created the shell, the rotator has
	// not filled it in. Not tampering, and clearing anything here would fight
	// the bootstrap.
	c := newFakeClient(t, mutatingWebhookConfig(opts, nil))
	if err := EnsureCertSecret(context.Background(), c, opts.SecretKey()); err != nil {
		t.Fatalf("EnsureCertSecret: %v", err)
	}

	// A real recorder, so silence here is proven rather than assumed: the
	// keyless branch below DOES emit for a poisoned bootstrap, and an operator
	// that cried tampering on every cold start would train people to ignore the
	// one Event that matters.
	recorder := record.NewFakeRecorder(eventBuffer)
	repaired, err := NewManagedCertMonitor(c, recorder, opts).CheckOnce(context.Background())
	if err != nil {
		t.Fatalf("CheckOnce: %v", err)
	}
	if repaired {
		t.Fatal("an empty bootstrap Secret must not be treated as tampering")
	}
	if events := drainEvents(recorder); len(events) != 0 {
		t.Fatalf("an honest bootstrap must not emit a tampering Event, got %v", events)
	}
}

// TestManagedCertMonitorRepairNeitherLoopsNorGoesSilentOnTheSecondCheck pins the
// bootstrap-guard x forceReMint interaction, which nothing exercised because
// nothing called CheckOnce twice.
//
// The repair works by DELETING ca.key -- the same shape a half-written bootstrap
// Secret has. So the very state a successful repair leaves behind is the state
// the bootstrap guard exists to ignore, and the second check runs down the
// keyless branch with ca.crt still poisoned. Both failure modes there are real:
// repairing again would be a write loop against a Secret cert-controller has not
// re-minted yet, and returning early in silence would leave the one case that
// should shout loudest (poison, then remove ca.key) completely unreported --
// which is precisely the gap 74fda5c96 closed.
func TestManagedCertMonitorRepairNeitherLoopsNorGoesSilentOnTheSecondCheck(t *testing.T) {
	opts := testOptions()
	secret, _ := healthyManagedSecret(t, opts)
	rogue := newTestCA(t, "ATTACKER-ROOT")
	poisoned := concatPEM(secret.Data[caCertKey], rogue.pem)
	secret.Data[caCertKey] = poisoned
	// The MutatingWebhookConfiguration is the object Events are recorded
	// against; without it report() logs and gives up.
	c := newFakeClient(t, secret, mutatingWebhookConfig(opts, poisoned))

	recorder := record.NewFakeRecorder(eventBuffer)
	monitor := NewManagedCertMonitor(c, recorder, opts)

	repaired, err := monitor.CheckOnce(context.Background())
	if err != nil {
		t.Fatalf("first CheckOnce: %v", err)
	}
	if !repaired {
		t.Fatal("the first check must repair the poisoned ca.crt")
	}
	assertOneTamperEvent(t, recorder, "first check")

	after := &corev1.Secret{}
	if err := c.Get(context.Background(), opts.SecretKey(), after); err != nil {
		t.Fatalf("get secret: %v", err)
	}
	if len(after.Data[caKeyKey]) != 0 {
		t.Fatal("the repair should have invalidated the CA key")
	}
	if !bytes.Equal(after.Data[caCertKey], poisoned) {
		t.Fatal("the repair must not rewrite ca.crt itself; cert-controller owns the minting")
	}

	// Second check: ca.key is gone and ca.crt is still poisoned, because
	// cert-controller has not reconciled in this test.
	repaired, err = monitor.CheckOnce(context.Background())
	if err != nil {
		t.Fatalf("second CheckOnce: %v", err)
	}
	if repaired {
		t.Fatal("the second check must not report another repair: ca.key is already gone, so re-deleting it " +
			"would be a needless write every interval until cert-controller re-mints")
	}
	assertOneTamperEvent(t, recorder, "second check")
}

// eventBuffer is generous on purpose: FakeRecorder DROPS events once its channel
// is full, so a tight buffer would turn "emitted too many" into "emitted
// exactly one" and hide the failure being tested.
const eventBuffer = 8

func assertOneTamperEvent(t *testing.T, recorder *record.FakeRecorder, when string) {
	t.Helper()
	events := drainEvents(recorder)
	if len(events) != 1 {
		t.Fatalf("%s: expected exactly one tampering Event, got %d: %v", when, len(events), events)
	}
	if !strings.Contains(events[0], eventReasonCertTampered) {
		t.Fatalf("%s: Event should carry reason %q, got %q", when, eventReasonCertTampered, events[0])
	}
	if !strings.Contains(events[0], "operator issues exactly one") {
		t.Fatalf("%s: Event should explain what was wrong with the Secret, got %q", when, events[0])
	}
}

func drainEvents(recorder *record.FakeRecorder) []string {
	var events []string
	for {
		select {
		case e := <-recorder.Events:
			events = append(events, e)
		default:
			return events
		}
	}
}

func TestUserSuppliedPathAcceptsDuplicatedAnchors(t *testing.T) {
	// Concatenating corporate bundles duplicates anchors routinely. An exact
	// duplicate is the same anchor listed twice -- it grants no trust the bundle
	// did not already grant -- so it must not be mistaken for a cross-signature,
	// which would send the operator hunting for one that does not exist.
	opts := unmanagedOptions()
	chain := issueChain(t, []string{opts.DNSName(), opts.ExtraDNSNames()[0]})

	bundles := map[string][]byte{
		"root+root":                      concatPEM(chain.rootPEM, chain.rootPEM),
		"intermediate+root+root":         concatPEM(chain.intermediatePEM, chain.rootPEM, chain.rootPEM),
		"intermediate+intermediate+root": concatPEM(chain.intermediatePEM, chain.intermediatePEM, chain.rootPEM),
	}

	for name, caPEM := range bundles {
		t.Run(name, func(t *testing.T) {
			secret := suppliedCertSecret(opts, keyPair{
				certPEM: chain.leafWithIntermediate(),
				keyPEM:  chain.leafKeyPEM,
				caPEM:   caPEM,
			})

			if _, err := LoadSuppliedCertSecret(context.Background(), newFakeClient(t, secret),
				opts.SecretKey(), opts.DNSName()); err != nil {
				t.Fatalf("a bundle with duplicated anchors must be accepted, got %v", err)
			}
		})
	}
}

func TestCrossSignatureIsStillRejectedAlongsideADuplicatedAnchor(t *testing.T) {
	// The duplicate skip must not become a hole: a genuine cross-signature
	// sitting next to a harmless duplicate is still rejected.
	opts := unmanagedOptions()
	legit := newTestCA(t, "kagi-operator-ca")
	rogue := newTestCA(t, "ATTACKER-ROOT")
	pair := legit.issueLeaf(t, []string{opts.DNSName(), opts.ExtraDNSNames()[0]})

	secret := suppliedCertSecret(opts, keyPair{
		certPEM: pair.certPEM,
		keyPEM:  pair.keyPEM,
		caPEM:   concatPEM(legit.pem, legit.pem, rogue.crossSign(t, legit), rogue.pem),
	})

	_, err := LoadSuppliedCertSecret(context.Background(), newFakeClient(t, secret),
		opts.SecretKey(), opts.DNSName())
	if err == nil {
		t.Fatal("a cross-signature must still be rejected when a duplicate anchor is also present")
	}
	if !strings.Contains(err.Error(), "cross-signature") {
		t.Fatalf("error should name the cross-signature, got %v", err)
	}
}

// TestCrossSignatureScanCoversBothFields is the regression matrix for the
// cross-signature bypass. The rule originally scanned ca.crt only, so a
// cross-certificate parked in tls.crt was never inspected -- yet it still made
// the attacker's root a genuine ancestor of the real chain and satisfied the
// participation rule. Cases D/E/F are the legitimate enterprise shapes the
// widened intermediate pool exists for; they pass only because byte-identical
// entries are skipped, since real bundles repeat an intermediate across both
// fields.
func TestCrossSignatureScanCoversBothFields(t *testing.T) {
	opts := unmanagedOptions()
	dns := opts.DNSName()
	root := newTestCA(t, "corp-root-ca")
	rogue := newTestCA(t, "rogue-root")
	leaf := root.issueLeaf(t, []string{dns, opts.ExtraDNSNames()[0]})
	cross := rogue.crossSign(t, root)
	chain := issueChain(t, []string{dns, opts.ExtraDNSNames()[0]})

	cases := []struct {
		name       string
		certPEM    []byte
		caPEM      []byte
		wantReject bool
	}{
		{"cross-cert in ca.crt", leaf.certPEM, concatPEM(root.pem, cross, rogue.pem), true},
		{"cross-cert in tls.crt", concatPEM(leaf.certPEM, cross), concatPEM(root.pem, rogue.pem), true},
		{"plain appended rogue root", leaf.certPEM, concatPEM(root.pem, rogue.pem), true},
		{"legit: ca.crt intermediate+root", chain.leafWithIntermediate(), chain.intermediateAndRoot(), false},
		{"legit: ca.crt root only", chain.leafWithIntermediate(), chain.rootPEM, false},
		{"legit: duplicated anchors", chain.leafWithIntermediate(),
			concatPEM(chain.intermediatePEM, chain.rootPEM, chain.rootPEM), false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := verifyCertChain(tc.certPEM, tc.caPEM, dns, caPolicyUserSupplied)
			if rejected := err != nil; rejected != tc.wantReject {
				t.Fatalf("rejected=%v, want %v (err=%v)", rejected, tc.wantReject, err)
			}
		})
	}
}

func TestAwaitWebhookCABundleRejectsASubstitutedCAOnTheManagedPath(t *testing.T) {
	// Scenario H: ca.crt replaced by a single rogue root, with a
	// cross-certificate hidden in tls.crt. Cardinality is satisfied (one
	// certificate) and the chain verifies, so without the CA-private-key check
	// the gate lets the operator go Ready with a rogue anchor published, leaving
	// only the monitor to catch it up to 5 minutes later. The gate and the
	// monitor must enforce the same rules.
	opts := testOptions()
	legit := newTestCA(t, "kagi-operator-ca")
	rogue := newTestCA(t, "ATTACKER-ROOT")
	leaf := legit.issueLeaf(t, []string{opts.DNSName(), opts.ExtraDNSNames()[0]})

	opts.CertDir = certDirWith(t, keyPair{
		certPEM: concatPEM(leaf.certPEM, rogue.crossSign(t, legit)),
		keyPEM:  leaf.keyPEM,
	})
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: opts.SecretName, Namespace: opts.Namespace},
		Type:       corev1.SecretTypeOpaque,
		Data: map[string][]byte{
			caCertKey:  rogue.pem,
			caKeyKey:   pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(legit.key)}),
			tlsCertKey: concatPEM(leaf.certPEM, rogue.crossSign(t, legit)),
			tlsKeyKey:  leaf.keyPEM,
		},
	}
	c := newFakeClient(t, secret, mutatingWebhookConfig(opts, rogue.pem))

	err := awaitWithTimeout(t, c, opts, 20*time.Millisecond)
	if err == nil {
		t.Fatal("a substituted ca.crt must not pass the readiness gate on the managed path")
	}
	if !strings.Contains(err.Error(), "no longer matches the CA private key") {
		t.Fatalf("error should name the CA private key mismatch, got %v", err)
	}
}
