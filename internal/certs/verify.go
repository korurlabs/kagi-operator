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
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// This file holds the actual X.509 checks.
//
// # Trust boundary (read this first)
//
// WRITE ACCESS TO THE CERTIFICATE SECRET IS EQUIVALENT TO CONTROL OF WEBHOOK
// ADMISSION. That is inherent to the cert-controller pattern -- Gatekeeper and
// Istio share it -- and no amount of verification here changes it: an attacker
// who can write the Secret can always construct a fully self-consistent
// (ca.crt, ca.key, tls.crt, tls.key) set that verifies perfectly and publishes
// their own CA as the API server's trust anchor. It was demonstrated, on both
// paths, with no restart required.
//
// So the checks below are NOT a boundary against someone with that access.
// What they are: a boundary against PARTIAL tampering -- the far likelier
// shape, where an attacker can append to or swap one field of the Secret but
// cannot produce a coherent replacement -- plus real protection against honest
// misconfiguration. Treat RBAC on the Secret as the actual control.
//
// # Who enforces what
//
// The two paths do not get the same rules, and on the managed path two of the
// rules below are satisfied trivially rather than doing any work. Stated once,
// here, so that no rule further down is read as load-bearing everywhere:
//
//	rule                  managed (operator-issued)       user-supplied
//	--------------------- ------------------------------- -------------------------
//	keypair, chain,       enforced                        enforced
//	SANs, expiry
//
//	cardinality           enforced, and decisive: exactly not applicable -- a real
//	(ca.crt holds one)    one certificate, which makes    bundle legitimately
//	                      every ca.crt-side append and    carries intermediates
//	                      cross-sign shape unreachable
//
//	chain participation   reached but vacuous: cardinality enforced. On this path
//	                      forces len(caCerts)==1 and every it is the only defence
//	                      returned chain ends at that one  against an APPENDED
//	                      root, so it can never fail       anchor
//
//	cross-signature       reachable, but only over the    enforced. Without it the
//	(union of ca.crt and  trailing certificates of        participation rule above
//	 tls.crt)             tls.crt -- the ca.crt side is   is defeated outright
//	                      already excluded by cardinality
//
//	ca.crt still matches  enforced, by ManagedCertMonitor not applicable -- the
//	ca.key                AND by the readiness gate       operator holds no private
//	                      (caBundleMatches). This is what key here, so nothing can
//	                      catches the ca.crt substitution distinguish a coherent
//	                      chain verification misses       substitution from a
//	                                                      legitimate CA rotation
//
// The gate and the monitor must keep enforcing the SAME set. Whichever is
// weaker defines the security of the path, and the gate is what decides whether
// this operator joins the webhook Service's Endpoints.
//
// # What is enforced, and why
//
//  1. SUBSTITUTION of ca.crt. A Secret whose ca.crt was an unrelated CA used to
//     be accepted and published verbatim.
//
//     Chain verification catches the SIMPLE form -- ca.crt swapped and nothing
//     else -- because tls.crt still chains to the original CA and does not
//     chain to the substitute. It does NOT catch the form where a
//     cross-certificate of the real CA, signed by the attacker's root, is
//     parked in tls.crt: the substituted root is then a genuine ancestor of the
//     real leaf, so the chain verifies, and on the managed path the single
//     substituted certificate satisfies cardinality as well.
//
//     What catches that form is ca.crt still matching the ca.key sitting in the
//     SAME Secret -- checked by ManagedCertMonitor.tamperReason and by
//     caBundleMatches. It is a managed-path rule only, and it bounds partial
//     tampering rather than full replacement (see the boundary note above:
//     whoever can rewrite ca.crt can rewrite ca.key beside it). monitor.go
//     states the same thing at its own check; if you change one, change both.
//
//  2. ADDITION to ca.crt. Chain verification alone does NOT catch it: loading
//     every certificate in ca.crt into the root pool and asking whether the leaf
//     chains to *some* root lets an attacker APPEND a rogue CA and leave the
//     legitimate one in place. The real chain still verifies, nothing fails,
//     nothing logs, the operator reports Ready -- and the API server now also
//     trusts a CA the attacker holds the key to. It reached the
//     operator-managed path with no existingCertSecret opt-in, because
//     cert-controller's validCACert only decodes the FIRST block of ca.crt, so
//     it sees a healthy CA, declines to re-mint, and republishes the poisoned
//     bundle verbatim.
//
//     Two rules address it. On the operator-managed path, ca.crt must contain
//     EXACTLY ONE certificate -- cert-controller writes exactly one, so this is
//     decisive and cannot regress a legitimate bundle. On the user-supplied
//     path, where multi-certificate bundles are legitimate, the weaker
//     chain-participation rule applies (see verifyCertChain).
//
//  3. NON-CERTIFICATES. Setting ca.crt, tls.crt, tls.key and the caBundle all
//     to the same non-certificate string made the startup gate report "in sync"
//     and register the webhook. A byte comparison is tautological on the
//     user-supplied path anyway, where the syncer compares its own write
//     against itself.
//
// The friendliest failure these also catch is the likeliest one for a
// bring-your-own-certificate user: guessing the <svc>.<ns>.svc DNS name wrong,
// which otherwise produces a healthy-looking operator and silently broken
// admission.

// caPolicy selects how strictly a ca.crt bundle is judged. The two paths differ
// in what is knowable: on the managed path the operator minted the CA itself and
// knows there is exactly one, while a user-supplied bundle legitimately carries
// a chain.
type caPolicy int

const (
	// caPolicyOperatorIssued applies to certificates the operator mints.
	// cert-controller's populateSecret writes a single PEM block into ca.crt, so
	// anything else is tampering, full stop.
	caPolicyOperatorIssued caPolicy = iota
	// caPolicyUserSupplied applies to injection.existingCertSecret. Bundles here
	// legitimately carry intermediates and roots, so only the weaker
	// chain-participation rule can be applied. It is hygiene, not a boundary.
	caPolicyUserSupplied
)

// parseCerts returns every certificate in a PEM bundle, in order.
//
// An unparseable CERTIFICATE block is a hard error rather than something to skip
// past: this material decides what the API server trusts, so "most of it parsed"
// is not a state worth proceeding from.
func parseCerts(pemBytes []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	rest := pemBytes
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		parsed, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("contains an unparseable certificate: %w", err)
		}
		certs = append(certs, parsed)
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("contains no PEM-encoded certificate")
	}
	return certs, nil
}

// parseCertChain splits a serving bundle into its leaf (the first certificate)
// and the intermediates that follow. Corporate PKIs routinely issue leaf ->
// intermediate -> root and their tooling emits the leaf and intermediates
// together in tls.crt, so ignoring the trailing blocks would reject perfectly
// valid enterprise certificates -- the exact users this path exists for.
//
// The intermediates are returned as a SLICE rather than a pool because they must
// be inspected, not just consulted: they end up in the verification pool, so they
// have to face the same cross-signature scan ca.crt does. Handing back an opaque
// pool is what let a cross-certificate hide in tls.crt.
func parseCertChain(pemBytes []byte) (leaf *x509.Certificate, intermediates []*x509.Certificate, err error) {
	certs, err := parseCerts(pemBytes)
	if err != nil {
		return nil, nil, err
	}
	return certs[0], certs[1:], nil
}

// rejectCrossSignatures fails when two DIFFERENT certificates in the set share a
// subject and a public key, i.e. one re-issues the other under another signer.
//
// It must be given every certificate the verifier will consider -- ca.crt AND
// the trailing intermediates from tls.crt -- because chains are built through
// both. Scanning ca.crt alone leaves the bypass open one field over: a
// cross-certificate parked in tls.crt never gets looked at, yet still makes the
// attacker's root a genuine ancestor of the real chain and so satisfies the
// participation rule.
//
// Byte-identical entries are skipped: that is the same anchor listed twice,
// which real bundles do constantly (concatenating a root file onto a chain file
// repeats the intermediate across both fields). Without that skip this scan
// false-positives on essentially every legitimate enterprise bundle.
func rejectCrossSignatures(certs []*x509.Certificate) error {
	for i := range certs {
		for j := i + 1; j < len(certs); j++ {
			if bytes.Equal(certs[i].Raw, certs[j].Raw) {
				continue
			}
			if bytes.Equal(certs[i].RawSubject, certs[j].RawSubject) &&
				bytes.Equal(certs[i].RawSubjectPublicKeyInfo, certs[j].RawSubjectPublicKeyInfo) {
				return fmt.Errorf("contains two different certificates for the same subject %q with the same "+
					"public key, i.e. a cross-signature; publishing it would let the second signer's root "+
					"become a trust anchor", certs[i].Subject)
			}
		}
	}
	return nil
}

// verifyServingCert checks that certPEM and keyPEM are a usable serving keypair,
// that the certificate chains to caPEM, and that it is currently valid for
// dnsName as a server certificate.
//
// This is the whole trust decision in one place: it is what makes publishing
// caPEM as the webhook's caBundle a safe thing to do.
func verifyServingCert(certPEM, keyPEM, caPEM []byte, dnsName string, policy caPolicy) error {
	if _, err := tls.X509KeyPair(certPEM, keyPEM); err != nil {
		return fmt.Errorf("%q and %q are not a matching keypair: %w", tlsCertKey, tlsKeyKey, err)
	}
	return verifyCertChain(certPEM, caPEM, dnsName, policy)
}

// verifyCertChain checks that certPEM chains to caPEM, is valid for dnsName
// right now, and that caPEM carries no trust anchor beyond what that chain
// needs.
//
// Every certificate in caPEM becomes an API server trust anchor for this
// webhook, so "does the leaf chain to something in here" is the wrong question:
// an attacker who appends a rogue CA and leaves the real one alone passes it
// with the real chain while quietly adding their own key to the trust store.
//
// How strict the anchor rule can be depends on the policy:
//
//   - caPolicyOperatorIssued: caPEM must hold EXACTLY ONE certificate.
//     cert-controller writes exactly one, so this is decisive against every
//     append and cross-sign variant, and cannot reject a legitimate bundle.
//
//   - caPolicyUserSupplied: multi-certificate bundles are legitimate here, so
//     the rule is only that every certificate in caPEM participated in a
//     verified chain, plus a rejection of cross-certificates (below). This is
//     BEST-EFFORT HYGIENE, NOT A SECURITY BOUNDARY -- see the trust-boundary
//     note at the top of this file. It does reject an unused cross-signed
//     second root kept for a migration; that is a considered choice, since an
//     unused anchor in a webhook caBundle grants trust nothing here needs.
//
// Split out from verifyServingCert because the caBundle gate verifies a
// certificate against a published CA without needing the private key.
func verifyCertChain(certPEM, caPEM []byte, dnsName string, policy caPolicy) error {
	caCerts, err := parseCerts(caPEM)
	if err != nil {
		return fmt.Errorf("%q %w, so it cannot be published as a caBundle", caCertKey, err)
	}

	// The decisive check on the managed path. Cheap, exact, and it makes every
	// ca.crt-side append attack below unreachable there.
	//
	// The message names the benign cause too, because it is the likelier one: a
	// user who pre-created the Secret from their own corporate bundle and never
	// set injection.existingCertSecret lands here, and being told they have been
	// breached -- moments before the operator deletes their ca.key and overwrites
	// the Secret -- is both wrong and alarming.
	if policy == caPolicyOperatorIssued && len(caCerts) != 1 {
		return fmt.Errorf("%q holds %d certificates but the operator issues exactly one; "+
			"the extra entries would become API server trust anchors, so either this Secret has been tampered with, "+
			"or -- if this is your own PKI bundle -- set injection.existingCertSecret "+
			"(--webhook-cert-managed=false) so the operator reads it instead of managing this Secret",
			caCertKey, len(caCerts))
	}

	leaf, chainIntermediates, err := parseCertChain(certPEM)
	if err != nil {
		return fmt.Errorf("%q %w", tlsCertKey, err)
	}

	// Scan the UNION of everything the verifier will consider. Chains are built
	// through ca.crt AND the trailing intermediates of tls.crt, so scanning
	// ca.crt alone left the bypass open one field over: a cross-certificate
	// parked in tls.crt was never inspected, yet still made the attacker's root
	// a genuine ancestor of the real chain and satisfied the participation rule
	// below.
	if err := rejectCrossSignatures(append(append([]*x509.Certificate{}, caCerts...), chainIntermediates...)); err != nil {
		return fmt.Errorf("the certificate material %w", err)
	}

	intermediates := x509.NewCertPool()
	for _, c := range chainIntermediates {
		intermediates.AddCert(c)
	}

	roots := x509.NewCertPool()
	for _, c := range caCerts {
		roots.AddCert(c)
		// Also offered as intermediates so that a ca.crt shipping BOTH an
		// intermediate and its root builds the full leaf -> intermediate -> root
		// chain. Without this, verification stops at the intermediate (it is in
		// the root pool, so it terminates the chain), the root never appears in
		// any chain, and the participation rule below would reject a completely
		// legitimate bundle. Three real-world shapes depend on it.
		//
		// This DOES widen what can appear "used": a rogue root that signs a
		// cross-certificate of the real CA enters a genuine chain and satisfies
		// the participation rule. That is why the cross-signature rejection
		// above exists, and why the participation rule is documented as hygiene
		// rather than a boundary. An earlier version of this comment claimed
		// widening the pool "cannot let an unrelated CA in" -- that was wrong,
		// and a confident comment asserting a security property is worse than no
		// comment at all.
		intermediates.AddCert(c)
	}

	// Checked before Verify purely for the error message: x509's own expiry
	// error does not say which certificate expired or when.
	now := time.Now()
	if now.After(leaf.NotAfter) {
		return fmt.Errorf("%q expired at %s", tlsCertKey, leaf.NotAfter.Format(time.RFC3339))
	}
	if now.Before(leaf.NotBefore) {
		return fmt.Errorf("%q is not valid until %s (check clock skew)", tlsCertKey, leaf.NotBefore.Format(time.RFC3339))
	}

	chains, err := leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		DNSName:       dnsName,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		CurrentTime:   now,
	})
	if err != nil {
		return fmt.Errorf("%q does not chain to %q as a server certificate for %q (SANs present: %v): %w",
			tlsCertKey, caCertKey, dnsName, leaf.DNSNames, err)
	}

	verified := map[[32]byte]bool{}
	for _, chain := range chains {
		for _, c := range chain {
			verified[sha256.Sum256(c.Raw)] = true
		}
	}
	for _, c := range caCerts {
		if !verified[sha256.Sum256(c.Raw)] {
			return fmt.Errorf("%q contains certificate %q, which is not part of the chain that signs %q; "+
				"publishing it would make the API server trust a CA unrelated to this webhook",
				caCertKey, c.Subject, tlsCertKey)
		}
	}
	return nil
}

// verifyServedCertOnDisk runs verifyServingCert against the files the webhook
// server actually reads, rather than against the API objects.
//
// The distinction matters during rotation: the caBundle is patched the instant
// the Secret is written, but the pod serves from a kubelet-projected volume that
// can lag by up to a minute. Checking the API objects alone would declare the
// webhook ready while it is still presenting the previous leaf, which the API
// server -- now trusting only the new CA -- would reject.
func verifyServedCertOnDisk(certDir string, caPEM []byte, dnsName string, policy caPolicy) error {
	certPath := filepath.Join(certDir, tlsCertKey)
	keyPath := filepath.Join(certDir, tlsKeyKey)

	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return fmt.Errorf("cannot read the served certificate %s: %w", certPath, err)
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return fmt.Errorf("cannot read the served key %s: %w", keyPath, err)
	}

	if err := verifyServingCert(certPEM, keyPEM, caPEM, dnsName, policy); err != nil {
		return fmt.Errorf("the certificate served from %s does not match the published caBundle: %w", certDir, err)
	}
	return nil
}
