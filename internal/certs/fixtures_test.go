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
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/open-policy-agent/cert-controller/pkg/rotator"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

// Shared fixtures. Certificates here are REAL: the code under test now performs
// actual chain and SAN verification, so string placeholders like "ca-pem" would
// only prove that a placeholder is rejected.

func testOptions() Options {
	return Options{
		Namespace:           "kagi-operator-system",
		SecretName:          "kagi-operator-webhook-server-cert",
		ServiceName:         "kagi-operator-webhook",
		MutatingWebhookName: "kagi-operator-mutating-webhook-configuration",
		CertDir:             DefaultCertDir,
		CABundleWaitTimeout: time.Minute,
	}
}

func unmanagedOptions() Options {
	opts := testOptions()
	opts.UserSuppliedCertificate = true
	opts.SecretName = "corp-pki-webhook-cert"
	return opts
}

func testScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(s); err != nil {
		t.Fatalf("add clientgo scheme: %v", err)
	}
	return s
}

func newFakeClient(t *testing.T, objects ...client.Object) client.Client {
	t.Helper()
	return fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(objects...).Build()
}

func newFakeClientWithInterceptor(t *testing.T, funcs interceptor.Funcs, objects ...client.Object) client.Client {
	t.Helper()
	return fake.NewClientBuilder().
		WithScheme(testScheme(t)).
		WithObjects(objects...).
		WithInterceptorFuncs(funcs).
		Build()
}

// keyPair is a CA plus one leaf issued by it.
type keyPair struct {
	caPEM   []byte
	certPEM []byte
	keyPEM  []byte
}

// newRotatorUnderTest mirrors exactly what Setup hands to cert-controller, so
// the fixtures exercise the same certificate shape the operator really issues.
func newRotatorUnderTest(opts Options) *rotator.CertRotator {
	return &rotator.CertRotator{
		SecretKey:      opts.SecretKey(),
		CertDir:        opts.CertDir,
		CAName:         caName,
		CAOrganization: caOrganization,
		DNSName:        opts.DNSName(),
		ExtraDNSNames:  opts.ExtraDNSNames(),
		ExtKeyUsages:   &[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
}

// issueFor mints a fresh CA and a leaf valid for opts' Service DNS name.
func issueFor(t *testing.T, opts Options) keyPair {
	t.Helper()
	return issueForWindow(t, opts, time.Now().Add(-time.Hour), time.Now().Add(serverCertDuration))
}

func issueForWindow(t *testing.T, opts Options, notBefore, notAfter time.Time) keyPair {
	t.Helper()
	cr := newRotatorUnderTest(opts)
	ca, err := cr.CreateCACert(notBefore, notAfter)
	if err != nil {
		t.Fatalf("CreateCACert: %v", err)
	}
	certPEM, keyPEM, err := cr.CreateCertPEM(ca, notBefore, notAfter)
	if err != nil {
		t.Fatalf("CreateCertPEM: %v", err)
	}
	return keyPair{caPEM: ca.CertPEM, certPEM: certPEM, keyPEM: keyPEM}
}

// certDirWith writes a keypair where the webhook server would read it, and
// returns the directory. The kubelet does this in a real cluster.
func certDirWith(t *testing.T, pair keyPair) string {
	t.Helper()
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, tlsCertKey), pair.certPEM)
	writeFile(t, filepath.Join(dir, tlsKeyKey), pair.keyPEM)
	return dir
}

func writeFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// managedSecret is what the rotator leaves behind on the operator-managed path.
func managedSecret(opts Options, pair keyPair) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: opts.SecretName, Namespace: opts.Namespace},
		Type:       corev1.SecretTypeOpaque,
		Data: map[string][]byte{
			caCertKey:  pair.caPEM,
			tlsCertKey: pair.certPEM,
			tlsKeyKey:  pair.keyPEM,
		},
	}
}

// suppliedCertSecret is what a customer's PKI would produce.
func suppliedCertSecret(opts Options, pair keyPair) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: opts.SecretName, Namespace: opts.Namespace},
		Type:       corev1.SecretTypeTLS,
		Data: map[string][]byte{
			tlsCertKey: pair.certPEM,
			tlsKeyKey:  pair.keyPEM,
			caCertKey:  pair.caPEM,
		},
	}
}

func mutatingWebhookConfig(opts Options, caBundles ...[]byte) *admissionregistrationv1.MutatingWebhookConfiguration {
	config := &admissionregistrationv1.MutatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: opts.MutatingWebhookName},
	}
	for i, caBundle := range caBundles {
		config.Webhooks = append(config.Webhooks, admissionregistrationv1.MutatingWebhook{
			Name: webhookEntryName(i),
			ClientConfig: admissionregistrationv1.WebhookClientConfig{
				CABundle: caBundle,
			},
		})
	}
	return config
}

// webhookEntryName names the i-th webhook entry. The first two keep the names
// the existing assertions match on; anything beyond them is generated, so a
// third caBundle argument widens the fixture instead of panicking on a
// hard-coded two-element slice -- which is the wrong failure for a test helper
// to hand back when someone extends a case.
func webhookEntryName(i int) string {
	switch i {
	case 0:
		return "mpod.kagi.pw"
	case 1:
		return "second.kagi.pw"
	default:
		return fmt.Sprintf("entry-%d.kagi.pw", i)
	}
}

// poisonedWith returns a ca.crt bundle that keeps the legitimate CA and APPENDS
// a rogue one. This is the addition attack: the real chain still verifies, so
// nothing breaks, nothing logs, and the API server quietly gains a second trust
// anchor whose key the attacker holds.
func poisonedWith(legitimate, rogue keyPair) []byte {
	return append(append([]byte{}, legitimate.caPEM...), rogue.caPEM...)
}

// chainFixture is a real three-level PKI: root -> intermediate -> leaf. The
// rotator primitives only mint two-level chains, but enterprise PKIs -- the
// users the bring-your-own-certificate path exists for -- routinely use three.
type chainFixture struct {
	rootPEM         []byte
	intermediatePEM []byte
	leafPEM         []byte
	leafKeyPEM      []byte
}

// leafWithIntermediate is the usual tls.crt shape: leaf first, then the
// intermediates needed to reach the root.
func (c chainFixture) leafWithIntermediate() []byte {
	return append(append([]byte{}, c.leafPEM...), c.intermediatePEM...)
}

// intermediateAndRoot is the ca.crt shape that verification has to accept even
// though the leaf alone chains to the intermediate: both are legitimately part
// of the trust path.
func (c chainFixture) intermediateAndRoot() []byte {
	return append(append([]byte{}, c.intermediatePEM...), c.rootPEM...)
}

func issueChain(t *testing.T, dnsNames []string) chainFixture {
	t.Helper()

	now := time.Now()
	notBefore, notAfter := now.Add(-time.Hour), now.Add(serverCertDuration)

	rootKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate root key: %v", err)
	}
	rootTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-root-ca"},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, rootKey.Public(), rootKey)
	if err != nil {
		t.Fatalf("create root: %v", err)
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatalf("parse root: %v", err)
	}

	intermediateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate intermediate key: %v", err)
	}
	intermediateTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "test-intermediate-ca"},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	intermediateDER, err := x509.CreateCertificate(rand.Reader, intermediateTemplate, root, intermediateKey.Public(), rootKey)
	if err != nil {
		t.Fatalf("create intermediate: %v", err)
	}
	intermediate, err := x509.ParseCertificate(intermediateDER)
	if err != nil {
		t.Fatalf("parse intermediate: %v", err)
	}

	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(3),
		Subject:               pkix.Name{CommonName: dnsNames[0]},
		DNSNames:              dnsNames,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, intermediate, leafKey.Public(), intermediateKey)
	if err != nil {
		t.Fatalf("create leaf: %v", err)
	}

	encode := func(kind string, der []byte) []byte {
		return pem.EncodeToMemory(&pem.Block{Type: kind, Bytes: der})
	}
	return chainFixture{
		rootPEM:         encode("CERTIFICATE", rootDER),
		intermediatePEM: encode("CERTIFICATE", intermediateDER),
		leafPEM:         encode("CERTIFICATE", leafDER),
		leafKeyPEM:      encode("RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(leafKey)),
	}
}

// testCA is a CA whose private key the test holds, so it can mint children and
// build the cross-signature the append bypass depends on.
type testCA struct {
	cert *x509.Certificate
	key  *rsa.PrivateKey
	pem  []byte
}

func encodeCert(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func newTestCA(t *testing.T, commonName string) testCA {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: commonName},
		DNSNames:              []string{commonName},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(serverCertDuration),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatalf("create CA: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse CA: %v", err)
	}
	return testCA{cert: cert, key: key, pem: encodeCert(der)}
}

// issueLeaf mints a serving certificate under ca for the given DNS names.
func (ca testCA) issueLeaf(t *testing.T, dnsNames []string) keyPair {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: dnsNames[0]},
		DNSNames:              dnsNames,
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(serverCertDuration),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, key.Public(), ca.key)
	if err != nil {
		t.Fatalf("create leaf: %v", err)
	}
	return keyPair{
		caPEM:   ca.pem,
		certPEM: encodeCert(der),
		keyPEM:  pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}),
	}
}

// crossSign re-issues target's identity -- same RawSubject, same PUBLIC key --
// under ca's signature. This is the bypass primitive: it needs only the target's
// public key, which is published in the caBundle for anyone to read, and it
// makes ca a genuine ancestor of anything target signed. Appending
// [crossCert, ca] to a ca.crt that still contains target therefore satisfies a
// naive "every anchor participated in a verified chain" rule.
func (ca testCA) crossSign(t *testing.T, target testCA) []byte {
	t.Helper()
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(3),
		RawSubject:            target.cert.RawSubject,
		SubjectKeyId:          target.cert.SubjectKeyId,
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(serverCertDuration),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, target.cert.PublicKey, ca.key)
	if err != nil {
		t.Fatalf("cross-sign: %v", err)
	}
	return encodeCert(der)
}

func concatPEM(parts ...[]byte) []byte {
	size := 0
	for _, p := range parts {
		size += len(p)
	}
	out := make([]byte, 0, size)
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}
