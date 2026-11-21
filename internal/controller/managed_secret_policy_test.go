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
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	kagiv1alpha1 "github.com/korurlabs/kagi-operator/api/v1alpha1"
)

// These tests cover what a KagiSecret or KagiCertificate may point the
// operator at, beyond who owns the managed Secret: which namespaces it may
// name, which legacy Secrets it may adopt, which Secret types it may ask for,
// and what happens when the deletion of its managed Secret fails.

const (
	// productionOperatorNamespace is the operator's namespace in the cluster.
	productionOperatorNamespace = "kagi-operator-system"

	// attackerNamespace is a namespace whose users may create resources but
	// may not read or write Secrets in victimNamespace.
	attackerNamespace = "attacker"

	// tokenSecretName is the name of the token Secret a resource names.
	tokenSecretName = "token"
)

// resourceUnderTest is one KagiSecret or KagiCertificate and how to drive it.
type resourceUnderTest struct {
	kind string
	obj  client.Object

	// reconcile runs one Reconcile of obj.
	reconcile func(c client.Client, kagiAPIURL, operatorNamespace string, recorder record.EventRecorder) error

	// status returns the stored Ready condition and LastErrorMessage of obj.
	status func(t *testing.T, c client.Client) (*metav1.Condition, string)
}

// resourceSpec places a resource and the Secrets it names.
type resourceSpec struct {
	namespace        string
	tokenNamespace   string
	managedNamespace string
	secretType       string
}

func kagiSecretUnderTest(spec resourceSpec) resourceUnderTest {
	cr, _ := buildKagiSecret("")
	cr.Namespace = spec.namespace
	cr.Spec.TokenSecret = &kagiv1alpha1.TokenSecretRef{Name: tokenSecretName, Namespace: spec.tokenNamespace}
	cr.Spec.ManagedSecret = &kagiv1alpha1.ManagedSecretRef{Name: victimSecretName, Namespace: spec.managedNamespace, Type: spec.secretType}
	key := client.ObjectKeyFromObject(cr)
	return resourceUnderTest{
		kind: kindKagiSecret,
		obj:  cr,
		reconcile: func(c client.Client, kagiAPIURL, operatorNamespace string, recorder record.EventRecorder) error {
			r := &KagiSecretReconciler{Client: c, Scheme: c.Scheme(), KagiAPIURL: kagiAPIURL, OperatorNamespace: operatorNamespace, Recorder: recorder}
			_, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: key})
			return err
		},
		status: func(t *testing.T, c client.Client) (*metav1.Condition, string) {
			t.Helper()
			var stored kagiv1alpha1.KagiSecret
			if err := c.Get(context.Background(), key, &stored); err != nil {
				t.Fatalf("get KagiSecret %s: %v", key, err)
			}
			return readyCondition(stored.Status.Conditions), stored.Status.LastErrorMessage
		},
	}
}

func kagiCertificateUnderTest(spec resourceSpec) resourceUnderTest {
	cr, _ := ownershipKagiCertificate()
	cr.Namespace = spec.namespace
	cr.Spec.TokenSecret = &kagiv1alpha1.TokenSecretRef{Name: tokenSecretName, Namespace: spec.tokenNamespace}
	cr.Spec.ManagedSecret = kagiv1alpha1.ManagedSecretRef{Name: victimSecretName, Namespace: spec.managedNamespace, Type: spec.secretType}
	key := client.ObjectKeyFromObject(cr)
	return resourceUnderTest{
		kind: kindKagiCertificate,
		obj:  cr,
		reconcile: func(c client.Client, kagiAPIURL, operatorNamespace string, recorder record.EventRecorder) error {
			r := &KagiCertificateReconciler{Client: c, Scheme: c.Scheme(), KagiAPIURL: kagiAPIURL, OperatorNamespace: operatorNamespace, Recorder: recorder}
			_, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: key})
			return err
		},
		status: func(t *testing.T, c client.Client) (*metav1.Condition, string) {
			t.Helper()
			var stored kagiv1alpha1.KagiCertificate
			if err := c.Get(context.Background(), key, &stored); err != nil {
				t.Fatalf("get KagiCertificate %s: %v", key, err)
			}
			return readyCondition(stored.Status.Conditions), stored.Status.LastErrorMessage
		},
	}
}

// bothKinds returns a KagiSecret and a KagiCertificate placed by spec.
func bothKinds(spec resourceSpec) []resourceUnderTest {
	return []resourceUnderTest{kagiSecretUnderTest(spec), kagiCertificateUnderTest(spec)}
}

// identityOf returns the identity labels an earlier release wrote for the
// resources of kagiSecretUnderTest and kagiCertificateUnderTest.
func identityOf(kind string) map[string]string {
	if kind == kindKagiCertificate {
		return kagiCertificateIdentity()
	}
	return kagiSecretIdentity()
}

// legacySecretFor returns the Secret an earlier release wrote at victimKey for
// a resource of kind: the managed-by label, the identity labels and a data
// hash, but no owner annotation.
func legacySecretFor(kind string) *corev1.Secret {
	return opaqueVictimSecret(
		mergeLabels(map[string]string{labelManagedBy: managedByValue}, identityOf(kind)),
		map[string]string{annotationHash: legacyDataHash})
}

func tokenSecretIn(namespace string) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: tokenSecretName, Namespace: namespace},
		Data:       map[string][]byte{"KAGI_TOKEN": []byte("vv_test")},
	}
}

// secretReads records the keys of every Secret a client reads.
type secretReads struct {
	mu   sync.Mutex
	keys []types.NamespacedName
}

func (s *secretReads) all() []types.NamespacedName {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]types.NamespacedName(nil), s.keys...)
}

// newReadRecordingFakeClient builds a fake client holding objs that records
// every Secret read through it.
func newReadRecordingFakeClient(t *testing.T, objs ...client.Object) (client.Client, *secretReads) {
	t.Helper()
	reads := &secretReads{}
	c := fake.NewClientBuilder().
		WithScheme(newFakeScheme(t)).
		WithObjects(objs...).
		WithStatusSubresource(&kagiv1alpha1.KagiSecret{}, &kagiv1alpha1.KagiCertificate{}).
		WithInterceptorFuncs(interceptor.Funcs{
			Get: func(ctx context.Context, cl client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
				if _, isSecret := obj.(*corev1.Secret); isSecret {
					reads.mu.Lock()
					reads.keys = append(reads.keys, key)
					reads.mu.Unlock()
				}
				return cl.Get(ctx, key, obj, opts...)
			},
		}).
		Build()
	return c, reads
}

// assertNoSecretRead fails when the reconcile read any Secret.
func assertNoSecretRead(t *testing.T, reads *secretReads) {
	t.Helper()
	if keys := reads.all(); len(keys) != 0 {
		t.Errorf("the reconcile read the Secrets %v, want none", keys)
	}
}

// assertReady checks the Ready condition and LastErrorMessage of a refused
// reconcile.
func assertReady(t *testing.T, resource resourceUnderTest, c client.Client, wantReason string, wantInMessage ...string) {
	t.Helper()
	ready, lastError := resource.status(t, c)
	if ready == nil {
		t.Fatal("no Ready condition was set")
	}
	if ready.Status != metav1.ConditionFalse || ready.Reason != wantReason {
		t.Errorf("Ready = %s/%s, want %s/%s", ready.Status, ready.Reason, metav1.ConditionFalse, wantReason)
	}
	for _, want := range wantInMessage {
		if !strings.Contains(ready.Message, want) {
			t.Errorf("Ready.Message = %q, want it to contain %q", ready.Message, want)
		}
	}
	if lastError != ready.Message {
		t.Errorf("Status.LastErrorMessage = %q, want the Ready message", lastError)
	}
}

// TestHijackFromAnotherNamespaceIsDenied covers the takeover of a Secret that
// an earlier release wrote for a resource in the operator's namespace. The
// attacker copies that resource's Kagi binding, so the identity labels match;
// only the namespace rules stop the takeover, and they stop it before the
// operator reads the attacker's token or the Secret.
func TestHijackFromAnotherNamespaceIsDenied(t *testing.T) {
	spec := resourceSpec{namespace: attackerNamespace, tokenNamespace: attackerNamespace, managedNamespace: victimNamespace}
	for _, resource := range bothKinds(spec) {
		t.Run(resource.kind, func(t *testing.T) {
			var fetches atomic.Int32
			server := ownershipKagiServer(&fetches)
			defer server.Close()

			legacy := legacySecretFor(resource.kind)
			c, reads := newReadRecordingFakeClient(t, resource.obj, tokenSecretIn(attackerNamespace), legacy)
			before := getVictim(t, c)
			reads.keys = nil

			err := resource.reconcile(c, server.URL, productionOperatorNamespace, nil)

			if managedSecretFailureReason(err) != reasonCrossNamespaceReferenceDenied {
				t.Fatalf("Reconcile = %v, want a %s refusal", err, reasonCrossNamespaceReferenceDenied)
			}
			assertReady(t, resource, c, reasonCrossNamespaceReferenceDenied, "spec.managedSecret.namespace", victimNamespace, productionOperatorNamespace)
			assertNoSecretRead(t, reads)
			assertUntouched(t, c, before)
			if n := fetches.Load(); n != 0 {
				t.Errorf("Kagi was asked for secret material %d times, want none", n)
			}
		})
	}
}

// TestAdoptionRefusal covers the rules for taking over a Secret that an
// earlier release wrote without an owner. The namespace rule is checked here
// directly, because checkSecretReferences already stops a reconcile that
// would reach it from another namespace.
func TestAdoptionRefusal(t *testing.T) {
	legacyIn := func(namespace string, labels map[string]string) *corev1.Secret {
		return &corev1.Secret{ObjectMeta: metav1.ObjectMeta{
			Name:        victimSecretName,
			Namespace:   namespace,
			Labels:      mergeLabels(map[string]string{labelManagedBy: managedByValue}, labels),
			Annotations: map[string]string{annotationHash: legacyDataHash},
		}}
	}
	claimIn := func(kind, namespace, operatorNamespace string, identity map[string]string) *managedSecretClaim {
		return &managedSecretClaim{
			kind:              kind,
			owner:             kind + "/" + namespace + "/res",
			namespace:         namespace,
			operatorNamespace: operatorNamespace,
			identity:          identity,
		}
	}
	appIdentity := kagiSecretIdentity()
	certIdentity := kagiCertificateIdentity()

	cases := []struct {
		name        string
		secret      *corev1.Secret
		claim       *managedSecretClaim
		wantRefusal string
	}{
		{
			name:   "a certificate in the Secret's own namespace",
			secret: legacyIn("apps", certIdentity),
			claim:  claimIn(kindKagiCertificate, "apps", productionOperatorNamespace, certIdentity),
		},
		{
			name:        "a KagiSecret in the Secret's own namespace",
			secret:      legacyIn("apps", appIdentity),
			claim:       claimIn(kindKagiSecret, "apps", productionOperatorNamespace, appIdentity),
			wantRefusal: "only a resource in the operator's namespace kagi-operator-system may take over a Secret an earlier release wrote for a KagiSecret",
		},
		{
			name:   "a KagiSecret in the operator's namespace",
			secret: legacyIn("apps", appIdentity),
			claim:  claimIn(kindKagiSecret, productionOperatorNamespace, productionOperatorNamespace, appIdentity),
		},
		{
			name:   "a certificate in the operator's namespace",
			secret: legacyIn("apps", certIdentity),
			claim:  claimIn(kindKagiCertificate, productionOperatorNamespace, productionOperatorNamespace, certIdentity),
		},
		{
			name:        "a KagiSecret in a third namespace",
			secret:      legacyIn("apps", appIdentity),
			claim:       claimIn(kindKagiSecret, attackerNamespace, productionOperatorNamespace, appIdentity),
			wantRefusal: "only a resource in the operator's namespace kagi-operator-system",
		},
		{
			name:        "a certificate in a third namespace",
			secret:      legacyIn("apps", certIdentity),
			claim:       claimIn(kindKagiCertificate, attackerNamespace, productionOperatorNamespace, certIdentity),
			wantRefusal: "only a KagiCertificate in namespace apps or a resource in the operator's namespace kagi-operator-system",
		},
		{
			name:   "the operator's namespace is not known, a KagiSecret in the Secret's own namespace",
			secret: legacyIn("apps", appIdentity),
			claim:  claimIn(kindKagiSecret, "apps", "", appIdentity),
		},
		{
			name:        "the operator's namespace is not known, a resource elsewhere",
			secret:      legacyIn("apps", appIdentity),
			claim:       claimIn(kindKagiSecret, productionOperatorNamespace, "", appIdentity),
			wantRefusal: "POD_NAMESPACE is not set, so only a resource in namespace apps",
		},
		{
			name:        "no resolved Kagi binding",
			secret:      legacyIn("apps", appIdentity),
			claim:       claimIn(kindKagiSecret, productionOperatorNamespace, productionOperatorNamespace, nil),
			wantRefusal: "has not resolved its Kagi binding",
		},
		{
			name:        "another app",
			secret:      legacyIn("apps", mergeLabels(appIdentity, map[string]string{labelAppID: "another-app"})),
			claim:       claimIn(kindKagiSecret, productionOperatorNamespace, productionOperatorNamespace, appIdentity),
			wantRefusal: `its label kagi.pw/app-id is "another-app", but this resource needs "app-id-123"`,
		},
		{
			name:        "another environment",
			secret:      legacyIn("apps", mergeLabels(appIdentity, map[string]string{labelEnv: "staging"})),
			claim:       claimIn(kindKagiSecret, productionOperatorNamespace, productionOperatorNamespace, appIdentity),
			wantRefusal: `its label kagi.pw/environment is "staging"`,
		},
		{
			name:        "another certificate",
			secret:      legacyIn("apps", map[string]string{labelCertificateID: "another-cert"}),
			claim:       claimIn(kindKagiCertificate, "apps", productionOperatorNamespace, certIdentity),
			wantRefusal: `its label kagi.pw/certificate-id is "another-cert"`,
		},
		{
			name:        "no identity labels",
			secret:      legacyIn("apps", nil),
			claim:       claimIn(kindKagiCertificate, "apps", productionOperatorNamespace, certIdentity),
			wantRefusal: `its label kagi.pw/certificate-id is ""`,
		},
		{
			name: "ownerReferences",
			secret: withSecret(legacyIn("apps", certIdentity), func(s *corev1.Secret) {
				s.OwnerReferences = []metav1.OwnerReference{{APIVersion: "v1", Kind: "ConfigMap", Name: "planted", UID: "planted-uid"}}
			}),
			claim:       claimIn(kindKagiCertificate, "apps", productionOperatorNamespace, certIdentity),
			wantRefusal: "it has ownerReferences",
		},
		{
			name:        "finalizers",
			secret:      withSecret(legacyIn("apps", certIdentity), func(s *corev1.Secret) { s.Finalizers = []string{"example.com/hold"} }),
			claim:       claimIn(kindKagiCertificate, "apps", productionOperatorNamespace, certIdentity),
			wantRefusal: "it has finalizers",
		},
		{
			name:        "immutable",
			secret:      withSecret(legacyIn("apps", certIdentity), func(s *corev1.Secret) { s.Immutable = new(true) }),
			claim:       claimIn(kindKagiCertificate, "apps", productionOperatorNamespace, certIdentity),
			wantRefusal: "it is immutable",
		},
		{
			name:   "immutable set to false",
			secret: withSecret(legacyIn("apps", certIdentity), func(s *corev1.Secret) { s.Immutable = new(false) }),
			claim:  claimIn(kindKagiCertificate, "apps", productionOperatorNamespace, certIdentity),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := classifySecretOwnership(tc.secret, tc.claim.owner); got != secretUnclaimed {
				t.Fatalf("classifySecretOwnership = %d, want secretUnclaimed", got)
			}
			got := adoptionRefusal(tc.secret, tc.claim)
			if tc.wantRefusal == "" {
				if got != "" {
					t.Errorf("adoptionRefusal = %q, want the adoption allowed", got)
				}
				if err := checkSecretWritable(tc.secret, tc.claim); err != nil {
					t.Errorf("checkSecretWritable = %v, want nil", err)
				}
				return
			}
			if !strings.Contains(got, tc.wantRefusal) {
				t.Errorf("adoptionRefusal = %q, want it to contain %q", got, tc.wantRefusal)
			}
			err := checkSecretWritable(tc.secret, tc.claim)
			if reason := managedSecretFailureReason(err); reason != reasonSecretNotManaged {
				t.Errorf("checkSecretWritable reason = %q (err %v), want %q", reason, err, reasonSecretNotManaged)
			}
		})
	}
}

func TestCheckSecretReferences(t *testing.T) {
	resource := &kagiv1alpha1.KagiSecret{ObjectMeta: metav1.ObjectMeta{Name: "res", Namespace: "apps"}}
	inOperatorNamespace := resource.DeepCopy()
	inOperatorNamespace.Namespace = productionOperatorNamespace
	ref := func(namespace string) secretReference {
		return secretReference{field: "spec.managedSecret.namespace", namespace: namespace}
	}

	cases := []struct {
		name              string
		resource          client.Object
		operatorNamespace string
		refs              []secretReference
		wantDenied        bool
	}{
		{name: "no reference", resource: resource, operatorNamespace: productionOperatorNamespace},
		{name: "empty namespace means the resource's own", resource: resource, operatorNamespace: productionOperatorNamespace, refs: []secretReference{ref("")}},
		{name: "the resource's own namespace", resource: resource, operatorNamespace: productionOperatorNamespace, refs: []secretReference{ref("apps")}},
		{name: "another namespace", resource: resource, operatorNamespace: productionOperatorNamespace, refs: []secretReference{ref("apps"), ref(victimNamespace)}, wantDenied: true},
		{name: "the operator's namespace from outside", resource: resource, operatorNamespace: productionOperatorNamespace, refs: []secretReference{ref(productionOperatorNamespace)}, wantDenied: true},
		{name: "another namespace from the operator's namespace", resource: inOperatorNamespace, operatorNamespace: productionOperatorNamespace, refs: []secretReference{ref(victimNamespace)}},
		{name: "another namespace while the operator's namespace is not known", resource: inOperatorNamespace, operatorNamespace: "", refs: []secretReference{ref(victimNamespace)}, wantDenied: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := checkSecretReferences(tc.resource, kindKagiSecret, tc.operatorNamespace, tc.refs...)
			if !tc.wantDenied {
				if err != nil {
					t.Errorf("checkSecretReferences = %v, want nil", err)
				}
				return
			}
			if reason := managedSecretFailureReason(err); reason != reasonCrossNamespaceReferenceDenied {
				t.Fatalf("checkSecretReferences reason = %q (err %v), want %q", reason, err, reasonCrossNamespaceReferenceDenied)
			}
			if !strings.Contains(err.Error(), "spec.managedSecret.namespace") {
				t.Errorf("message %q does not name the field", err.Error())
			}
		})
	}
}

// TestCrossNamespaceReferenceDeniedOutsideOperatorNamespace covers both
// references a resource outside the operator's namespace could use against
// another namespace: a token Secret it would act with, and a managed Secret
// it would write. The operator reads neither.
func TestCrossNamespaceReferenceDeniedOutsideOperatorNamespace(t *testing.T) {
	cases := []struct {
		name      string
		spec      resourceSpec
		wantField string
	}{
		{
			name:      "token Secret in another namespace",
			spec:      resourceSpec{namespace: attackerNamespace, tokenNamespace: productionOperatorNamespace, managedNamespace: attackerNamespace},
			wantField: "spec.tokenSecret.namespace",
		},
		{
			name:      "managed Secret in another namespace",
			spec:      resourceSpec{namespace: attackerNamespace, tokenNamespace: attackerNamespace, managedNamespace: victimNamespace},
			wantField: "spec.managedSecret.namespace",
		},
	}
	for _, tc := range cases {
		for _, resource := range bothKinds(tc.spec) {
			t.Run(tc.name+"/"+resource.kind, func(t *testing.T) {
				var fetches atomic.Int32
				server := ownershipKagiServer(&fetches)
				defer server.Close()

				objs := []client.Object{resource.obj, tokenSecretIn(tc.spec.tokenNamespace)}
				if tc.spec.tokenNamespace != attackerNamespace {
					objs = append(objs, tokenSecretIn(attackerNamespace))
				}
				c, reads := newReadRecordingFakeClient(t, objs...)

				err := resource.reconcile(c, server.URL, productionOperatorNamespace, nil)

				if managedSecretFailureReason(err) != reasonCrossNamespaceReferenceDenied {
					t.Fatalf("Reconcile = %v, want a %s refusal", err, reasonCrossNamespaceReferenceDenied)
				}
				assertReady(t, resource, c, reasonCrossNamespaceReferenceDenied, tc.wantField)
				assertNoSecretRead(t, reads)
				if n := fetches.Load(); n != 0 {
					t.Errorf("Kagi was asked for secret material %d times, want none", n)
				}
				var target corev1.Secret
				managedKey := types.NamespacedName{Namespace: tc.spec.managedNamespace, Name: victimSecretName}
				if err := c.Get(context.Background(), managedKey, &target); !apierrors.IsNotFound(err) {
					t.Errorf("managed Secret %s exists or could not be read (%v), want none created", managedKey, err)
				}
			})
		}
	}
}

// TestCrossNamespaceReferenceAllowedInOperatorNamespace is the shape of every
// production KagiSecret: it lives in the operator's namespace, reads its
// token there or elsewhere, and writes into an application namespace.
func TestCrossNamespaceReferenceAllowedInOperatorNamespace(t *testing.T) {
	spec := resourceSpec{namespace: productionOperatorNamespace, tokenNamespace: "tokens", managedNamespace: victimNamespace}
	for _, resource := range bothKinds(spec) {
		t.Run(resource.kind, func(t *testing.T) {
			var fetches atomic.Int32
			server := ownershipKagiServer(&fetches)
			defer server.Close()

			c, _ := newReadRecordingFakeClient(t, resource.obj, tokenSecretIn("tokens"))

			if err := resource.reconcile(c, server.URL, productionOperatorNamespace, nil); err != nil {
				t.Fatalf("Reconcile: %v", err)
			}
			created := getVictim(t, c)
			if created == nil {
				t.Fatalf("managed Secret %s was not created", victimKey)
			}
			if got, want := created.Annotations[annotationOwner], managedSecretOwner(resource.kind, resource.obj); got != want {
				t.Errorf("annotation %s = %q, want %q", annotationOwner, got, want)
			}
		})
	}
}

// TestInjectedRolloutOutsideOperatorNamespaceIsDenied covers the rollout of
// an Injected-mode KagiSecret, which patches Deployments in the namespace of
// spec.managedSecret. From outside the operator's namespace that namespace
// must be the resource's own.
func TestInjectedRolloutOutsideOperatorNamespaceIsDenied(t *testing.T) {
	var fetches atomic.Int32
	server := ownershipKagiServer(&fetches)
	defer server.Close()

	resource := kagiSecretUnderTest(resourceSpec{namespace: attackerNamespace, tokenNamespace: attackerNamespace, managedNamespace: victimNamespace})
	cr := resource.obj.(*kagiv1alpha1.KagiSecret)
	cr.Spec.Mode = modeInjected
	cr.Spec.Rollout = &kagiv1alpha1.RolloutSpec{Deployments: []string{"payments"}}
	cr.Status.LastVersion = "v-before"
	deployment := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "payments", Namespace: victimNamespace}}
	c, reads := newReadRecordingFakeClient(t, cr, tokenSecretIn(attackerNamespace), deployment)

	err := resource.reconcile(c, server.URL, productionOperatorNamespace, nil)

	if managedSecretFailureReason(err) != reasonCrossNamespaceReferenceDenied {
		t.Fatalf("Reconcile = %v, want a %s refusal", err, reasonCrossNamespaceReferenceDenied)
	}
	assertNoSecretRead(t, reads)
	var after appsv1.Deployment
	if err := c.Get(context.Background(), client.ObjectKeyFromObject(deployment), &after); err != nil {
		t.Fatalf("get Deployment: %v", err)
	}
	if v, stamped := after.Spec.Template.Annotations[annotationSecretsVersion]; stamped {
		t.Errorf("Deployment %s/%s was stamped with version %q, want it untouched", victimNamespace, "payments", v)
	}
}

func TestCheckManagedSecretType(t *testing.T) {
	for _, allowed := range []string{"", "Opaque", "kubernetes.io/tls"} {
		if err := checkManagedSecretType(allowed); err != nil {
			t.Errorf("checkManagedSecretType(%q) = %v, want nil", allowed, err)
		}
	}
	for _, refused := range []string{
		"kubernetes.io/service-account-token",
		"bootstrap.kubernetes.io/token",
		"kubernetes.io/dockerconfigjson",
		"opaque",
	} {
		err := checkManagedSecretType(refused)
		if reason := managedSecretFailureReason(err); reason != reasonInvalidSpec {
			t.Errorf("checkManagedSecretType(%q) reason = %q (err %v), want %q", refused, reason, err, reasonInvalidSpec)
		}
	}
}

// TestServiceAccountTokenTypeIsRefused covers a resource stored before the
// CRD enum was applied: the reconcile refuses it before any Secret is read.
func TestServiceAccountTokenTypeIsRefused(t *testing.T) {
	spec := resourceSpec{
		namespace:        testOperatorNamespace,
		tokenNamespace:   testOperatorNamespace,
		managedNamespace: victimNamespace,
		secretType:       string(corev1.SecretTypeServiceAccountToken),
	}
	for _, resource := range bothKinds(spec) {
		t.Run(resource.kind, func(t *testing.T) {
			var fetches atomic.Int32
			server := ownershipKagiServer(&fetches)
			defer server.Close()

			c, reads := newReadRecordingFakeClient(t, resource.obj, tokenSecretIn(testOperatorNamespace))

			err := resource.reconcile(c, server.URL, testOperatorNamespace, nil)

			if managedSecretFailureReason(err) != reasonInvalidSpec {
				t.Fatalf("Reconcile = %v, want an %s refusal", err, reasonInvalidSpec)
			}
			assertReady(t, resource, c, reasonInvalidSpec, string(corev1.SecretTypeServiceAccountToken))
			assertNoSecretRead(t, reads)
			if getVictim(t, c) != nil {
				t.Errorf("Secret %s was created, want none", victimKey)
			}
			if n := fetches.Load(); n != 0 {
				t.Errorf("Kagi was asked for secret material %d times, want none", n)
			}
		})
	}
}

// TestDeletionKeepsFinalizerWhenSecretCleanupFails covers a managed Secret
// that this resource owns and that the API server fails to delete. Removing
// the finalizer anyway would orphan the Secret, so the finalizer stays, the
// error goes back to the rate limiter and a Warning Event says why; the next
// attempt, once the API server recovers, deletes the Secret and completes the
// deletion.
func TestDeletionKeepsFinalizerWhenSecretCleanupFails(t *testing.T) {
	spec := resourceSpec{namespace: testOperatorNamespace, tokenNamespace: testOperatorNamespace, managedNamespace: victimNamespace}
	for _, resource := range bothKinds(spec) {
		t.Run(resource.kind, func(t *testing.T) {
			now := metav1.Now()
			resource.obj.SetDeletionTimestamp(&now)
			owned := opaqueVictimSecret(
				map[string]string{labelManagedBy: managedByValue},
				map[string]string{annotationOwner: managedSecretOwner(resource.kind, resource.obj)})
			var failing atomic.Bool
			failing.Store(true)
			c := fake.NewClientBuilder().
				WithScheme(newFakeScheme(t)).
				WithObjects(resource.obj, owned).
				WithInterceptorFuncs(interceptor.Funcs{
					Delete: func(ctx context.Context, cl client.WithWatch, obj client.Object, opts ...client.DeleteOption) error {
						if client.ObjectKeyFromObject(obj) == victimKey && failing.Load() {
							return apierrors.NewServiceUnavailable("the API server is restarting")
						}
						return cl.Delete(ctx, obj, opts...)
					},
				}).
				Build()
			recorder := record.NewFakeRecorder(eventBuffer)
			key := client.ObjectKeyFromObject(resource.obj)

			err := resource.reconcile(c, "", testOperatorNamespace, recorder)

			if !apierrors.IsServiceUnavailable(err) || !strings.Contains(err.Error(), victimKey.String()) {
				t.Fatalf("Reconcile = %v, want the ServiceUnavailable error naming %s", err, victimKey)
			}
			stuck := resource.obj.DeepCopyObject().(client.Object)
			if err := c.Get(context.Background(), key, stuck); err != nil {
				t.Fatalf("get %s after the failed cleanup: %v", key, err)
			}
			if len(stuck.GetFinalizers()) == 0 {
				t.Error("the finalizer was removed although the managed Secret could not be deleted")
			}
			if getVictim(t, c) == nil {
				t.Fatalf("Secret %s is gone, want it still there after the failed delete", victimKey)
			}
			events := recordedEvents(recorder)
			want := corev1.EventTypeWarning + " " + eventReasonSecretCleanupFailed + " "
			if len(events) != 1 || !strings.HasPrefix(events[0], want) || !strings.Contains(events[0], victimKey.String()) {
				t.Errorf("Events = %v, want one %q Event naming %s", events, want, victimKey)
			}

			failing.Store(false)
			if err := resource.reconcile(c, "", testOperatorNamespace, recorder); err != nil {
				t.Fatalf("Reconcile after the API server recovered: %v", err)
			}
			assertFinalizerReleased(t, c, resource.obj.DeepCopyObject().(client.Object), key)
			if getVictim(t, c) != nil {
				t.Errorf("Secret %s survived deletion of its owner", victimKey)
			}
		})
	}
}

// TestDeletionOutsideOperatorNamespaceLeavesCrossNamespaceSecret covers a
// resource outside the operator's namespace that names a Secret elsewhere and
// is deleted. Even a Secret whose annotation names the resource as its owner,
// which anyone who may write that Secret could have planted, stays in place
// unread, and the deletion still completes.
func TestDeletionOutsideOperatorNamespaceLeavesCrossNamespaceSecret(t *testing.T) {
	spec := resourceSpec{namespace: attackerNamespace, tokenNamespace: attackerNamespace, managedNamespace: victimNamespace}
	for _, resource := range bothKinds(spec) {
		t.Run(resource.kind, func(t *testing.T) {
			now := metav1.Now()
			resource.obj.SetDeletionTimestamp(&now)
			planted := opaqueVictimSecret(
				map[string]string{labelManagedBy: managedByValue},
				map[string]string{annotationOwner: managedSecretOwner(resource.kind, resource.obj)})
			c, reads := newReadRecordingFakeClient(t, resource.obj, planted)
			before := getVictim(t, c)
			reads.keys = nil
			recorder := record.NewFakeRecorder(eventBuffer)

			if err := resource.reconcile(c, "", productionOperatorNamespace, recorder); err != nil {
				t.Fatalf("Reconcile: %v", err)
			}

			assertNoSecretRead(t, reads)
			assertFinalizerReleased(t, c, resource.obj.DeepCopyObject().(client.Object), client.ObjectKeyFromObject(resource.obj))
			assertUntouched(t, c, before)
			events := recordedEvents(recorder)
			want := corev1.EventTypeWarning + " " + eventReasonSecretLeftInPlace + " "
			if len(events) != 1 || !strings.HasPrefix(events[0], want) || !strings.Contains(events[0], "spec.managedSecret.namespace") {
				t.Errorf("Events = %v, want one %q Event naming spec.managedSecret.namespace", events, want)
			}
		})
	}
}

// TestSameNamespaceKagiSecretCannotRaceOperatorNamespaceOwner covers a Secret
// that an earlier release wrote for a KagiSecret in the operator's namespace,
// and a KagiSecret created next to that Secret with the same Kagi binding,
// copied from Git. If the Secret's own namespace were enough to adopt it, the
// first of the two to reconcile would take it over. The KagiSecret next to it
// is refused before the operator fetches secret values, and the real owner
// adopts the Secret afterwards.
func TestSameNamespaceKagiSecretCannotRaceOperatorNamespaceOwner(t *testing.T) {
	var fetches atomic.Int32
	server := ownershipKagiServer(&fetches)
	defer server.Close()

	racer := kagiSecretUnderTest(resourceSpec{namespace: victimNamespace, tokenNamespace: victimNamespace, managedNamespace: victimNamespace})
	owner := kagiSecretUnderTest(resourceSpec{
		namespace: productionOperatorNamespace, tokenNamespace: productionOperatorNamespace, managedNamespace: victimNamespace,
	})
	c, _ := newReadRecordingFakeClient(t, racer.obj, owner.obj,
		tokenSecretIn(victimNamespace), tokenSecretIn(productionOperatorNamespace), legacySecretFor(kindKagiSecret))
	before := getVictim(t, c)

	err := racer.reconcile(c, server.URL, productionOperatorNamespace, nil)

	if managedSecretFailureReason(err) != reasonSecretNotManaged {
		t.Fatalf("Reconcile of the KagiSecret next to the Secret = %v, want a %s refusal", err, reasonSecretNotManaged)
	}
	assertReady(t, racer, c, reasonSecretNotManaged, victimKey.String(), productionOperatorNamespace)
	assertUntouched(t, c, before)
	if n := fetches.Load(); n != 0 {
		t.Errorf("Kagi was asked for secret material %d times, want none", n)
	}

	if err := owner.reconcile(c, server.URL, productionOperatorNamespace, nil); err != nil {
		t.Fatalf("Reconcile of the KagiSecret in the operator's namespace: %v", err)
	}
	assertOwnedAndSynced(t, c, managedSecretOwner(kindKagiSecret, owner.obj), map[string]string{"FOO": "bar"})
}

// resolvedIDOf returns the Kagi binding ID in the identity labels an earlier
// release wrote for a resource of kind.
func resolvedIDOf(kind string) string {
	if kind == kindKagiCertificate {
		return kagiCertificateIdentity()[labelCertificateID]
	}
	return kagiSecretIdentity()[labelAppID]
}

// setResolvedID records id in the status of resource as the Kagi binding its
// last sync resolved.
func setResolvedID(t *testing.T, resource resourceUnderTest, id string) {
	t.Helper()
	switch obj := resource.obj.(type) {
	case *kagiv1alpha1.KagiSecret:
		obj.Status.ResolvedAppID = id
	case *kagiv1alpha1.KagiCertificate:
		obj.Status.ResolvedCertificateID = id
	default:
		t.Fatalf("unexpected resource type %T", resource.obj)
	}
}

// TestDeletionDeletesUnclaimedSecretItCouldAdopt covers the deletion of a
// resource whose Secret an earlier release wrote without an owner. The
// resource deletes it only when it could have adopted it: the Kagi binding its
// status recorded matches the Secret's identity labels and the namespace rules
// of adoption allow it. Otherwise the Secret stays and a Warning Event says
// why. Either way the deletion completes.
func TestDeletionDeletesUnclaimedSecretItCouldAdopt(t *testing.T) {
	cases := []struct {
		name       string
		namespace  string
		resolvedID func(kind string) string
		// deletedFor lists the kinds whose deletion deletes the Secret.
		deletedFor  []string
		wantInEvent string
	}{
		{
			name:       "status records the Secret's binding",
			namespace:  productionOperatorNamespace,
			resolvedID: resolvedIDOf,
			deletedFor: []string{kindKagiSecret, kindKagiCertificate},
		},
		{
			name:        "status records no binding",
			namespace:   productionOperatorNamespace,
			resolvedID:  func(string) string { return "" },
			wantInEvent: "has not resolved its Kagi binding",
		},
		{
			name:        "status records another binding",
			namespace:   productionOperatorNamespace,
			resolvedID:  func(string) string { return "another-binding" },
			wantInEvent: `"another-binding"`,
		},
		{
			name:        "the resource lives next to the Secret",
			namespace:   victimNamespace,
			resolvedID:  resolvedIDOf,
			deletedFor:  []string{kindKagiCertificate},
			wantInEvent: "only a resource in the operator's namespace " + productionOperatorNamespace,
		},
	}
	for _, tc := range cases {
		spec := resourceSpec{namespace: tc.namespace, tokenNamespace: tc.namespace, managedNamespace: victimNamespace}
		for _, resource := range bothKinds(spec) {
			t.Run(tc.name+"/"+resource.kind, func(t *testing.T) {
				now := metav1.Now()
				resource.obj.SetDeletionTimestamp(&now)
				setResolvedID(t, resource, tc.resolvedID(resource.kind))
				c, _ := newReadRecordingFakeClient(t, resource.obj, legacySecretFor(resource.kind))
				before := getVictim(t, c)
				recorder := record.NewFakeRecorder(eventBuffer)

				if err := resource.reconcile(c, "", productionOperatorNamespace, recorder); err != nil {
					t.Fatalf("Reconcile: %v", err)
				}

				assertFinalizerReleased(t, c, resource.obj.DeepCopyObject().(client.Object), client.ObjectKeyFromObject(resource.obj))
				events := recordedEvents(recorder)
				if slices.Contains(tc.deletedFor, resource.kind) {
					if getVictim(t, c) != nil {
						t.Errorf("Secret %s survived deletion of the resource it was written for", victimKey)
					}
					if len(events) != 0 {
						t.Errorf("Events = %v, want none", events)
					}
					return
				}
				assertUntouched(t, c, before)
				want := corev1.EventTypeWarning + " " + eventReasonSecretLeftInPlace + " "
				if len(events) != 1 || !strings.HasPrefix(events[0], want) || !strings.Contains(events[0], tc.wantInEvent) {
					t.Errorf("Events = %v, want one %q Event containing %q", events, want, tc.wantInEvent)
				}
			})
		}
	}
}

// TestDeleteManagedSecretRechecksUnclaimedSecretAfterConflict covers an
// unclaimed Secret that changes between the adoption check and the delete.
// The delete carries the UID and resourceVersion that were checked, so it
// fails and the Secret is checked once more: a Secret that was only updated
// in between is deleted, and one that another resource claimed stays.
func TestDeleteManagedSecretRechecksUnclaimedSecretAfterConflict(t *testing.T) {
	claim := &managedSecretClaim{
		kind:              kindKagiSecret,
		owner:             "KagiSecret/" + testOperatorNamespace + "/test",
		namespace:         testOperatorNamespace,
		operatorNamespace: testOperatorNamespace,
		identity:          kagiSecretIdentity(),
	}
	cases := []struct {
		name        string
		change      concurrentChange
		wantDeleted bool
		wantDeletes int
	}{
		{
			name: "updated in between and still unclaimed",
			change: func(live *corev1.Secret, attempt int) bool {
				if attempt > 1 {
					return false
				}
				live.Data["rotated"] = []byte("yes")
				return true
			},
			wantDeleted: true,
			wantDeletes: 2,
		},
		{
			name: "claimed by another resource in between",
			change: func(live *corev1.Secret, attempt int) bool {
				if attempt > 1 {
					return false
				}
				live.Annotations[annotationOwner] = otherOwner
				return true
			},
			wantDeletes: 1,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, _, deletes := newRacingFakeClient(t, legacySecretFor(kindKagiSecret), tc.change)

			kept, err := deleteManagedSecret(context.Background(), c, c, victimKey, claim)

			if err != nil {
				t.Fatalf("deleteManagedSecret: %v", err)
			}
			if *deletes != tc.wantDeletes {
				t.Errorf("delete was called %d times, want %d", *deletes, tc.wantDeletes)
			}
			after := getVictim(t, c)
			if tc.wantDeleted {
				if after != nil || kept != "" {
					t.Errorf("Secret %s left in place (%q), want it deleted", victimKey, kept)
				}
				return
			}
			if after == nil {
				t.Fatalf("Secret %s was deleted, want it left in place", victimKey)
			}
			if after.Annotations[annotationOwner] != otherOwner || !strings.Contains(kept, otherOwner) {
				t.Errorf("annotation %s = %q and message %q, want the new owner %s kept and named",
					annotationOwner, after.Annotations[annotationOwner], kept, otherOwner)
			}
		})
	}
}

// TestInjectedKagiSecretFinalizeLeavesManagedSecretAlone covers the deletion
// of an Injected-mode KagiSecret. Injected mode never writes a managed Secret,
// so finalize releases the finalizer without reading or deleting the Secret
// that spec.managedSecret names, even one that names this KagiSecret as its
// owner.
func TestInjectedKagiSecretFinalizeLeavesManagedSecretAlone(t *testing.T) {
	resource := kagiSecretUnderTest(resourceSpec{
		namespace: testOperatorNamespace, tokenNamespace: testOperatorNamespace, managedNamespace: victimNamespace,
	})
	ks := resource.obj.(*kagiv1alpha1.KagiSecret)
	ks.Spec.Mode = modeInjected
	now := metav1.Now()
	ks.DeletionTimestamp = &now
	named := opaqueVictimSecret(
		map[string]string{labelManagedBy: managedByValue},
		map[string]string{annotationOwner: managedSecretOwner(kindKagiSecret, ks), annotationHash: legacyDataHash})
	c, reads := newReadRecordingFakeClient(t, ks, named)
	before := getVictim(t, c)
	key := client.ObjectKeyFromObject(ks)
	var stored kagiv1alpha1.KagiSecret
	if err := c.Get(context.Background(), key, &stored); err != nil {
		t.Fatalf("get KagiSecret %s: %v", key, err)
	}
	reads.keys = nil
	recorder := record.NewFakeRecorder(eventBuffer)
	r := &KagiSecretReconciler{Client: c, Scheme: c.Scheme(), OperatorNamespace: testOperatorNamespace, Recorder: recorder}

	if err := r.finalize(context.Background(), &stored); err != nil {
		t.Fatalf("finalize: %v", err)
	}

	assertNoSecretRead(t, reads)
	assertFinalizerReleased(t, c, &kagiv1alpha1.KagiSecret{}, key)
	assertUntouched(t, c, before)
	if events := recordedEvents(recorder); len(events) != 0 {
		t.Errorf("Events = %v, want none", events)
	}
}
