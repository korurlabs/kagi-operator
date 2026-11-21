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
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
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

// The operator holds cluster-wide write and delete rights on Secrets, so a
// KagiSecret or KagiCertificate whose spec.managedSecret names a Secret it did
// not create must neither overwrite that Secret nor delete it with itself.
// These tests drive both reconcilers through every ownership state of the
// target Secret, on the write path and on the delete path.

const (
	// victimNamespace and victimSecretName address a Secret outside the
	// resource's own namespace, the shape of the overwrite and delete attacks.
	victimNamespace  = "victim"
	victimSecretName = "target"

	// otherOwner is a resource that is not the one under test.
	otherOwner = "KagiSecret/other-team/other-resource"

	// legacyDataHash stands in for the data hash an earlier operator release
	// wrote on every managed Secret.
	legacyDataHash = "hash-from-an-earlier-release"

	// testOperatorNamespace is the operator's namespace in these tests. The
	// resources under test live in it and write into victimNamespace, the
	// shape of every production KagiSecret.
	testOperatorNamespace = "default"

	// eventBuffer is generous on purpose: FakeRecorder drops Events once its
	// channel is full, which would hide an Event a test expects.
	eventBuffer = 32
)

var victimKey = types.NamespacedName{Namespace: victimNamespace, Name: victimSecretName}

// ownershipCase is one ownership state of the Secret a resource points at.
type ownershipCase struct {
	name string
	// existing is the Secret already at victimKey, or nil for none.
	existing *corev1.Secret
	// wantReason is the Ready reason of a refused write, or "" when the write
	// must go through.
	wantReason string
	// deletedWithOwner reports whether deleting the resource deletes the Secret.
	deletedWithOwner bool
}

// withSecret applies change to a copy of secret and returns the copy.
func withSecret(secret *corev1.Secret, change func(*corev1.Secret)) *corev1.Secret {
	changed := secret.DeepCopy()
	change(changed)
	return changed
}

// mergeLabels returns the union of sets, later sets winning.
func mergeLabels(sets ...map[string]string) map[string]string {
	merged := map[string]string{}
	for _, set := range sets {
		maps.Copy(merged, set)
	}
	return merged
}

// otherIdentity returns identity with every value changed: the identity
// labels of another Kagi app, environment or certificate.
func otherIdentity(identity map[string]string) map[string]string {
	other := make(map[string]string, len(identity))
	for k, v := range identity {
		other[k] = "other-" + v
	}
	return other
}

// victimSecretFn builds the Secret at victimKey with the given metadata, in the
// type and data shape of the kind under test.
type victimSecretFn func(labels, annotations map[string]string) *corev1.Secret

func opaqueVictimSecret(labels, annotations map[string]string) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: victimSecretName, Namespace: victimNamespace, Labels: labels, Annotations: annotations},
		Type:       corev1.SecretTypeOpaque,
		Data:       map[string][]byte{"original": []byte("untouched")},
	}
}

func tlsVictimSecret(labels, annotations map[string]string) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: victimSecretName, Namespace: victimNamespace, Labels: labels, Annotations: annotations},
		Type:       corev1.SecretTypeTLS,
		Data:       map[string][]byte{"tls.crt": []byte("original-crt"), "tls.key": []byte("original-key")},
	}
}

// ownershipCases lists every ownership state for a resource named by owner,
// whose Kagi binding an earlier release recorded as the labels identity.
func ownershipCases(owner string, identity map[string]string, build victimSecretFn) []ownershipCase {
	managed := map[string]string{labelManagedBy: managedByValue}
	legacyLabels := mergeLabels(managed, identity)
	legacy := build(legacyLabels, map[string]string{annotationHash: legacyDataHash})
	return []ownershipCase{
		{name: "no Secret yet", existing: nil},
		{
			name:             "owned by this resource",
			existing:         build(managed, map[string]string{annotationOwner: owner}),
			deletedWithOwner: true,
		},
		{
			name:     "labelled with a data hash but no owner, as written by earlier operator releases",
			existing: legacy,
		},
		{
			name:       "written by an earlier release for another Kagi binding",
			existing:   build(mergeLabels(managed, otherIdentity(identity)), map[string]string{annotationHash: legacyDataHash}),
			wantReason: reasonSecretNotManaged,
		},
		{
			name:       "written by an earlier release without the identity labels",
			existing:   build(managed, map[string]string{annotationHash: legacyDataHash}),
			wantReason: reasonSecretNotManaged,
		},
		{
			name: "written by an earlier release, then given an ownerReference",
			existing: withSecret(legacy, func(s *corev1.Secret) {
				s.OwnerReferences = []metav1.OwnerReference{{APIVersion: "v1", Kind: "ConfigMap", Name: "planted", UID: "planted-uid"}}
			}),
			wantReason: reasonSecretNotManaged,
		},
		{
			name: "written by an earlier release, then given a finalizer",
			existing: withSecret(legacy, func(s *corev1.Secret) {
				s.Finalizers = []string{"example.com/hold"}
			}),
			wantReason: reasonSecretNotManaged,
		},
		{
			name: "written by an earlier release, then made immutable",
			existing: withSecret(legacy, func(s *corev1.Secret) {
				s.Immutable = new(true)
			}),
			wantReason: reasonSecretNotManaged,
		},
		{
			name:       "labelled without a data hash, like the operator's webhook certificate Secret",
			existing:   build(managed, nil),
			wantReason: reasonSecretNotManaged,
		},
		{
			name:       "owned by another resource",
			existing:   build(managed, map[string]string{annotationOwner: otherOwner}),
			wantReason: reasonSecretOwnedByOther,
		},
		{
			name:       "not created by the operator",
			existing:   build(map[string]string{"app": "payments"}, nil),
			wantReason: reasonSecretNotManaged,
		},
		{
			name:       "owner annotation without the managed-by label",
			existing:   build(nil, map[string]string{annotationOwner: owner}),
			wantReason: reasonSecretNotManaged,
		},
	}
}

// ownershipKagiServer answers the secrets and certificate routes and counts the
// requests that return secret material: the secrets fetch and the certificate
// TLS fetch.
func ownershipKagiServer(fetches *atomic.Int32) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		p := r.URL.Path
		switch {
		case strings.HasSuffix(p, "/secrets/version"):
			_ = json.NewEncoder(w).Encode(map[string]any{"version": "v-upstream", "count": 1})
		case strings.HasSuffix(p, "/secrets/fetch"):
			fetches.Add(1)
			_ = json.NewEncoder(w).Encode(map[string]any{"secrets": map[string]string{"FOO": "bar"}})
		case strings.HasPrefix(p, "/kagi/certificates/by-id/") && strings.HasSuffix(p, "/tls"):
			fetches.Add(1)
			_ = json.NewEncoder(w).Encode(map[string]string{"name": "cert", "tlsCrt": "crt", "tlsKey": "key"})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

// newOwnershipFakeClient builds a fake client holding objs plus existing, when
// it is set.
func newOwnershipFakeClient(t *testing.T, existing *corev1.Secret, objs ...client.Object) client.Client {
	t.Helper()
	if existing != nil {
		objs = append(objs, existing.DeepCopy())
	}
	return fake.NewClientBuilder().
		WithScheme(newFakeScheme(t)).
		WithObjects(objs...).
		WithStatusSubresource(&kagiv1alpha1.KagiSecret{}, &kagiv1alpha1.KagiCertificate{}).
		Build()
}

// getVictim reads the Secret at victimKey, returning nil when it does not exist.
func getVictim(t *testing.T, c client.Client) *corev1.Secret {
	t.Helper()
	var secret corev1.Secret
	if err := c.Get(context.Background(), victimKey, &secret); err != nil {
		if apierrors.IsNotFound(err) {
			return nil
		}
		t.Fatalf("get Secret %s: %v", victimKey, err)
	}
	return &secret
}

// assertRefused checks that a refused write is reported where an operator sees
// it, names the Secret and, for another owner, that owner.
func assertRefused(t *testing.T, err error, conditions []metav1.Condition, lastError, wantReason string) {
	t.Helper()
	if err == nil {
		t.Fatal("Reconcile returned nil, want an ownership error")
	}
	ready := readyCondition(conditions)
	if ready == nil {
		t.Fatalf("no Ready condition was set; conditions=%v", conditions)
	}
	if ready.Status != metav1.ConditionFalse || ready.Reason != wantReason {
		t.Errorf("Ready = %s/%s, want %s/%s", ready.Status, ready.Reason, metav1.ConditionFalse, wantReason)
	}
	if !strings.Contains(ready.Message, victimKey.String()) {
		t.Errorf("Ready.Message = %q, want it to name Secret %s", ready.Message, victimKey)
	}
	if wantReason == reasonSecretOwnedByOther && !strings.Contains(ready.Message, otherOwner) {
		t.Errorf("Ready.Message = %q, want it to name the owner %s", ready.Message, otherOwner)
	}
	if lastError == "" {
		t.Error("Status.LastErrorMessage is empty, want the ownership error")
	}
}

// assertUntouched checks that the Secret at victimKey is still exactly before.
func assertUntouched(t *testing.T, c client.Client, before *corev1.Secret) {
	t.Helper()
	after := getVictim(t, c)
	if after == nil {
		t.Fatalf("Secret %s was deleted", victimKey)
	}
	if after.ResourceVersion != before.ResourceVersion ||
		!equality.Semantic.DeepEqual(after.Labels, before.Labels) ||
		!equality.Semantic.DeepEqual(after.Annotations, before.Annotations) ||
		!equality.Semantic.DeepEqual(after.Data, before.Data) ||
		after.Type != before.Type {
		t.Errorf("Secret %s was changed:\nbefore=%+v\nafter=%+v", victimKey, before, after)
	}
}

// assertOwnedAndSynced checks that the Secret at victimKey carries the
// management markers for owner and holds wantData.
func assertOwnedAndSynced(t *testing.T, c client.Client, owner string, wantData map[string]string) {
	t.Helper()
	secret := getVictim(t, c)
	if secret == nil {
		t.Fatalf("Secret %s does not exist", victimKey)
	}
	if got := secret.Labels[labelManagedBy]; got != managedByValue {
		t.Errorf("label %s = %q, want %q", labelManagedBy, got, managedByValue)
	}
	if got := secret.Annotations[annotationOwner]; got != owner {
		t.Errorf("annotation %s = %q, want %q", annotationOwner, got, owner)
	}
	for k, want := range wantData {
		if got := string(secret.Data[k]); got != want {
			t.Errorf("data %s = %q, want %q", k, got, want)
		}
	}
}

// ownershipKagiSecret returns a reconcilable KagiSecret that writes to
// victimKey, and its token Secret.
func ownershipKagiSecret() (*kagiv1alpha1.KagiSecret, *corev1.Secret) {
	cr, token := buildKagiSecret("")
	cr.Spec.ManagedSecret = &kagiv1alpha1.ManagedSecretRef{Name: victimSecretName, Namespace: victimNamespace, Type: "Opaque"}
	return cr, token
}

// ownershipKagiCertificate returns a reconcilable KagiCertificate that writes
// to victimKey, and its token Secret.
func ownershipKagiCertificate() (*kagiv1alpha1.KagiCertificate, *corev1.Secret) {
	cr := &kagiv1alpha1.KagiCertificate{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-cert",
			Namespace:  "default",
			Generation: 1,
			Finalizers: []string{certFinalizerName},
		},
		Spec: kagiv1alpha1.KagiCertificateSpec{
			CertificateID: "cert-id-123",
			TokenSecret:   &kagiv1alpha1.TokenSecretRef{Name: "token", Namespace: "default"},
			ManagedSecret: kagiv1alpha1.ManagedSecretRef{Name: victimSecretName, Namespace: victimNamespace},
		},
	}
	token := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "token", Namespace: "default"},
		Data:       map[string][]byte{"KAGI_TOKEN": []byte("vv_test")},
	}
	return cr, token
}

// kagiSecretIdentity is the identity labels an earlier release wrote for the
// KagiSecret of ownershipKagiSecret.
func kagiSecretIdentity() map[string]string {
	return map[string]string{labelAppID: "app-id-123", labelEnv: "production"}
}

// kagiCertificateIdentity is the identity label an earlier release wrote for
// the KagiCertificate of ownershipKagiCertificate.
func kagiCertificateIdentity() map[string]string {
	return map[string]string{labelCertificateID: "cert-id-123"}
}

func TestKagiSecretReconcileWritesOnlyAnOwnedOrUnclaimedSecret(t *testing.T) {
	cr, token := ownershipKagiSecret()
	owner := managedSecretOwner(kindKagiSecret, cr)
	if owner != "KagiSecret/default/test" {
		t.Fatalf("owner = %q, want KagiSecret/default/test", owner)
	}

	for _, tc := range ownershipCases(owner, kagiSecretIdentity(), opaqueVictimSecret) {
		t.Run(tc.name, func(t *testing.T) {
			var fetches atomic.Int32
			server := ownershipKagiServer(&fetches)
			defer server.Close()

			cr, token := cr.DeepCopy(), token.DeepCopy()
			c := newOwnershipFakeClient(t, tc.existing, cr, token)
			before := getVictim(t, c)

			r := &KagiSecretReconciler{Client: c, Scheme: c.Scheme(), KagiAPIURL: server.URL, OperatorNamespace: testOperatorNamespace}
			_, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(cr)})

			var stored kagiv1alpha1.KagiSecret
			if getErr := c.Get(context.Background(), client.ObjectKeyFromObject(cr), &stored); getErr != nil {
				t.Fatalf("get KagiSecret: %v", getErr)
			}

			if tc.wantReason != "" {
				assertRefused(t, err, stored.Status.Conditions, stored.Status.LastErrorMessage, tc.wantReason)
				assertUntouched(t, c, before)
				if n := fetches.Load(); n != 0 {
					t.Errorf("secrets were fetched %d times for a Secret the resource may not write", n)
				}
				return
			}

			if err != nil {
				t.Fatalf("Reconcile: %v", err)
			}
			assertOwnedAndSynced(t, c, owner, map[string]string{"FOO": "bar"})
			if _, kept := getVictim(t, c).Data["original"]; kept {
				t.Error("data key original survived the sync, want the Secret's data replaced by the upstream secrets")
			}
		})
	}
}

func TestKagiCertificateReconcileWritesOnlyAnOwnedOrUnclaimedSecret(t *testing.T) {
	cr, token := ownershipKagiCertificate()
	owner := managedSecretOwner(kindKagiCertificate, cr)
	if owner != "KagiCertificate/default/test-cert" {
		t.Fatalf("owner = %q, want KagiCertificate/default/test-cert", owner)
	}

	for _, tc := range ownershipCases(owner, kagiCertificateIdentity(), tlsVictimSecret) {
		t.Run(tc.name, func(t *testing.T) {
			var fetches atomic.Int32
			server := ownershipKagiServer(&fetches)
			defer server.Close()

			cr, token := cr.DeepCopy(), token.DeepCopy()
			c := newOwnershipFakeClient(t, tc.existing, cr, token)
			before := getVictim(t, c)

			r := &KagiCertificateReconciler{Client: c, Scheme: c.Scheme(), KagiAPIURL: server.URL, OperatorNamespace: testOperatorNamespace}
			_, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(cr)})

			var stored kagiv1alpha1.KagiCertificate
			if getErr := c.Get(context.Background(), client.ObjectKeyFromObject(cr), &stored); getErr != nil {
				t.Fatalf("get KagiCertificate: %v", getErr)
			}

			if tc.wantReason != "" {
				assertRefused(t, err, stored.Status.Conditions, stored.Status.LastErrorMessage, tc.wantReason)
				assertUntouched(t, c, before)
				if n := fetches.Load(); n != 0 {
					t.Errorf("the certificate was fetched %d times for a Secret the resource may not write", n)
				}
				return
			}

			if err != nil {
				t.Fatalf("Reconcile: %v", err)
			}
			assertOwnedAndSynced(t, c, owner, map[string]string{"tls.crt": "crt", "tls.key": "key"})
		})
	}
}

func TestKagiSecretDeletionDeletesOnlyAnOwnedSecret(t *testing.T) {
	cr, _ := ownershipKagiSecret()
	owner := managedSecretOwner(kindKagiSecret, cr)

	for _, tc := range ownershipCases(owner, kagiSecretIdentity(), opaqueVictimSecret) {
		t.Run(tc.name, func(t *testing.T) {
			// No token Secret exists: deletion must not depend on one.
			cr := cr.DeepCopy()
			now := metav1.Now()
			cr.DeletionTimestamp = &now
			c := newOwnershipFakeClient(t, tc.existing, cr)
			before := getVictim(t, c)
			recorder := record.NewFakeRecorder(eventBuffer)

			r := &KagiSecretReconciler{Client: c, Scheme: c.Scheme(), Recorder: recorder, OperatorNamespace: testOperatorNamespace}
			if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(cr)}); err != nil {
				t.Fatalf("Reconcile: %v", err)
			}

			assertFinalizerReleased(t, c, &kagiv1alpha1.KagiSecret{}, client.ObjectKeyFromObject(cr))
			assertDeletionOutcome(t, c, tc, before)
			assertLeftInPlaceEvent(t, recorder, tc, before)
		})
	}
}

func TestKagiCertificateDeletionDeletesOnlyAnOwnedSecret(t *testing.T) {
	cr, _ := ownershipKagiCertificate()
	owner := managedSecretOwner(kindKagiCertificate, cr)

	for _, tc := range ownershipCases(owner, kagiCertificateIdentity(), tlsVictimSecret) {
		t.Run(tc.name, func(t *testing.T) {
			// No token Secret exists: deletion must not depend on one.
			cr := cr.DeepCopy()
			now := metav1.Now()
			cr.DeletionTimestamp = &now
			c := newOwnershipFakeClient(t, tc.existing, cr)
			before := getVictim(t, c)
			recorder := record.NewFakeRecorder(eventBuffer)

			r := &KagiCertificateReconciler{Client: c, Scheme: c.Scheme(), Recorder: recorder, OperatorNamespace: testOperatorNamespace}
			if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(cr)}); err != nil {
				t.Fatalf("Reconcile: %v", err)
			}

			assertFinalizerReleased(t, c, &kagiv1alpha1.KagiCertificate{}, client.ObjectKeyFromObject(cr))
			assertDeletionOutcome(t, c, tc, before)
			assertLeftInPlaceEvent(t, recorder, tc, before)
		})
	}
}

// assertFinalizerReleased checks that the resource is gone: the fake client
// removes an object with a deletion timestamp once its last finalizer is
// removed, so a resource still present means it is stuck.
func assertFinalizerReleased(t *testing.T, c client.Client, obj client.Object, key types.NamespacedName) {
	t.Helper()
	err := c.Get(context.Background(), key, obj)
	if err == nil {
		t.Fatalf("%s still exists with finalizers %v, want the finalizer removed", key, obj.GetFinalizers())
	}
	if !apierrors.IsNotFound(err) {
		t.Fatalf("get %s: %v", key, err)
	}
}

// assertDeletionOutcome checks that the Secret was deleted when the resource
// owned it and is untouched otherwise.
func assertDeletionOutcome(t *testing.T, c client.Client, tc ownershipCase, before *corev1.Secret) {
	t.Helper()
	switch {
	case before == nil:
		if getVictim(t, c) != nil {
			t.Errorf("Secret %s exists after deletion, want none", victimKey)
		}
	case tc.deletedWithOwner:
		if getVictim(t, c) != nil {
			t.Errorf("Secret %s survived deletion of its owner", victimKey)
		}
	default:
		assertUntouched(t, c, before)
	}
}

// assertLeftInPlaceEvent checks that deleting the resource emitted exactly
// one Warning Event naming the Secret when it left an existing Secret in
// place, and none otherwise.
func assertLeftInPlaceEvent(t *testing.T, recorder *record.FakeRecorder, tc ownershipCase, before *corev1.Secret) {
	t.Helper()
	events := recordedEvents(recorder)
	if before == nil || tc.deletedWithOwner {
		if len(events) != 0 {
			t.Errorf("Events = %v, want none", events)
		}
		return
	}
	if len(events) != 1 {
		t.Fatalf("Events = %v, want one %s Warning", events, eventReasonSecretLeftInPlace)
	}
	want := corev1.EventTypeWarning + " " + eventReasonSecretLeftInPlace + " "
	if !strings.HasPrefix(events[0], want) || !strings.Contains(events[0], victimKey.String()) {
		t.Errorf("Event = %q, want a %q Event that names Secret %s", events[0], want, victimKey)
	}
}

// recordedEvents returns the Events recorder holds without blocking.
func recordedEvents(recorder *record.FakeRecorder) []string {
	var events []string
	for {
		select {
		case event := <-recorder.Events:
			events = append(events, event)
		default:
			return events
		}
	}
}

func TestManagedSecretIntactRequiresOwnership(t *testing.T) {
	cr, _ := ownershipKagiSecret()
	owner := managedSecretOwner(kindKagiSecret, cr)
	data := map[string][]byte{"FOO": []byte("bar")}
	hash := computeDataHashBytes(data)

	cases := []struct {
		name        string
		labels      map[string]string
		annotations map[string]string
		want        bool
	}{
		{
			name:        "owned by this KagiSecret",
			labels:      map[string]string{labelManagedBy: managedByValue},
			annotations: map[string]string{annotationHash: hash, annotationOwner: owner},
			want:        true,
		},
		{
			name:        "labelled without owner",
			labels:      map[string]string{labelManagedBy: managedByValue},
			annotations: map[string]string{annotationHash: hash},
		},
		{
			name:        "owned by another resource",
			labels:      map[string]string{labelManagedBy: managedByValue},
			annotations: map[string]string{annotationHash: hash, annotationOwner: otherOwner},
		},
		{
			name:        "not created by the operator",
			annotations: map[string]string{annotationHash: hash, annotationOwner: owner},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			existing := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: victimSecretName, Namespace: victimNamespace, Labels: tc.labels, Annotations: tc.annotations},
				Type:       corev1.SecretTypeOpaque,
				Data:       data,
			}
			c := newOwnershipFakeClient(t, existing, cr.DeepCopy())
			r := &KagiSecretReconciler{Client: c, Scheme: c.Scheme(), OperatorNamespace: testOperatorNamespace}

			got, err := r.managedSecretIntact(context.Background(), cr)
			if err != nil {
				t.Fatalf("managedSecretIntact: %v", err)
			}
			if got != tc.want {
				t.Errorf("managedSecretIntact = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestReconcileAdoptsUnclaimedSecretWhenVersionMatches covers the upgrade: every
// Secret written by an earlier release carries the managed-by label and a data
// hash, but no owner. Even with an unchanged upstream version, the first reconcile must not
// take the skip path, so that the owner is stamped before the resource can be
// deleted; otherwise its deletion would leave the Secret behind.
func TestReconcileAdoptsUnclaimedSecretWhenVersionMatches(t *testing.T) {
	var fetches atomic.Int32
	server := ownershipKagiServer(&fetches)
	defer server.Close()

	cr, token := ownershipKagiSecret()
	cr.Status.LastVersion = "v-upstream"
	upstream := map[string][]byte{"FOO": []byte("bar")}
	unclaimed := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:        victimSecretName,
			Namespace:   victimNamespace,
			Labels:      map[string]string{labelManagedBy: managedByValue, labelAppID: "app-id-123", labelEnv: "production"},
			Annotations: map[string]string{annotationHash: computeDataHashBytes(upstream)},
		},
		Type: corev1.SecretTypeOpaque,
		Data: upstream,
	}
	c := newOwnershipFakeClient(t, unclaimed, cr, token)

	r := &KagiSecretReconciler{Client: c, Scheme: c.Scheme(), KagiAPIURL: server.URL, OperatorNamespace: testOperatorNamespace}
	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(cr)}); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if n := fetches.Load(); n != 1 {
		t.Errorf("secrets were fetched %d times, want 1: the version-match skip must not apply to an unclaimed Secret", n)
	}
	assertOwnedAndSynced(t, c, managedSecretOwner(kindKagiSecret, cr), map[string]string{"FOO": "bar"})
}

// TestCertManagedSecretKeyFallsBackToOwnNamespace covers the KagiCertificate
// fallback: with no managedSecret.namespace the Secret lives in the resource's
// namespace. The guard, the write and the delete all take their key from
// certManagedSecretKey.
func TestCertManagedSecretKeyFallsBackToOwnNamespace(t *testing.T) {
	cr, _ := ownershipKagiCertificate()
	cr.Spec.ManagedSecret.Namespace = ""

	key := certManagedSecretKey(cr)
	if want := (types.NamespacedName{Namespace: "default", Name: victimSecretName}); key != want {
		t.Errorf("certManagedSecretKey = %s, want %s", key, want)
	}
}

func TestClassifySecretOwnership(t *testing.T) {
	const owner = "KagiCertificate/apps/web-tls"
	cases := []struct {
		name        string
		labels      map[string]string
		annotations map[string]string
		want        secretOwnership
	}{
		{"owned", map[string]string{labelManagedBy: managedByValue}, map[string]string{annotationOwner: owner}, secretOwned},
		{"unclaimed", map[string]string{labelManagedBy: managedByValue}, map[string]string{annotationHash: legacyDataHash}, secretUnclaimed},
		{"empty owner annotation is unclaimed", map[string]string{labelManagedBy: managedByValue}, map[string]string{annotationOwner: "", annotationHash: legacyDataHash}, secretUnclaimed},
		{"label without a data hash, as on the webhook certificate Secret", map[string]string{labelManagedBy: managedByValue}, nil, secretNotManaged},
		{"empty data hash", map[string]string{labelManagedBy: managedByValue}, map[string]string{annotationHash: ""}, secretNotManaged},
		{"owned by another resource", map[string]string{labelManagedBy: managedByValue}, map[string]string{annotationOwner: otherOwner}, secretOwnedByOther},
		{"same namespace and name of another kind", map[string]string{labelManagedBy: managedByValue}, map[string]string{annotationOwner: "KagiSecret/apps/web-tls"}, secretOwnedByOther},
		{"no label", nil, map[string]string{annotationOwner: owner}, secretNotManaged},
		{"another manager's label", map[string]string{labelManagedBy: "helm"}, map[string]string{annotationOwner: owner}, secretNotManaged},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Labels: tc.labels, Annotations: tc.annotations}}
			if got := classifySecretOwnership(secret, owner); got != tc.want {
				t.Errorf("classifySecretOwnership = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestManagedSecretFailureReason(t *testing.T) {
	refused := checkSecretWritable(opaqueVictimSecret(nil, nil), &managedSecretClaim{owner: "KagiSecret/default/test"})
	if got := managedSecretFailureReason(fmt.Errorf("wrapped: %w", refused)); got != reasonSecretNotManaged {
		t.Errorf("reason of a wrapped ownership error = %q, want %q", got, reasonSecretNotManaged)
	}
	if got := managedSecretFailureReason(fmt.Errorf("conflict")); got != reasonSecretReconcileFailed {
		t.Errorf("reason of another error = %q, want %q", got, reasonSecretReconcileFailed)
	}
}

// concurrentChange is what another writer does to the live Secret just before
// the operator's write number attempt reaches the API server. It reports
// whether it changed anything.
type concurrentChange func(live *corev1.Secret, attempt int) bool

// newRacingFakeClient builds a fake client holding existing, in which change
// runs before every Update and Delete of the Secret at victimKey. A change
// bumps the resourceVersion, so the operator's write then fails its
// resourceVersion check with a Conflict, as it would on the API server.
func newRacingFakeClient(t *testing.T, existing *corev1.Secret, change concurrentChange) (client.Client, *int, *int) {
	t.Helper()
	var updates, deletes int
	race := func(ctx context.Context, cl client.WithWatch, obj client.Object, attempt int) error {
		if client.ObjectKeyFromObject(obj) != victimKey {
			return nil
		}
		var live corev1.Secret
		if err := cl.Get(ctx, victimKey, &live); err != nil {
			return err
		}
		if !change(&live, attempt) {
			return nil
		}
		return cl.Update(ctx, &live)
	}
	c := fake.NewClientBuilder().
		WithScheme(newFakeScheme(t)).
		WithObjects(existing.DeepCopy()).
		WithInterceptorFuncs(interceptor.Funcs{
			Update: func(ctx context.Context, cl client.WithWatch, obj client.Object, opts ...client.UpdateOption) error {
				updates++
				if err := race(ctx, cl, obj, updates); err != nil {
					return err
				}
				return cl.Update(ctx, obj, opts...)
			},
			Delete: func(ctx context.Context, cl client.WithWatch, obj client.Object, opts ...client.DeleteOption) error {
				deletes++
				if err := race(ctx, cl, obj, deletes); err != nil {
					return err
				}
				return cl.Delete(ctx, obj, opts...)
			},
		}).
		Build()
	return c, &updates, &deletes
}

// TestDeleteManagedSecretRechecksOwnershipAfterConflict covers a Secret that
// changes between the ownership check and the delete. The delete is
// conditional on the resourceVersion that was checked, so it fails; the
// Secret is then read and checked once more.
func TestDeleteManagedSecretRechecksOwnershipAfterConflict(t *testing.T) {
	const owner = "KagiSecret/default/test"
	owned := opaqueVictimSecret(
		map[string]string{labelManagedBy: managedByValue},
		map[string]string{annotationHash: legacyDataHash, annotationOwner: owner})

	cases := []struct {
		name        string
		change      concurrentChange
		wantDeleted bool
		wantErr     bool
		wantDeletes int
	}{
		{
			name: "updated in between and still owned",
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
		{
			name: "changed again before every attempt",
			change: func(live *corev1.Secret, attempt int) bool {
				live.Data["rotated"] = fmt.Append(nil, attempt)
				return true
			},
			wantErr:     true,
			wantDeletes: 2,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, _, deletes := newRacingFakeClient(t, owned, tc.change)

			_, err := deleteManagedSecret(context.Background(), c, c, victimKey, &managedSecretClaim{kind: kindKagiSecret, owner: owner})

			if tc.wantErr {
				if !apierrors.IsConflict(err) || !strings.Contains(err.Error(), victimKey.String()) {
					t.Errorf("deleteManagedSecret = %v, want a Conflict that names %s", err, victimKey)
				}
			} else if err != nil {
				t.Errorf("deleteManagedSecret: %v", err)
			}
			if *deletes != tc.wantDeletes {
				t.Errorf("delete was called %d times, want %d", *deletes, tc.wantDeletes)
			}
			after := getVictim(t, c)
			if tc.wantDeleted {
				if after != nil {
					t.Errorf("Secret %s survived deletion of its owner", victimKey)
				}
				return
			}
			if after == nil {
				t.Fatalf("Secret %s was deleted, want it left in place", victimKey)
			}
			if !tc.wantErr && after.Annotations[annotationOwner] != otherOwner {
				t.Errorf("annotation %s = %q, want the new owner %s kept", annotationOwner, after.Annotations[annotationOwner], otherOwner)
			}
		})
	}
}

// TestWriteManagedSecretAdoptionLosesRaceWithoutWriting covers a Secret written
// by an earlier release that another controller takes over between the
// operator's ownership check and its adopting update. The update carries the
// resourceVersion that was checked, so it fails with a Conflict instead of
// overwriting the Secret, and the next attempt sees the new state and refuses.
func TestWriteManagedSecretAdoptionLosesRaceWithoutWriting(t *testing.T) {
	legacy := opaqueVictimSecret(
		mergeLabels(map[string]string{labelManagedBy: managedByValue}, kagiSecretIdentity()),
		map[string]string{annotationHash: legacyDataHash})
	c, updates, _ := newRacingFakeClient(t, legacy, func(live *corev1.Secret, attempt int) bool {
		if attempt > 1 {
			return false
		}
		live.Labels = map[string]string{"app": "payments"}
		return true
	})
	data := map[string][]byte{"FOO": []byte("bar")}
	desired := &desiredManagedSecret{
		key: victimKey,
		claim: &managedSecretClaim{
			kind:              kindKagiSecret,
			owner:             "KagiSecret/default/test",
			namespace:         testOperatorNamespace,
			operatorNamespace: testOperatorNamespace,
			identity:          kagiSecretIdentity(),
		},
		dataHash:   computeDataHashBytes(data),
		data:       data,
		secretType: corev1.SecretTypeOpaque,
	}

	_, err := writeManagedSecret(context.Background(), c, desired)
	if !apierrors.IsConflict(err) {
		t.Fatalf("writeManagedSecret = %v, want a Conflict", err)
	}
	taken := getVictim(t, c)
	if taken == nil {
		t.Fatalf("Secret %s was deleted", victimKey)
	}
	if got := taken.Annotations[annotationOwner]; got != "" {
		t.Errorf("annotation %s = %q, want none: the adoption must not be written", annotationOwner, got)
	}
	if got := string(taken.Data["original"]); got != "untouched" {
		t.Errorf("data original = %q, want the Secret's own data kept", got)
	}

	_, err = writeManagedSecret(context.Background(), c, desired)
	if got := managedSecretFailureReason(err); got != reasonSecretNotManaged {
		t.Errorf("reason of the second attempt = %q (err %v), want %q", got, err, reasonSecretNotManaged)
	}
	assertUntouched(t, c, taken)
	if *updates != 1 {
		t.Errorf("update was called %d times, want 1: the second attempt must not write", *updates)
	}
}
