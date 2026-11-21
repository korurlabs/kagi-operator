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
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	kagiv1alpha1 "github.com/korurlabs/kagi-operator/api/v1alpha1"
)

// These tests exercise the reconcile workflow pieces in isolation using the
// controller-runtime fake client. They complement the envtest-based Ginkgo
// suite in kagisecret_controller_test.go. The fake client is sufficient here
// because we are asserting on our own helpers and on the predicate filter --
// not on kubelet/API server behavior.

func newFakeScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(s); err != nil {
		t.Fatalf("add corev1 scheme: %v", err)
	}
	if err := kagiv1alpha1.AddToScheme(s); err != nil {
		t.Fatalf("add kagi scheme: %v", err)
	}
	return s
}

// TestPatchStatusIfChangedSkipsNoOpWrite ensures we do not issue a
// Status().Update when the computed status matches the snapshot. This is the
// core defense against the self-triggered reconcile loop.
func TestPatchStatusIfChangedSkipsNoOpWrite(t *testing.T) {
	scheme := newFakeScheme(t)

	kagiSecret := &kagiv1alpha1.KagiSecret{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test",
			Namespace:  "default",
			Generation: 1,
		},
		Spec: kagiv1alpha1.KagiSecretSpec{
			AppID:         "app-123",
			Environment:   "e",
			ManagedSecret: &kagiv1alpha1.ManagedSecretRef{Name: "m", Namespace: "default"},
		},
		Status: kagiv1alpha1.KagiSecretStatus{
			SecretCount: 3,
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(kagiSecret).
		WithStatusSubresource(&kagiv1alpha1.KagiSecret{}).
		Build()

	r := &KagiSecretReconciler{Client: fakeClient, Scheme: scheme}

	// Pull the CR fresh and snapshot its status.
	fetched := &kagiv1alpha1.KagiSecret{}
	if err := fakeClient.Get(context.Background(), types.NamespacedName{Name: "test", Namespace: "default"}, fetched); err != nil {
		t.Fatalf("get: %v", err)
	}
	beforeRV := fetched.ResourceVersion
	previous := *fetched.Status.DeepCopy()

	// Call patchStatusIfChanged without mutating status; it must not write.
	if err := r.patchStatusIfChanged(context.Background(), fetched, &previous); err != nil {
		t.Fatalf("patchStatusIfChanged: %v", err)
	}

	after := &kagiv1alpha1.KagiSecret{}
	if err := fakeClient.Get(context.Background(), types.NamespacedName{Name: "test", Namespace: "default"}, after); err != nil {
		t.Fatalf("get after: %v", err)
	}
	if after.ResourceVersion != beforeRV {
		t.Errorf("resourceVersion bumped on no-op: before=%s after=%s", beforeRV, after.ResourceVersion)
	}
}

// TestPatchStatusIfChangedWritesOnChange ensures we DO write when the status
// actually changes (guard against overcorrecting the no-op path).
func TestPatchStatusIfChangedWritesOnChange(t *testing.T) {
	scheme := newFakeScheme(t)

	kagiSecret := &kagiv1alpha1.KagiSecret{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test",
			Namespace:  "default",
			Generation: 1,
		},
		Spec: kagiv1alpha1.KagiSecretSpec{
			AppID:         "app-123",
			Environment:   "e",
			ManagedSecret: &kagiv1alpha1.ManagedSecretRef{Name: "m", Namespace: "default"},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(kagiSecret).
		WithStatusSubresource(&kagiv1alpha1.KagiSecret{}).
		Build()

	r := &KagiSecretReconciler{Client: fakeClient, Scheme: scheme}

	fetched := &kagiv1alpha1.KagiSecret{}
	if err := fakeClient.Get(context.Background(), types.NamespacedName{Name: "test", Namespace: "default"}, fetched); err != nil {
		t.Fatalf("get: %v", err)
	}
	previous := *fetched.Status.DeepCopy()

	// Mutate status.
	fetched.Status.SecretCount = 7
	setReadyCondition(&fetched.Status.Conditions, fetched.Generation, metav1.ConditionTrue, "SyncSuccessful", "ok")

	if err := r.patchStatusIfChanged(context.Background(), fetched, &previous); err != nil {
		t.Fatalf("patchStatusIfChanged: %v", err)
	}

	after := &kagiv1alpha1.KagiSecret{}
	if err := fakeClient.Get(context.Background(), types.NamespacedName{Name: "test", Namespace: "default"}, after); err != nil {
		t.Fatalf("get after: %v", err)
	}
	if after.Status.SecretCount != 7 {
		t.Errorf("expected SecretCount=7, got %d", after.Status.SecretCount)
	}
}

// TestReconcileManagedSecretNoOpWhenDataUnchanged verifies the Secret-sync
// helper returns changed=false and does NOT bump the Secret's resourceVersion
// when the upstream data matches the existing hash annotation. This is the
// second half of the idle-resync cost fix -- no Kagi-API-derived churn makes
// it to the K8s API.
func TestReconcileManagedSecretNoOpWhenDataUnchanged(t *testing.T) {
	scheme := newFakeScheme(t)

	secrets := map[string]string{"FOO": "bar", "BAZ": "qux"}
	dataHash := computeDataHash(secrets)

	kagiSecret := &kagiv1alpha1.KagiSecret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test",
			Namespace: "default",
		},
		Spec: kagiv1alpha1.KagiSecretSpec{
			AppID:       "app-123",
			Environment: "e",
			ManagedSecret: &kagiv1alpha1.ManagedSecretRef{
				Name:      "managed",
				Namespace: "default",
				Type:      "Opaque",
			},
		},
	}

	// Pre-seed the managed Secret with matching content + hash.
	existing := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "managed",
			Namespace: "default",
			Labels: map[string]string{
				labelManagedBy: managedByValue,
				labelAppID:     "app-123",
				labelEnv:       "e",
			},
			Annotations: map[string]string{
				annotationHash:  dataHash,
				annotationOwner: managedSecretOwner(kindKagiSecret, kagiSecret),
			},
		},
		Type: corev1.SecretType("Opaque"),
		Data: map[string][]byte{"FOO": []byte("bar"), "BAZ": []byte("qux")},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(kagiSecret, existing).
		Build()

	r := &KagiSecretReconciler{Client: fakeClient, Scheme: scheme}

	// Capture baseline resourceVersion.
	before := &corev1.Secret{}
	if err := fakeClient.Get(context.Background(), types.NamespacedName{Name: "managed", Namespace: "default"}, before); err != nil {
		t.Fatalf("get existing: %v", err)
	}
	beforeRV := before.ResourceVersion

	changed, err := r.reconcileManagedSecret(context.Background(), kagiSecret, "app-123", secrets)
	if err != nil {
		t.Fatalf("reconcileManagedSecret: %v", err)
	}
	if changed {
		t.Errorf("expected changed=false on identical content, got true")
	}

	after := &corev1.Secret{}
	if err := fakeClient.Get(context.Background(), types.NamespacedName{Name: "managed", Namespace: "default"}, after); err != nil {
		t.Fatalf("get after: %v", err)
	}
	if after.ResourceVersion != beforeRV {
		t.Errorf("resourceVersion bumped on no-op Secret reconcile: before=%s after=%s", beforeRV, after.ResourceVersion)
	}
}

// TestReconcileManagedSecretUpdatesWhenDataChanged verifies we still write
// when upstream secrets change.
func TestReconcileManagedSecretUpdatesWhenDataChanged(t *testing.T) {
	scheme := newFakeScheme(t)

	oldSecrets := map[string]string{"FOO": "old"}
	oldHash := computeDataHash(oldSecrets)

	kagiSecret := &kagiv1alpha1.KagiSecret{
		ObjectMeta: metav1.ObjectMeta{Name: "test", Namespace: "default"},
		Spec: kagiv1alpha1.KagiSecretSpec{
			AppID:       "app-123",
			Environment: "e",
			ManagedSecret: &kagiv1alpha1.ManagedSecretRef{
				Name:      "managed",
				Namespace: "default",
				Type:      "Opaque",
			},
		},
	}
	existing := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "managed",
			Namespace: "default",
			Labels:    map[string]string{labelManagedBy: managedByValue},
			Annotations: map[string]string{
				annotationHash:  oldHash,
				annotationOwner: managedSecretOwner(kindKagiSecret, kagiSecret),
			},
		},
		Type: corev1.SecretType("Opaque"),
		Data: map[string][]byte{"FOO": []byte("old")},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(kagiSecret, existing).
		Build()

	r := &KagiSecretReconciler{Client: fakeClient, Scheme: scheme}

	newSecrets := map[string]string{"FOO": "new"}
	changed, err := r.reconcileManagedSecret(context.Background(), kagiSecret, "app-123", newSecrets)
	if err != nil {
		t.Fatalf("reconcileManagedSecret: %v", err)
	}
	if !changed {
		t.Fatalf("expected changed=true when secret data changed")
	}

	after := &corev1.Secret{}
	if err := fakeClient.Get(context.Background(), types.NamespacedName{Name: "managed", Namespace: "default"}, after); err != nil {
		t.Fatalf("get after: %v", err)
	}
	if string(after.Data["FOO"]) != "new" {
		t.Errorf("expected FOO=new, got %s", string(after.Data["FOO"]))
	}
}

// TestPredicateFiltersStatusOnlyUpdate proves that the exact predicate wired
// into SetupWithManager rejects a status-only update (one where .generation,
// .labels, and .annotations are all unchanged). This is the final piece
// that closes the reconcile loop: even if r.Status().Update DID fire, the
// predicate drops the resulting watch event.
func TestPredicateFiltersStatusOnlyUpdate(t *testing.T) {
	p := predicate.Or(
		predicate.GenerationChangedPredicate{},
		predicate.AnnotationChangedPredicate{},
		predicate.LabelChangedPredicate{},
	)

	oldObj := &kagiv1alpha1.KagiSecret{
		ObjectMeta: metav1.ObjectMeta{
			Name:            "test",
			Namespace:       "default",
			Generation:      2,
			ResourceVersion: "100",
			Labels:          map[string]string{"foo": "bar"},
			Annotations:     map[string]string{"a": "1"},
		},
		Status: kagiv1alpha1.KagiSecretStatus{SecretCount: 3},
	}
	// Status-only bump: same generation, labels, annotations; newer RV.
	newObj := oldObj.DeepCopy()
	newObj.ResourceVersion = "101"
	newObj.Status.SecretCount = 4

	if p.Update(event.UpdateEvent{ObjectOld: oldObj, ObjectNew: newObj}) {
		t.Errorf("predicate should drop status-only update")
	}

	// Spec change (generation bump) must pass.
	specChange := oldObj.DeepCopy()
	specChange.Generation = 3
	specChange.ResourceVersion = "102"
	if !p.Update(event.UpdateEvent{ObjectOld: oldObj, ObjectNew: specChange}) {
		t.Errorf("predicate should pass generation change")
	}

	// Annotation change (force-resync pattern) must pass.
	annoChange := oldObj.DeepCopy()
	annoChange.Annotations = map[string]string{"a": "2"}
	annoChange.ResourceVersion = "103"
	if !p.Update(event.UpdateEvent{ObjectOld: oldObj, ObjectNew: annoChange}) {
		t.Errorf("predicate should pass annotation change")
	}
}

// Compile-time check that KagiSecretReconciler satisfies the client.Reader
// interface expected by our helpers. Cheap guard against accidental signature
// drift.
var _ client.Reader = (*KagiSecretReconciler)(nil)
