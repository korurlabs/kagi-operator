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
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	kagiv1alpha1 "github.com/korurlabs/kagi-operator/api/v1alpha1"
)

// The CRD Pattern on spec.organization only runs at admission, i.e. on a write.
// An object stored before that pattern landed keeps its malformed value and is
// never re-validated, so without a reconcile-time guard the operator would send
// it as X-Organization-ID on every reconcile for the life of the object. The
// fake client below writes the object straight into the tracker with no schema
// validation, which is exactly that pre-existing-object case.
//
// The failure the guard prevents is invisible at the point of the mistake: under
// tenancy enforcement STRICT the Kagi API answers 403 on every request, and
// under OFF/SHADOW it logs the mismatch server-side and proceeds on the token's
// own organization -- so the cross-check the author asked for silently never
// runs. Both of those are indistinguishable, from the cluster, from an unrelated
// credential problem.
const malformedOrganization = "acme"

// refusingKagiServer fails the test if it is ever called. The guard must refuse
// before the SDK client is constructed, so a reconcile of a CR with a malformed
// organization must reach the Kagi API zero times.
func refusingKagiServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("Kagi API was called with a malformed spec.organization: %s %s (X-Organization-ID=%q)",
			r.Method, r.URL.Path, r.Header.Get("X-Organization-ID"))
		w.WriteHeader(http.StatusInternalServerError)
	}))
}

// readyCondition returns the Ready condition from conditions, or nil.
func readyCondition(conditions []metav1.Condition) *metav1.Condition {
	for i := range conditions {
		if conditions[i].Type == "Ready" {
			return &conditions[i]
		}
	}
	return nil
}

// assertInvalidSpec checks that the guard reported the refusal where an operator
// will actually see it -- the Ready condition and LastErrorMessage -- rather than
// only returning an error into the controller-runtime log.
func assertInvalidSpec(t *testing.T, conditions []metav1.Condition, lastError string) {
	t.Helper()
	ready := readyCondition(conditions)
	if ready == nil {
		t.Fatalf("no Ready condition was set; conditions=%v", conditions)
	}
	if ready.Status != metav1.ConditionFalse {
		t.Errorf("Ready.Status = %q, want %q", ready.Status, metav1.ConditionFalse)
	}
	if ready.Reason != "InvalidSpec" {
		t.Errorf("Ready.Reason = %q, want %q", ready.Reason, "InvalidSpec")
	}
	// The message must name the field and the offending value, because the whole
	// point of the guard is that the API's own answer does not.
	if !strings.Contains(ready.Message, "spec.organization") {
		t.Errorf("Ready.Message = %q, want it to name spec.organization", ready.Message)
	}
	if !strings.Contains(ready.Message, malformedOrganization) {
		t.Errorf("Ready.Message = %q, want it to quote the rejected value %q", ready.Message, malformedOrganization)
	}
	if lastError == "" {
		t.Errorf("Status.LastErrorMessage is empty, want the validation error")
	}
}

// TestReconcileRefusesMalformedOrganization proves a KagiSecret whose
// spec.organization is not a UUID is refused at reconcile time, before any
// request is made.
func TestReconcileRefusesMalformedOrganization(t *testing.T) {
	scheme := newFakeScheme(t)
	server := refusingKagiServer(t)
	defer server.Close()

	cr, token := buildKagiSecret(malformedOrganization)
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(cr, token).
		WithStatusSubresource(&kagiv1alpha1.KagiSecret{}).
		Build()

	r := &KagiSecretReconciler{Client: fakeClient, Scheme: scheme, KagiAPIURL: server.URL}
	_, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: "test", Namespace: "default"}})
	if err == nil {
		t.Fatal("Reconcile returned nil, want a validation error")
	}
	if !strings.Contains(err.Error(), "spec.organization") {
		t.Errorf("Reconcile error = %q, want it to name spec.organization", err)
	}

	var stored kagiv1alpha1.KagiSecret
	if getErr := fakeClient.Get(context.Background(), types.NamespacedName{Name: "test", Namespace: "default"}, &stored); getErr != nil {
		t.Fatalf("Get after Reconcile: %v", getErr)
	}
	assertInvalidSpec(t, stored.Status.Conditions, stored.Status.LastErrorMessage)
}

// TestCertificateReconcileRefusesMalformedOrganization is the same proof for the
// KagiCertificate reconciler, which shares kagiClientOptions but has its own
// Reconcile and therefore its own guard.
func TestCertificateReconcileRefusesMalformedOrganization(t *testing.T) {
	scheme := newFakeScheme(t)
	server := refusingKagiServer(t)
	defer server.Close()

	cr := &kagiv1alpha1.KagiCertificate{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-cert",
			Namespace:  "default",
			Generation: 1,
			Finalizers: []string{certFinalizerName},
		},
		Spec: kagiv1alpha1.KagiCertificateSpec{
			CertificateID: "cert-id-123",
			Organization:  malformedOrganization,
			TokenSecret:   &kagiv1alpha1.TokenSecretRef{Name: "token", Namespace: "default"},
			ManagedSecret: kagiv1alpha1.ManagedSecretRef{Name: "managed-tls", Namespace: "default"},
		},
	}
	token := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "token", Namespace: "default"},
		Data:       map[string][]byte{"KAGI_TOKEN": []byte("vv_test")},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(cr, token).
		WithStatusSubresource(&kagiv1alpha1.KagiCertificate{}).
		Build()

	r := &KagiCertificateReconciler{Client: fakeClient, Scheme: scheme, KagiAPIURL: server.URL}
	_, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: "test-cert", Namespace: "default"}})
	if err == nil {
		t.Fatal("Reconcile returned nil, want a validation error")
	}
	if !strings.Contains(err.Error(), "spec.organization") {
		t.Errorf("Reconcile error = %q, want it to name spec.organization", err)
	}

	var stored kagiv1alpha1.KagiCertificate
	if getErr := fakeClient.Get(context.Background(), types.NamespacedName{Name: "test-cert", Namespace: "default"}, &stored); getErr != nil {
		t.Fatalf("Get after Reconcile: %v", getErr)
	}
	assertInvalidSpec(t, stored.Status.Conditions, stored.Status.LastErrorMessage)
}
