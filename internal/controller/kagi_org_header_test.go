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

const orgUUID = "00000000-0000-0000-0000-000000000001"

// buildKagiSecret returns a reconcilable KagiSecret CR (with finalizer already
// present so Reconcile proceeds past the finalizer-add early return) and its
// backing token secret.
func buildKagiSecret(org string) (*kagiv1alpha1.KagiSecret, *corev1.Secret) {
	cr := &kagiv1alpha1.KagiSecret{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test",
			Namespace:  "default",
			Generation: 1,
			Finalizers: []string{finalizerName},
		},
		Spec: kagiv1alpha1.KagiSecretSpec{
			AppID:        "app-id-123",
			Environment:  "production",
			Organization: org,
			TokenSecret:  &kagiv1alpha1.TokenSecretRef{Name: "token", Namespace: "default"},
			ManagedSecret: &kagiv1alpha1.ManagedSecretRef{
				Name:      "managed",
				Namespace: "default",
				Type:      "Opaque",
			},
		},
	}
	token := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "token", Namespace: "default"},
		Data:       map[string][]byte{"KAGI_TOKEN": []byte("vv_test")},
	}
	return cr, token
}

// fullFlowKagiServer responds to the app-id-addressed secret fetch so Reconcile
// reaches a successful sync, recording the X-Organization-ID header seen on
// every request. The CR binds by spec.appId, so no folder-resolution call is
// made -- the only request is the /kagi/apps/{appId}/.../secrets/fetch route.
func fullFlowKagiServer(t *testing.T, captured *string, present *bool) *httptest.Server {
	t.Helper()
	writeJSON := func(w http.ResponseWriter, data any) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(data)
	}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*captured = r.Header.Get("X-Organization-ID")
		if _, ok := r.Header["X-Organization-Id"]; ok {
			*present = true
		}

		p := r.URL.Path
		switch {
		case strings.HasSuffix(p, "/secrets/version"):
			writeJSON(w, map[string]any{"version": "v-test-1", "count": 1})
		case strings.HasSuffix(p, "/secrets/fetch"):
			writeJSON(w, map[string]any{"secrets": map[string]string{"FOO": "bar"}})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

// TestReconcileSendsOrgHeaderWhenSet verifies that a KagiSecret with
// spec.Organization set causes the SDK client to send X-Organization-ID on its
// fetch calls.
func TestReconcileSendsOrgHeaderWhenSet(t *testing.T) {
	scheme := newFakeScheme(t)
	var captured string
	var present bool
	server := fullFlowKagiServer(t, &captured, &present)
	defer server.Close()

	cr, token := buildKagiSecret(orgUUID)
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(cr, token).
		WithStatusSubresource(&kagiv1alpha1.KagiSecret{}).
		Build()

	r := &KagiSecretReconciler{Client: fakeClient, Scheme: scheme, KagiAPIURL: server.URL}
	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: "test", Namespace: "default"}}); err != nil {
		t.Fatalf("Reconcile returned error: %v", err)
	}
	if captured != orgUUID {
		t.Errorf("expected X-Organization-ID %q, got %q", orgUUID, captured)
	}
}

// TestReconcileOmitsOrgHeaderWhenEmpty verifies that a KagiSecret WITHOUT
// spec.Organization sends NO X-Organization-ID header -- byte-identical to the
// pre-multi-org behavior.
func TestReconcileOmitsOrgHeaderWhenEmpty(t *testing.T) {
	scheme := newFakeScheme(t)
	var captured string
	var present bool
	server := fullFlowKagiServer(t, &captured, &present)
	defer server.Close()

	cr, token := buildKagiSecret("")
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(cr, token).
		WithStatusSubresource(&kagiv1alpha1.KagiSecret{}).
		Build()

	r := &KagiSecretReconciler{Client: fakeClient, Scheme: scheme, KagiAPIURL: server.URL}
	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: "test", Namespace: "default"}}); err != nil {
		t.Fatalf("Reconcile returned error: %v", err)
	}
	if present {
		t.Errorf("expected no X-Organization-ID header when org unset, but it was present (value=%q)", captured)
	}
}

// TestCertificateReconcileSendsOrgHeaderWhenSet verifies the same cross-check
// header wiring for the KagiCertificate reconciler.
func TestCertificateReconcileSendsOrgHeaderWhenSet(t *testing.T) {
	scheme := newFakeScheme(t)
	var captured string
	server := certFlowKagiServer(t, &captured)
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
			Organization:  orgUUID,
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
	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: "test-cert", Namespace: "default"}}); err != nil {
		t.Fatalf("Reconcile returned error: %v", err)
	}
	if captured != orgUUID {
		t.Errorf("expected X-Organization-ID %q, got %q", orgUUID, captured)
	}
}

// certFlowKagiServer responds to the certificate by-id TLS fetch, recording the
// X-Organization-ID header.
func certFlowKagiServer(t *testing.T, captured *string) *httptest.Server {
	t.Helper()
	// A minimal self-consistent PEM so parseCertificateMetadata does not panic;
	// it tolerates a nil block, so any body is fine here.
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*captured = r.Header.Get("X-Organization-ID")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"name": "sensey-io", "tlsCrt": "crt", "tlsKey": "key"})
	}))
}
