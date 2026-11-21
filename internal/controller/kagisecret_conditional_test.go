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
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	kagiv1alpha1 "github.com/korurlabs/kagi-operator/api/v1alpha1"
)

// TestReconcileSkipsFetchWhenVersionMatches proves the scale fix: when the
// upstream version equals status.LastVersion and the managed Secret is still
// intact, Reconcile serves the version probe but NEVER hits the (decrypting)
// /secrets/fetch route.
func TestReconcileSkipsFetchWhenVersionMatches(t *testing.T) {
	scheme := newFakeScheme(t)

	const version = "v-stable-42"
	var fetchHit bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/secrets/fetch") {
			fetchHit = true
			t.Errorf("fetch must be skipped on version match, but /secrets/fetch was hit")
		}
		w.Header().Set("Content-Type", "application/json")
		if strings.HasSuffix(r.URL.Path, "/secrets/version") {
			_ = json.NewEncoder(w).Encode(map[string]any{"version": version, "count": 1})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	cr := &kagiv1alpha1.KagiSecret{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test",
			Namespace:  "default",
			Generation: 1,
			Finalizers: []string{finalizerName},
		},
		Spec: kagiv1alpha1.KagiSecretSpec{
			AppID:       "app-id-123",
			Environment: "production",
			TokenSecret: &kagiv1alpha1.TokenSecretRef{Name: "token", Namespace: "default"},
			ManagedSecret: &kagiv1alpha1.ManagedSecretRef{
				Name:      "managed",
				Namespace: "default",
				Type:      "Opaque",
			},
		},
		Status: kagiv1alpha1.KagiSecretStatus{
			LastVersion: version,
		},
	}
	token := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "token", Namespace: "default"},
		Data:       map[string][]byte{"KAGI_TOKEN": []byte("vv_test")},
	}
	// Intact managed Secret: our managed-by label, an owner annotation naming
	// this KagiSecret, and a data-hash annotation that matches the current data,
	// so the tamper check inside managedSecretIntact passes and the
	// version-match skip holds.
	managed := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "managed",
			Namespace: "default",
			Labels:    map[string]string{labelManagedBy: managedByValue, labelAppID: "app-id-123", labelEnv: "production"},
			Annotations: map[string]string{
				annotationHash:  computeDataHash(map[string]string{"FOO": "bar"}),
				annotationOwner: managedSecretOwner(kindKagiSecret, cr),
			},
		},
		Type: corev1.SecretType("Opaque"),
		Data: map[string][]byte{"FOO": []byte("bar")},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(cr, token, managed).
		WithStatusSubresource(&kagiv1alpha1.KagiSecret{}).
		Build()

	r := &KagiSecretReconciler{Client: fakeClient, Scheme: scheme, KagiAPIURL: server.URL}
	res, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: "test", Namespace: "default"}})
	if err != nil {
		t.Fatalf("Reconcile returned error: %v", err)
	}
	if fetchHit {
		t.Fatal("fetch was hit despite version match")
	}
	if res.RequeueAfter <= 0 {
		t.Errorf("expected a positive jittered RequeueAfter, got %v", res.RequeueAfter)
	}
}

// TestReconcileFetchesWhenManagedSecretDataTampered proves the self-heal path:
// even when the upstream version matches status.LastVersion and the managed
// Secret carries our label + a non-empty data-hash annotation, an out-of-band
// edit to the Secret's data (annotation left intact) must force a fetch and
// restore the Secret's data. Without the tamper check the skip guard would
// leave the mutated data in place indefinitely.
func TestReconcileFetchesWhenManagedSecretDataTampered(t *testing.T) {
	scheme := newFakeScheme(t)

	const version = "v-stable-42"
	var fetchHit bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/secrets/version"):
			_ = json.NewEncoder(w).Encode(map[string]any{"version": version, "count": 1})
		case strings.HasSuffix(r.URL.Path, "/secrets/fetch"):
			fetchHit = true
			_ = json.NewEncoder(w).Encode(map[string]any{"secrets": map[string]string{"FOO": "bar"}})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	cr := &kagiv1alpha1.KagiSecret{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test",
			Namespace:  "default",
			Generation: 1,
			Finalizers: []string{finalizerName},
		},
		Spec: kagiv1alpha1.KagiSecretSpec{
			AppID:       "app-id-123",
			Environment: "production",
			TokenSecret: &kagiv1alpha1.TokenSecretRef{Name: "token", Namespace: "default"},
			ManagedSecret: &kagiv1alpha1.ManagedSecretRef{
				Name:      "managed",
				Namespace: "default",
				Type:      "Opaque",
			},
		},
		Status: kagiv1alpha1.KagiSecretStatus{LastVersion: version},
	}
	token := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "token", Namespace: "default"},
		Data:       map[string][]byte{"KAGI_TOKEN": []byte("vv_test")},
	}
	// Managed Secret with correct label + a data-hash annotation for the true
	// upstream data (FOO=bar), but its data was tampered out-of-band (FOO=hacked).
	// The annotation is intentionally left intact to simulate a data-only edit.
	managed := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:        "managed",
			Namespace:   "default",
			Labels:      map[string]string{labelManagedBy: managedByValue, labelAppID: "app-id-123", labelEnv: "production"},
			Annotations: map[string]string{annotationHash: computeDataHash(map[string]string{"FOO": "bar"})},
		},
		Type: corev1.SecretType("Opaque"),
		Data: map[string][]byte{"FOO": []byte("hacked")},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(cr, token, managed).
		WithStatusSubresource(&kagiv1alpha1.KagiSecret{}).
		Build()

	r := &KagiSecretReconciler{Client: fakeClient, Scheme: scheme, KagiAPIURL: server.URL}
	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: "test", Namespace: "default"}}); err != nil {
		t.Fatalf("Reconcile returned error: %v", err)
	}
	if !fetchHit {
		t.Fatal("expected a fetch when managed Secret data was tampered, but /secrets/fetch was not hit")
	}

	// The managed Secret's data must be restored to the true upstream value.
	after := &corev1.Secret{}
	if err := fakeClient.Get(context.Background(), types.NamespacedName{Name: "managed", Namespace: "default"}, after); err != nil {
		t.Fatalf("get managed after: %v", err)
	}
	if got := string(after.Data["FOO"]); got != "bar" {
		t.Errorf("expected managed Secret data FOO restored to %q, got %q", "bar", got)
	}
}

// TestReconcileFetchesWhenVersionDiffers verifies the complement: a changed
// upstream version forces a fetch and records the new version in status.
func TestReconcileFetchesWhenVersionDiffers(t *testing.T) {
	scheme := newFakeScheme(t)

	var fetchHit bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/secrets/version"):
			_ = json.NewEncoder(w).Encode(map[string]any{"version": "v-new", "count": 1})
		case strings.HasSuffix(r.URL.Path, "/secrets/fetch"):
			fetchHit = true
			_ = json.NewEncoder(w).Encode(map[string]any{"secrets": map[string]string{"FOO": "bar"}})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	cr := &kagiv1alpha1.KagiSecret{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test",
			Namespace:  "default",
			Generation: 1,
			Finalizers: []string{finalizerName},
		},
		Spec: kagiv1alpha1.KagiSecretSpec{
			AppID:       "app-id-123",
			Environment: "production",
			TokenSecret: &kagiv1alpha1.TokenSecretRef{Name: "token", Namespace: "default"},
			ManagedSecret: &kagiv1alpha1.ManagedSecretRef{
				Name:      "managed",
				Namespace: "default",
				Type:      "Opaque",
			},
		},
		Status: kagiv1alpha1.KagiSecretStatus{LastVersion: "v-old"},
	}
	token := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "token", Namespace: "default"},
		Data:       map[string][]byte{"KAGI_TOKEN": []byte("vv_test")},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(cr, token).
		WithStatusSubresource(&kagiv1alpha1.KagiSecret{}).
		Build()

	r := &KagiSecretReconciler{Client: fakeClient, Scheme: scheme, KagiAPIURL: server.URL}
	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: "test", Namespace: "default"}}); err != nil {
		t.Fatalf("Reconcile returned error: %v", err)
	}
	if !fetchHit {
		t.Fatal("expected a fetch when version differs, but /secrets/fetch was not hit")
	}

	after := &kagiv1alpha1.KagiSecret{}
	if err := fakeClient.Get(context.Background(), types.NamespacedName{Name: "test", Namespace: "default"}, after); err != nil {
		t.Fatalf("get after: %v", err)
	}
	if after.Status.LastVersion != "v-new" {
		t.Errorf("expected status.LastVersion=v-new, got %q", after.Status.LastVersion)
	}
	if after.Status.ResolvedAppID != "app-id-123" {
		t.Errorf("expected status.ResolvedAppID=app-id-123, got %q", after.Status.ResolvedAppID)
	}
}

// TestReconcileFallsBackToFetchWhenVersionProbeFails verifies the graceful
// degrade path: an older backend without the version route (404) causes an
// unconditional fetch.
func TestReconcileFallsBackToFetchWhenVersionProbeFails(t *testing.T) {
	scheme := newFakeScheme(t)

	var fetchHit bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/secrets/version"):
			w.WriteHeader(http.StatusNotFound)
		case strings.HasSuffix(r.URL.Path, "/secrets/fetch"):
			fetchHit = true
			_ = json.NewEncoder(w).Encode(map[string]any{"secrets": map[string]string{"FOO": "bar"}})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	// Even though LastVersion is set, an unknown current version must not skip.
	cr := &kagiv1alpha1.KagiSecret{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test",
			Namespace:  "default",
			Generation: 1,
			Finalizers: []string{finalizerName},
		},
		Spec: kagiv1alpha1.KagiSecretSpec{
			AppID:       "app-id-123",
			Environment: "production",
			TokenSecret: &kagiv1alpha1.TokenSecretRef{Name: "token", Namespace: "default"},
			ManagedSecret: &kagiv1alpha1.ManagedSecretRef{
				Name:      "managed",
				Namespace: "default",
				Type:      "Opaque",
			},
		},
		Status: kagiv1alpha1.KagiSecretStatus{LastVersion: "v-old"},
	}
	token := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "token", Namespace: "default"},
		Data:       map[string][]byte{"KAGI_TOKEN": []byte("vv_test")},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(cr, token).
		WithStatusSubresource(&kagiv1alpha1.KagiSecret{}).
		Build()

	r := &KagiSecretReconciler{Client: fakeClient, Scheme: scheme, KagiAPIURL: server.URL}
	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: "test", Namespace: "default"}}); err != nil {
		t.Fatalf("Reconcile returned error: %v", err)
	}
	if !fetchHit {
		t.Fatal("expected fallback fetch when version probe fails, but /secrets/fetch was not hit")
	}
}

// TestJitteredDurationBounds asserts the jittered resync stays within
// [base-maxJitter, base+maxJitter] and is deterministic per key.
func TestJitteredDurationBounds(t *testing.T) {
	base := 5 * time.Minute
	maxJitter := 60 * time.Second

	keys := []string{"a/b", "ns/name", "uid-123ns/name", "another-object"}
	for _, k := range keys {
		got := jitteredDuration(base, maxJitter, k)
		if got < base-maxJitter || got > base+maxJitter {
			t.Errorf("jitteredDuration(%q) = %v, out of bounds [%v, %v]", k, got, base-maxJitter, base+maxJitter)
		}
		// Determinism: same key -> same offset.
		if again := jitteredDuration(base, maxJitter, k); again != got {
			t.Errorf("jitteredDuration not deterministic for %q: %v vs %v", k, got, again)
		}
	}

	// Distinct keys should not all collapse to the same value.
	if jitteredDuration(base, maxJitter, "x") == jitteredDuration(base, maxJitter, "y") &&
		jitteredDuration(base, maxJitter, "x") == jitteredDuration(base, maxJitter, "z") {
		t.Error("expected jitter to spread distinct keys, got identical values")
	}
}

// TestJitteredDurationSpread asserts offsets actually distribute across the
// full jitter window rather than collapsing into a narrow band. A 32-bit hash
// caps at ~4.3s in nanoseconds -- smaller than the 120s span -- so its modulo
// never wraps and every offset lands in [-60s, -55.7s]. This test would have
// caught that: it requires the observed min-to-max spread across many keys to
// exceed maxJitter (half the window), which the collapsed range cannot reach.
func TestJitteredDurationSpread(t *testing.T) {
	base := 5 * time.Minute
	maxJitter := 60 * time.Second

	minSeen := base + maxJitter
	maxSeen := base - maxJitter
	for i := range 500 {
		got := jitteredDuration(base, maxJitter, fmt.Sprintf("ns-%d/name-%d", i, i))
		if got < minSeen {
			minSeen = got
		}
		if got > maxSeen {
			maxSeen = got
		}
	}

	if spread := maxSeen - minSeen; spread <= maxJitter {
		t.Errorf("jitter offsets collapsed: observed spread %v across 500 keys, want > %v (window is %v)",
			spread, maxJitter, 2*maxJitter)
	}
}
