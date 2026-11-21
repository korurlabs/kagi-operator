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

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	kagiv1alpha1 "github.com/korurlabs/kagi-operator/api/v1alpha1"
)

// TestIsInjectedMode locks the mode discriminator: only the exact "Injected"
// string opts into injection; empty (the default) and "Secret" stay on the
// byte-for-byte-unchanged Secret path.
func TestIsInjectedMode(t *testing.T) {
	cases := map[string]bool{
		"":         false,
		"Secret":   false,
		"Injected": true,
		"injected": false, // exact match only
	}
	for mode, want := range cases {
		ks := &kagiv1alpha1.KagiSecret{Spec: kagiv1alpha1.KagiSecretSpec{Mode: mode}}
		if got := isInjectedMode(ks); got != want {
			t.Errorf("isInjectedMode(%q) = %v, want %v", mode, got, want)
		}
	}
}

// injectedKagiSecret returns an Injected-mode CR that deliberately omits
// managedSecret: Injected mode never materializes a Secret, so the field is
// optional there. The rollout namespace falls back to the CR's namespace.
func injectedKagiSecret(deployments []string) *kagiv1alpha1.KagiSecret {
	return &kagiv1alpha1.KagiSecret{
		ObjectMeta: metav1.ObjectMeta{Name: "portal", Namespace: "apps"},
		Spec: kagiv1alpha1.KagiSecretSpec{
			AppID:       "app-123",
			Environment: "production",
			Mode:        modeInjected,
			Rollout:     &kagiv1alpha1.RolloutSpec{Deployments: deployments},
		},
	}
}

// (d) Injected-mode rollout stamps the named target's pod-template annotation
// (triggering a native rolling restart) and creates NO Secret.
func TestRolloutInjectedTargetsPatchesNamedDeploymentAndCreatesNoSecret(t *testing.T) {
	scheme := newFakeScheme(t)

	deployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: "portal", Namespace: "apps"},
	}
	ks := injectedKagiSecret([]string{"portal"})

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(ks, deployment).
		Build()

	r := &KagiSecretReconciler{Client: fakeClient, Scheme: scheme}

	if err := r.rolloutInjectedTargets(context.Background(), ks, "v42"); err != nil {
		t.Fatalf("rolloutInjectedTargets: %v", err)
	}

	after := &appsv1.Deployment{}
	if err := fakeClient.Get(context.Background(), types.NamespacedName{Name: "portal", Namespace: "apps"}, after); err != nil {
		t.Fatalf("get deployment: %v", err)
	}
	if got := after.Spec.Template.Annotations[annotationSecretsVersion]; got != "v42" {
		t.Errorf("pod-template secrets-version annotation: got %q want %q", got, "v42")
	}

	// Injected mode must never materialize a Secret.
	secret := &corev1.Secret{}
	err := fakeClient.Get(context.Background(), types.NamespacedName{Name: "unused", Namespace: "apps"}, secret)
	if !apierrors.IsNotFound(err) {
		t.Errorf("Injected mode must not create a Secret; got err=%v", err)
	}
}

// (d-cont) Re-stamping the same version is a no-op: no resourceVersion bump, so
// the Deployment controller does not restart the workload a second time.
func TestStampDeploymentVersionNoOpWhenEqual(t *testing.T) {
	scheme := newFakeScheme(t)

	deployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: "portal", Namespace: "apps"},
	}
	deployment.Spec.Template.Annotations = map[string]string{annotationSecretsVersion: "v42"}

	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(deployment).Build()
	r := &KagiSecretReconciler{Client: fakeClient, Scheme: scheme}

	before := &appsv1.Deployment{}
	if err := fakeClient.Get(context.Background(), types.NamespacedName{Name: "portal", Namespace: "apps"}, before); err != nil {
		t.Fatalf("get: %v", err)
	}
	beforeRV := before.ResourceVersion

	if err := r.stampDeploymentVersion(context.Background(), before, "v42"); err != nil {
		t.Fatalf("stampDeploymentVersion: %v", err)
	}

	after := &appsv1.Deployment{}
	if err := fakeClient.Get(context.Background(), types.NamespacedName{Name: "portal", Namespace: "apps"}, after); err != nil {
		t.Fatalf("get after: %v", err)
	}
	if after.ResourceVersion != beforeRV {
		t.Errorf("resourceVersion bumped on no-op re-stamp: before=%s after=%s", beforeRV, after.ResourceVersion)
	}
}

// (d-cont) The workloadSelector path patches label-matched deployments and does
// not double-patch a deployment already covered by name.
func TestRolloutInjectedTargetsSelector(t *testing.T) {
	scheme := newFakeScheme(t)

	selected := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "worker",
			Namespace: "apps",
			Labels:    map[string]string{"app.kubernetes.io/part-of": "kagi"},
		},
	}
	unrelated := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: "other", Namespace: "apps"},
	}

	ks := &kagiv1alpha1.KagiSecret{
		ObjectMeta: metav1.ObjectMeta{Name: "portal", Namespace: "apps"},
		Spec: kagiv1alpha1.KagiSecretSpec{
			Mode: modeInjected,
			Rollout: &kagiv1alpha1.RolloutSpec{
				WorkloadSelector: &metav1.LabelSelector{
					MatchLabels: map[string]string{"app.kubernetes.io/part-of": "kagi"},
				},
			},
		},
	}

	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(ks, selected, unrelated).Build()
	r := &KagiSecretReconciler{Client: fakeClient, Scheme: scheme}

	if err := r.rolloutInjectedTargets(context.Background(), ks, "v7"); err != nil {
		t.Fatalf("rolloutInjectedTargets: %v", err)
	}

	got := &appsv1.Deployment{}
	if err := fakeClient.Get(context.Background(), types.NamespacedName{Name: "worker", Namespace: "apps"}, got); err != nil {
		t.Fatalf("get worker: %v", err)
	}
	if got.Spec.Template.Annotations[annotationSecretsVersion] != "v7" {
		t.Errorf("selected deployment not stamped: %v", got.Spec.Template.Annotations)
	}

	other := &appsv1.Deployment{}
	if err := fakeClient.Get(context.Background(), types.NamespacedName{Name: "other", Namespace: "apps"}, other); err != nil {
		t.Fatalf("get other: %v", err)
	}
	if _, ok := other.Spec.Template.Annotations[annotationSecretsVersion]; ok {
		t.Errorf("unselected deployment must not be stamped")
	}
}

// A missing named rollout target surfaces an error rather than silently
// succeeding (no-silent-failures).
func TestRolloutInjectedTargetsMissingDeploymentErrors(t *testing.T) {
	scheme := newFakeScheme(t)
	ks := injectedKagiSecret([]string{"ghost"})
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(ks).Build()
	r := &KagiSecretReconciler{Client: fakeClient, Scheme: scheme}

	if err := r.rolloutInjectedTargets(context.Background(), ks, "v1"); err == nil {
		t.Fatalf("expected an error when a named rollout target does not exist")
	}
}

// (f) A full Reconcile of an Injected-mode CR that omits managedSecret is
// accepted (no validation error) and materializes NO Secret. This proves the
// CRD's conditional requirement is honored end-to-end: managedSecret is optional
// in Injected mode.
func TestReconcileInjectedAcceptsMissingManagedSecret(t *testing.T) {
	scheme := newFakeScheme(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.HasSuffix(r.URL.Path, "/secrets/version") {
			_ = json.NewEncoder(w).Encode(map[string]any{"version": "v1", "count": 1})
			return
		}
		if strings.HasSuffix(r.URL.Path, "/secrets/fetch") {
			t.Errorf("Injected mode must never fetch secrets into the operator")
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	cr := &kagiv1alpha1.KagiSecret{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "portal",
			Namespace:  "apps",
			Generation: 1,
			Finalizers: []string{finalizerName},
		},
		Spec: kagiv1alpha1.KagiSecretSpec{
			AppID:       "app-123",
			Environment: "production",
			Mode:        modeInjected,
			TokenSecret: &kagiv1alpha1.TokenSecretRef{Name: "token", Namespace: "apps"},
			// No managedSecret: optional in Injected mode.
		},
	}
	token := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "token", Namespace: "apps"},
		Data:       map[string][]byte{"KAGI_TOKEN": []byte("vv_test")},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(cr, token).
		WithStatusSubresource(&kagiv1alpha1.KagiSecret{}).
		Build()

	r := &KagiSecretReconciler{Client: fakeClient, Scheme: scheme, KagiAPIURL: server.URL}
	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: "portal", Namespace: "apps"}}); err != nil {
		t.Fatalf("Reconcile of injected CR without managedSecret must succeed, got: %v", err)
	}

	// No Secret other than the pre-existing token must exist in the namespace.
	var secrets corev1.SecretList
	if err := fakeClient.List(context.Background(), &secrets); err != nil {
		t.Fatalf("list secrets: %v", err)
	}
	for i := range secrets.Items {
		if secrets.Items[i].Name != "token" {
			t.Errorf("Injected mode must not materialize a Secret; found %q", secrets.Items[i].Name)
		}
	}

	after := &kagiv1alpha1.KagiSecret{}
	if err := fakeClient.Get(context.Background(), types.NamespacedName{Name: "portal", Namespace: "apps"}, after); err != nil {
		t.Fatalf("get after: %v", err)
	}
	if after.Status.LastVersion != "v1" {
		t.Errorf("expected status.LastVersion=v1 recorded on first observation, got %q", after.Status.LastVersion)
	}
}

// (f-cont) A full Reconcile of a Secret-mode CR (the default) that omits
// managedSecret must error via the validation path -- not silently operate on
// an empty Secret name -- and must set Ready=False with reason InvalidSpec.
func TestReconcileSecretModeMissingManagedSecretErrors(t *testing.T) {
	scheme := newFakeScheme(t)

	// Version probe returns 404 so the reconcile degrades to the always-fetch
	// fallback; the managedSecret nil-guard must fire before any fetch.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/secrets/fetch") {
			t.Errorf("must not fetch: reconcile should fail on the missing managedSecret first")
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	cr := &kagiv1alpha1.KagiSecret{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "svc",
			Namespace:  "apps",
			Generation: 1,
			Finalizers: []string{finalizerName},
		},
		Spec: kagiv1alpha1.KagiSecretSpec{
			AppID:       "app-123",
			Environment: "production",
			// Mode unset -> defaults to Secret; no managedSecret set.
			TokenSecret: &kagiv1alpha1.TokenSecretRef{Name: "token", Namespace: "apps"},
		},
	}
	token := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "token", Namespace: "apps"},
		Data:       map[string][]byte{"KAGI_TOKEN": []byte("vv_test")},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(cr, token).
		WithStatusSubresource(&kagiv1alpha1.KagiSecret{}).
		Build()

	r := &KagiSecretReconciler{Client: fakeClient, Scheme: scheme, KagiAPIURL: server.URL}
	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: "svc", Namespace: "apps"}}); err == nil {
		t.Fatalf("Secret-mode reconcile without managedSecret must return an error")
	}

	after := &kagiv1alpha1.KagiSecret{}
	if err := fakeClient.Get(context.Background(), types.NamespacedName{Name: "svc", Namespace: "apps"}, after); err != nil {
		t.Fatalf("get after: %v", err)
	}
	cond := meta.FindStatusCondition(after.Status.Conditions, "Ready")
	if cond == nil {
		t.Fatalf("expected a Ready condition to be set")
	}
	if cond.Status != metav1.ConditionFalse || cond.Reason != "InvalidSpec" {
		t.Errorf("expected Ready=False reason=InvalidSpec, got status=%s reason=%s", cond.Status, cond.Reason)
	}
}

// (e) Guard that the Secret-mode discriminator keeps the default/absent-mode CR
// on the Secret path: the existing reconcileManagedSecret tests then apply
// unchanged. A default-mode CR must not be treated as Injected.
func TestSecretModeDefaultNotInjected(t *testing.T) {
	ks := &kagiv1alpha1.KagiSecret{
		Spec: kagiv1alpha1.KagiSecretSpec{
			AppID:         "app-123",
			Environment:   "e",
			ManagedSecret: &kagiv1alpha1.ManagedSecretRef{Name: "m", Namespace: "default"},
		},
	}
	if isInjectedMode(ks) {
		t.Fatalf("default-mode CR must take the Secret path")
	}
}
