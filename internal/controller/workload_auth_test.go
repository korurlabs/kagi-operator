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
	"sync"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	kagiv1alpha1 "github.com/korurlabs/kagi-operator/api/v1alpha1"
	kagi "github.com/korurlabs/kagi-operator/internal/kagiclient"
)

// fakeWorkloadTokens stands in for the exchange: it records the pairs asked
// for and answers each with a token, or with a 401 refusal for a denied app.
type fakeWorkloadTokens struct {
	deniedApp string

	mu     sync.Mutex
	scopes []kagi.TokenScope
}

func (f *fakeWorkloadTokens) Token(_ context.Context, scope kagi.TokenScope) (string, error) {
	f.mu.Lock()
	f.scopes = append(f.scopes, scope)
	f.mu.Unlock()
	if scope.AppID == "" || scope.EnvironmentSlug == "" {
		return "", kagi.ErrTokenScopeRequired
	}
	if scope.AppID == f.deniedApp {
		return "", &kagi.ExchangeError{Scope: scope, Err: &kagi.APIError{StatusCode: http.StatusUnauthorized, Code: "KGI_AUT_003"}}
	}
	return "vv_workload_" + scope.AppID, nil
}

func (f *fakeWorkloadTokens) calls() []kagi.TokenScope {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]kagi.TokenScope(nil), f.scopes...)
}

// workloadAPI is a Kagi API that serves the version and fetch routes and
// records the bearer token of each call.
func workloadAPI(t *testing.T) (*httptest.Server, *[]string) {
	t.Helper()
	var mu sync.Mutex
	auths := []string{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		auths = append(auths, r.Header.Get("Authorization"))
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/secrets/version"):
			_ = json.NewEncoder(w).Encode(map[string]any{"version": "v1", "count": 1})
		case strings.HasSuffix(r.URL.Path, "/secrets/fetch"):
			_ = json.NewEncoder(w).Encode(map[string]any{"secrets": map[string]string{"FOO": "bar"}})
		default:
			t.Errorf("unexpected API call %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)
	return server, &auths
}

func workloadKagiSecret(spec kagiv1alpha1.KagiSecretSpec) *kagiv1alpha1.KagiSecret {
	if spec.Environment == "" {
		spec.Environment = "production"
	}
	if spec.ManagedSecret == nil && spec.Mode != modeInjected {
		spec.ManagedSecret = &kagiv1alpha1.ManagedSecretRef{Name: "managed", Namespace: "default", Type: "Opaque"}
	}
	return &kagiv1alpha1.KagiSecret{
		ObjectMeta: metav1.ObjectMeta{Name: "test", Namespace: "default", Generation: 1, Finalizers: []string{finalizerName}},
		Spec:       spec,
	}
}

func reconcileWorkloadSecret(
	t *testing.T, cr *kagiv1alpha1.KagiSecret, tokens kagi.TokenSource, apiURL string, extra ...client.Object,
) (*kagiv1alpha1.KagiSecret, ctrl.Result, error) {
	t.Helper()
	scheme := newFakeScheme(t)
	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(append([]client.Object{cr}, extra...)...).
		WithStatusSubresource(&kagiv1alpha1.KagiSecret{}).
		Build()
	r := &KagiSecretReconciler{
		Client: c, Scheme: scheme, KagiAPIURL: apiURL, WorkloadTokens: tokens,
		DefaultTokenSecretName: "default-token", DefaultTokenSecretNamespace: "default",
	}
	res, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: "test", Namespace: "default"}})
	var got kagiv1alpha1.KagiSecret
	if getErr := c.Get(context.Background(), types.NamespacedName{Name: "test", Namespace: "default"}, &got); getErr != nil {
		t.Fatalf("get KagiSecret: %v", getErr)
	}
	return &got, res, err
}

func readyOf(t *testing.T, conditions []metav1.Condition) *metav1.Condition {
	t.Helper()
	ready := meta.FindStatusCondition(conditions, "Ready")
	if ready == nil {
		t.Fatal("no Ready condition was set")
	}
	return ready
}

// Under the exchange a KagiSecret with an app id reads its pair with the
// pair's token, and the default token Secret is never consulted.
func TestWorkloadExchangeFetchesWithThePairToken(t *testing.T) {
	server, auths := workloadAPI(t)
	tokens := &fakeWorkloadTokens{}
	cr := workloadKagiSecret(kagiv1alpha1.KagiSecretSpec{AppID: "app-1"})

	got, _, err := reconcileWorkloadSecret(t, cr, tokens, server.URL)
	if err != nil {
		t.Fatalf("Reconcile returned error: %v", err)
	}
	if ready := readyOf(t, got.Status.Conditions); ready.Status != metav1.ConditionTrue {
		t.Errorf("Ready = %s/%s (%s), want True", ready.Status, ready.Reason, ready.Message)
	}
	if len(tokens.calls()) == 0 || len(*auths) == 0 {
		t.Fatalf("exchange calls %v, API calls %v; want both", tokens.calls(), *auths)
	}
	for _, scope := range tokens.calls() {
		if scope != (kagi.TokenScope{AppID: "app-1", EnvironmentSlug: "production"}) {
			t.Errorf("token asked for %+v, want app-1/production", scope)
		}
	}
	for _, auth := range *auths {
		if auth != "Bearer vv_workload_app-1" {
			t.Errorf("API call carried %q, want the pair's workload token", auth)
		}
	}
}

// spec.folderPath cannot be resolved under the exchange: the object is told
// how to fix it and is not retried.
func TestWorkloadExchangeRefusesFolderPath(t *testing.T) {
	server, auths := workloadAPI(t)
	tokens := &fakeWorkloadTokens{}
	cr := workloadKagiSecret(kagiv1alpha1.KagiSecretSpec{FolderPath: "/team/app"})

	got, res, err := reconcileWorkloadSecret(t, cr, tokens, server.URL)
	if err != nil {
		t.Errorf("Reconcile returned error %v, want none (a retry cannot fix the spec)", err)
	}
	if res.RequeueAfter != 0 {
		t.Errorf("RequeueAfter = %v, want no requeue", res.RequeueAfter)
	}
	ready := readyOf(t, got.Status.Conditions)
	if ready.Status != metav1.ConditionFalse || ready.Reason != reasonWorkloadTokenCannotResolve {
		t.Errorf("Ready = %s/%s, want False/%s", ready.Status, ready.Reason, reasonWorkloadTokenCannotResolve)
	}
	for _, want := range []string{"spec.appId", "spec.tokenSecret"} {
		if !strings.Contains(ready.Message, want) {
			t.Errorf("Ready.Message = %q, want it to name %s", ready.Message, want)
		}
	}
	if len(tokens.calls()) != 0 || len(*auths) != 0 {
		t.Errorf("exchange calls %v, API calls %v; want none", tokens.calls(), *auths)
	}
}

// A refused exchange is WorkloadAccessDenied naming the pair, and the reconcile
// fails so the rate limiter backs it off.
func TestWorkloadExchangeDenialBacksOff(t *testing.T) {
	for _, mode := range []string{"", modeInjected} {
		t.Run("mode="+mode, func(t *testing.T) {
			server, _ := workloadAPI(t)
			tokens := &fakeWorkloadTokens{deniedApp: "app-1"}
			cr := workloadKagiSecret(kagiv1alpha1.KagiSecretSpec{AppID: "app-1", Mode: mode})

			got, _, err := reconcileWorkloadSecret(t, cr, tokens, server.URL)
			if !kagi.IsWorkloadAccessDenied(err) {
				t.Fatalf("Reconcile err = %v, want the access denial returned for back-off", err)
			}
			ready := readyOf(t, got.Status.Conditions)
			if ready.Status != metav1.ConditionFalse || ready.Reason != reasonWorkloadAccessDenied {
				t.Errorf("Ready = %s/%s, want False/%s", ready.Status, ready.Reason, reasonWorkloadAccessDenied)
			}
			for _, want := range []string{"app-1", "production", "Integrations"} {
				if !strings.Contains(ready.Message, want) {
					t.Errorf("Ready.Message = %q, want it to contain %q", ready.Message, want)
				}
			}
			if got.Status.LastErrorMessage != ready.Message {
				t.Errorf("LastErrorMessage = %q, want the Ready message", got.Status.LastErrorMessage)
			}
		})
	}
}

// spec.tokenSecret still wins per object under the exchange.
func TestWorkloadExchangeTokenSecretWins(t *testing.T) {
	server, auths := workloadAPI(t)
	tokens := &fakeWorkloadTokens{}
	cr := workloadKagiSecret(kagiv1alpha1.KagiSecretSpec{
		AppID:       "app-1",
		TokenSecret: &kagiv1alpha1.TokenSecretRef{Name: "own-token", Namespace: "default"},
	})
	ownToken := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "own-token", Namespace: "default"},
		Data:       map[string][]byte{"KAGI_TOKEN": []byte("vv_own")},
	}

	if _, _, err := reconcileWorkloadSecret(t, cr, tokens, server.URL, ownToken); err != nil {
		t.Fatalf("Reconcile returned error: %v", err)
	}
	if len(tokens.calls()) != 0 {
		t.Errorf("exchange asked for %v, want no exchange for an object with its own tokenSecret", tokens.calls())
	}
	for _, auth := range *auths {
		if auth != "Bearer vv_own" {
			t.Errorf("API call carried %q, want the object's own PAT", auth)
		}
	}
}

// A KagiCertificate cannot use the exchange; without its own tokenSecret it is
// told so and not retried.
func TestWorkloadExchangeRefusesKagiCertificate(t *testing.T) {
	scheme := newFakeScheme(t)
	cert := &kagiv1alpha1.KagiCertificate{
		ObjectMeta: metav1.ObjectMeta{Name: "cert", Namespace: "default", Generation: 1, Finalizers: []string{certFinalizerName}},
		Spec: kagiv1alpha1.KagiCertificateSpec{
			CertificateID: "cert-1",
			ManagedSecret: kagiv1alpha1.ManagedSecretRef{Name: "tls", Namespace: "default"},
		},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(cert).
		WithStatusSubresource(&kagiv1alpha1.KagiCertificate{}).Build()
	tokens := &fakeWorkloadTokens{}
	r := &KagiCertificateReconciler{Client: c, Scheme: scheme, KagiAPIURL: "http://unused", WorkloadTokens: tokens}

	res, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: "cert", Namespace: "default"}})
	if err != nil || res.RequeueAfter != 0 {
		t.Errorf("Reconcile = %v, %v; want no error and no requeue", res, err)
	}
	var got kagiv1alpha1.KagiCertificate
	if err := c.Get(context.Background(), types.NamespacedName{Name: "cert", Namespace: "default"}, &got); err != nil {
		t.Fatalf("get KagiCertificate: %v", err)
	}
	ready := readyOf(t, got.Status.Conditions)
	if ready.Status != metav1.ConditionFalse || ready.Reason != reasonWorkloadTokenCannotResolve {
		t.Errorf("Ready = %s/%s, want False/%s", ready.Status, ready.Reason, reasonWorkloadTokenCannotResolve)
	}
	if !strings.Contains(ready.Message, "spec.tokenSecret") {
		t.Errorf("Ready.Message = %q, want it to name spec.tokenSecret", ready.Message)
	}
	if len(tokens.calls()) != 0 {
		t.Errorf("exchange asked for %v, want none", tokens.calls())
	}
}
