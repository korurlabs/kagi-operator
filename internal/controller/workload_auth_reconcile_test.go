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
	"errors"
	"maps"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	kagiv1alpha1 "github.com/korurlabs/kagi-operator/api/v1alpha1"
	kagi "github.com/korurlabs/kagi-operator/internal/kagiclient"
)

// failingWorkloadTokens is an exchange that fails every pair with err.
type failingWorkloadTokens struct {
	err   error
	calls atomic.Int32
}

func (f *failingWorkloadTokens) Token(_ context.Context, scope kagi.TokenScope) (string, error) {
	f.calls.Add(1)
	return "", &kagi.ExchangeError{Scope: scope, Err: f.err}
}

// folderAPI serves the folder listing ResolveApp reads, the version probe and
// the fetch, and records the bearer token of each call by path.
func folderAPI(t *testing.T, appID string) (*httptest.Server, func() map[string]string) {
	t.Helper()
	var mu sync.Mutex
	auths := map[string]string{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		auths[r.URL.Path] = r.Header.Get("Authorization")
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/kagi/folders/secrets/children/team":
			_ = json.NewEncoder(w).Encode(kagi.FolderChildren{
				Path: "/team",
				Apps: []kagi.App{{ID: appID, Name: "App", Slug: "app"}},
			})
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
	return server, func() map[string]string {
		mu.Lock()
		defer mu.Unlock()
		return maps.Clone(auths)
	}
}

func patSecret(name, token string) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default"},
		Data:       map[string][]byte{"KAGI_TOKEN": []byte(token)},
	}
}

// An exchange that fails for any reason other than a refusal (an unreadable
// projected token, the API unreachable) is TokenResolutionFailed, and the
// reconcile fails so it backs off.
func TestWorkloadExchangeFailureIsTokenResolutionFailed(t *testing.T) {
	for _, mode := range []string{"", modeInjected} {
		t.Run("mode="+mode, func(t *testing.T) {
			server, _ := workloadAPI(t)
			tokens := &failingWorkloadTokens{err: errors.New("failed to read service account token at /var/run/secrets/kagi/token")}
			cr := workloadKagiSecret(kagiv1alpha1.KagiSecretSpec{AppID: "app-1", Mode: mode})

			got, _, err := reconcileWorkloadSecret(t, cr, tokens, server.URL)
			if !kagi.IsExchangeError(err) || kagi.IsWorkloadAccessDenied(err) {
				t.Fatalf("Reconcile err = %v, want the exchange failure returned for back-off", err)
			}
			ready := readyOf(t, got.Status.Conditions)
			if ready.Status != metav1.ConditionFalse || ready.Reason != reasonTokenResolutionFailed {
				t.Errorf("Ready = %s/%s, want False/%s", ready.Status, ready.Reason, reasonTokenResolutionFailed)
			}
			for _, want := range []string{"app-1", "production", "service account token"} {
				if !strings.Contains(ready.Message, want) {
					t.Errorf("Ready.Message = %q, want it to contain %q", ready.Message, want)
				}
			}
		})
	}
}

// A 403 from the exchange (a plan or billing gate) is not a missing grant:
// it is reported as TokenResolutionFailed, not WorkloadAccessDenied.
func TestWorkloadExchangeForbiddenIsNotAccessDenied(t *testing.T) {
	server, _ := workloadAPI(t)
	tokens := &failingWorkloadTokens{err: &kagi.APIError{StatusCode: http.StatusForbidden, Code: "KGI_SEC_038"}}
	cr := workloadKagiSecret(kagiv1alpha1.KagiSecretSpec{AppID: "app-1"})

	got, _, err := reconcileWorkloadSecret(t, cr, tokens, server.URL)
	if err == nil {
		t.Fatal("Reconcile returned no error, want the failure returned for back-off")
	}
	if ready := readyOf(t, got.Status.Conditions); ready.Reason != reasonTokenResolutionFailed {
		t.Errorf("Ready.Reason = %s, want %s", ready.Reason, reasonTokenResolutionFailed)
	}
}

// A grant the admin adds after a denial is picked up by the next reconcile:
// the object turns Ready and its error message is cleared.
func TestWorkloadExchangeRecoversOnceThePairIsGranted(t *testing.T) {
	server, _ := workloadAPI(t)
	tokens := &fakeWorkloadTokens{deniedApp: "app-1"}
	cr := workloadKagiSecret(kagiv1alpha1.KagiSecretSpec{AppID: "app-1"})

	scheme := newFakeScheme(t)
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(cr).
		WithStatusSubresource(&kagiv1alpha1.KagiSecret{}).Build()
	r := &KagiSecretReconciler{Client: c, Scheme: scheme, KagiAPIURL: server.URL, WorkloadTokens: tokens}
	req := ctrl.Request{NamespacedName: types.NamespacedName{Name: "test", Namespace: "default"}}

	if _, err := r.Reconcile(context.Background(), req); !kagi.IsWorkloadAccessDenied(err) {
		t.Fatalf("first Reconcile err = %v, want the access denial", err)
	}
	tokens.deniedApp = ""
	if _, err := r.Reconcile(context.Background(), req); err != nil {
		t.Fatalf("Reconcile after the grant returned error: %v", err)
	}

	var got kagiv1alpha1.KagiSecret
	if err := c.Get(context.Background(), req.NamespacedName, &got); err != nil {
		t.Fatalf("get KagiSecret: %v", err)
	}
	if ready := readyOf(t, got.Status.Conditions); ready.Status != metav1.ConditionTrue {
		t.Errorf("Ready = %s/%s (%s), want True", ready.Status, ready.Reason, ready.Message)
	}
	if got.Status.LastErrorMessage != "" {
		t.Errorf("LastErrorMessage = %q, want it cleared", got.Status.LastErrorMessage)
	}
}

// spec.folderPath keeps working where a PAT is available: under the exchange
// with the object's own tokenSecret, and under token-secret with the default
// token Secret. Only the exchange alone refuses it.
func TestFolderPathResolvesWithAPAT(t *testing.T) {
	cases := []struct {
		name        string
		tokens      kagi.TokenSource
		tokenSecret *kagiv1alpha1.TokenSecretRef
		wantAuth    string
	}{
		{
			name:        "exchange with the object's tokenSecret",
			tokens:      &fakeWorkloadTokens{},
			tokenSecret: &kagiv1alpha1.TokenSecretRef{Name: "own-token", Namespace: "default"},
			wantAuth:    "Bearer vv_own",
		},
		{
			name:     "token-secret with the default token Secret",
			tokens:   nil,
			wantAuth: "Bearer vv_default",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server, auths := folderAPI(t, "app-resolved")
			cr := workloadKagiSecret(kagiv1alpha1.KagiSecretSpec{FolderPath: "/team/app", TokenSecret: tc.tokenSecret})

			got, _, err := reconcileWorkloadSecret(t, cr, tc.tokens, server.URL,
				patSecret("own-token", "vv_own"), patSecret("default-token", "vv_default"))
			if err != nil {
				t.Fatalf("Reconcile returned error: %v", err)
			}
			if ready := readyOf(t, got.Status.Conditions); ready.Status != metav1.ConditionTrue {
				t.Errorf("Ready = %s/%s (%s), want True", ready.Status, ready.Reason, ready.Message)
			}
			if exchange, ok := tc.tokens.(*fakeWorkloadTokens); ok && len(exchange.calls()) != 0 {
				t.Errorf("exchange asked for %v, want none", exchange.calls())
			}
			calls := auths()
			if calls["/kagi/folders/secrets/children/team"] != tc.wantAuth {
				t.Errorf("folder lookup carried %q, want %q", calls["/kagi/folders/secrets/children/team"], tc.wantAuth)
			}
			if calls["/kagi/apps/app-resolved/environments/production/secrets/fetch"] != tc.wantAuth {
				t.Errorf("fetch of the resolved app carried %q, want %q (calls %v)",
					calls["/kagi/apps/app-resolved/environments/production/secrets/fetch"], tc.wantAuth, calls)
			}
		})
	}
}

// A KagiCertificate with its own tokenSecret is served under the exchange
// with that PAT, and the exchange is never asked.
func TestWorkloadExchangeKagiCertificateWithTokenSecret(t *testing.T) {
	var fetches atomic.Int32
	var auth atomic.Value
	certAPI := ownershipKagiServer(&fetches)
	defer certAPI.Close()
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth.Store(r.Header.Get("Authorization"))
		certAPI.Config.Handler.ServeHTTP(w, r)
	}))
	defer api.Close()

	scheme := newFakeScheme(t)
	cert := &kagiv1alpha1.KagiCertificate{
		ObjectMeta: metav1.ObjectMeta{Name: "cert", Namespace: "default", Generation: 1, Finalizers: []string{certFinalizerName}},
		Spec: kagiv1alpha1.KagiCertificateSpec{
			CertificateID: "cert-1",
			TokenSecret:   &kagiv1alpha1.TokenSecretRef{Name: "own-token", Namespace: "default"},
			ManagedSecret: kagiv1alpha1.ManagedSecretRef{Name: "tls", Namespace: "default"},
		},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(cert, patSecret("own-token", "vv_own")).
		WithStatusSubresource(&kagiv1alpha1.KagiCertificate{}).Build()
	tokens := &fakeWorkloadTokens{}
	r := &KagiCertificateReconciler{Client: c, Scheme: scheme, KagiAPIURL: api.URL, WorkloadTokens: tokens}

	req := ctrl.Request{NamespacedName: types.NamespacedName{Name: "cert", Namespace: "default"}}
	if _, err := r.Reconcile(context.Background(), req); err != nil {
		t.Fatalf("Reconcile returned error: %v", err)
	}
	var got kagiv1alpha1.KagiCertificate
	if err := c.Get(context.Background(), req.NamespacedName, &got); err != nil {
		t.Fatalf("get KagiCertificate: %v", err)
	}
	if ready := readyOf(t, got.Status.Conditions); ready.Status != metav1.ConditionTrue {
		t.Errorf("Ready = %s/%s (%s), want True", ready.Status, ready.Reason, ready.Message)
	}
	if fetches.Load() != 1 || auth.Load() != "Bearer vv_own" {
		t.Errorf("certificate fetches %d with %v, want one with the object's PAT", fetches.Load(), auth.Load())
	}
	if len(tokens.calls()) != 0 {
		t.Errorf("exchange asked for %v, want none", tokens.calls())
	}
}

// Under token-secret a missing default token Secret is TokenResolutionFailed
// and backs off, as before the exchange existed.
func TestTokenSecretModeMissingDefaultSecretIsTokenResolutionFailed(t *testing.T) {
	server, auths := workloadAPI(t)
	cr := workloadKagiSecret(kagiv1alpha1.KagiSecretSpec{AppID: "app-1"})

	got, _, err := reconcileWorkloadSecret(t, cr, nil, server.URL)
	if err == nil {
		t.Fatal("Reconcile returned no error, want the failure returned for back-off")
	}
	ready := readyOf(t, got.Status.Conditions)
	if ready.Status != metav1.ConditionFalse || ready.Reason != reasonTokenResolutionFailed {
		t.Errorf("Ready = %s/%s, want False/%s", ready.Status, ready.Reason, reasonTokenResolutionFailed)
	}
	if len(*auths) != 0 {
		t.Errorf("API calls %v, want none without a credential", *auths)
	}
}
