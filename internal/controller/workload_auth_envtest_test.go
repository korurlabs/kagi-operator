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
	"net/http/httptest"
	"sync/atomic"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	kagiv1alpha1 "github.com/korurlabs/kagi-operator/api/v1alpha1"
	kagi "github.com/korurlabs/kagi-operator/internal/kagiclient"
)

// These specs store the workload exchange's Ready reasons through the real API
// server (envtest), so the CRDs' condition schema accepts them and the
// finalizer flow runs as in a cluster. The fake-client cases in
// workload_auth_test.go and workload_auth_reconcile_test.go cover every branch.
var _ = Describe("Workload token exchange", func() {
	const namespace = "default"

	var (
		fetches atomic.Int32
		server  *httptest.Server
	)

	BeforeEach(func() {
		fetches.Store(0)
		server = ownershipKagiServer(&fetches)
		DeferCleanup(server.Close)
	})

	// reconcileTwice creates the resource and reconciles it twice: the first
	// pass only adds the finalizer. It returns the error of the second pass.
	reconcileTwice := func(resource client.Object, r reconcile.Reconciler) error {
		Expect(k8sClient.Create(ctx, resource)).To(Succeed())
		DeferCleanup(func() {
			Expect(client.IgnoreNotFound(k8sClient.Delete(ctx, resource))).To(Succeed())
			_, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(resource)})
			Expect(err).NotTo(HaveOccurred())
		})
		req := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(resource)}
		_, err := r.Reconcile(ctx, req)
		Expect(err).NotTo(HaveOccurred())
		_, err = r.Reconcile(ctx, req)
		return err
	}

	secretReady := func(resource *kagiv1alpha1.KagiSecret) *metav1.Condition {
		var stored kagiv1alpha1.KagiSecret
		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(resource), &stored)).To(Succeed())
		return readyCondition(stored.Status.Conditions)
	}

	newKagiSecret := func(name string, spec kagiv1alpha1.KagiSecretSpec) *kagiv1alpha1.KagiSecret {
		spec.Environment = "production"
		spec.ManagedSecret = &kagiv1alpha1.ManagedSecretRef{Name: name + "-managed", Namespace: namespace}
		return &kagiv1alpha1.KagiSecret{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace}, Spec: spec}
	}

	secretReconciler := func(tokens kagi.TokenSource) *KagiSecretReconciler {
		return &KagiSecretReconciler{
			Client: k8sClient, Scheme: k8sClient.Scheme(), KagiAPIURL: server.URL,
			OperatorNamespace: namespace, WorkloadTokens: tokens,
		}
	}

	It("stores WorkloadTokenCannotResolve for a folderPath KagiSecret and fetches nothing", func() {
		tokens := &fakeWorkloadTokens{}
		resource := newKagiSecret("wl-folder-path", kagiv1alpha1.KagiSecretSpec{FolderPath: "/team/app"})

		Expect(reconcileTwice(resource, secretReconciler(tokens))).To(Succeed())

		ready := secretReady(resource)
		Expect(ready).NotTo(BeNil())
		Expect(ready.Status).To(Equal(metav1.ConditionFalse))
		Expect(ready.Reason).To(Equal(reasonWorkloadTokenCannotResolve))
		Expect(ready.Message).To(ContainSubstring("spec.appId"))
		Expect(tokens.calls()).To(BeEmpty())
		Expect(fetches.Load()).To(BeZero())
	})

	It("stores WorkloadAccessDenied naming the pair and returns the denial for back-off", func() {
		const appID = "3f2504e0-4f89-11d3-9a0c-0305e82c3310"
		tokens := &fakeWorkloadTokens{deniedApp: appID}
		resource := newKagiSecret("wl-denied", kagiv1alpha1.KagiSecretSpec{AppID: appID})

		err := reconcileTwice(resource, secretReconciler(tokens))
		Expect(kagi.IsWorkloadAccessDenied(err)).To(BeTrue(), "Reconcile err = %v", err)

		ready := secretReady(resource)
		Expect(ready).NotTo(BeNil())
		Expect(ready.Status).To(Equal(metav1.ConditionFalse))
		Expect(ready.Reason).To(Equal(reasonWorkloadAccessDenied))
		Expect(ready.Message).To(And(ContainSubstring(appID), ContainSubstring("production")))
		Expect(fetches.Load()).To(BeZero())
	})

	It("syncs a KagiSecret with an app id through the pair's token", func() {
		const appID = "3f2504e0-4f89-11d3-9a0c-0305e82c3311"
		tokens := &fakeWorkloadTokens{}
		resource := newKagiSecret("wl-granted", kagiv1alpha1.KagiSecretSpec{AppID: appID})

		Expect(reconcileTwice(resource, secretReconciler(tokens))).To(Succeed())

		ready := secretReady(resource)
		Expect(ready).NotTo(BeNil())
		Expect(ready.Status).To(Equal(metav1.ConditionTrue))
		Expect(fetches.Load()).To(BeEquivalentTo(1))
		Expect(tokens.calls()).To(HaveEach(kagi.TokenScope{AppID: appID, EnvironmentSlug: "production"}))
	})

	It("stores WorkloadTokenCannotResolve for a KagiCertificate without a tokenSecret", func() {
		tokens := &fakeWorkloadTokens{}
		resource := &kagiv1alpha1.KagiCertificate{
			ObjectMeta: metav1.ObjectMeta{Name: "wl-cert", Namespace: namespace},
			Spec: kagiv1alpha1.KagiCertificateSpec{
				CertificateID: "3f2504e0-4f89-11d3-9a0c-0305e82c3312",
				ManagedSecret: kagiv1alpha1.ManagedSecretRef{Name: "wl-cert-tls", Namespace: namespace},
			},
		}
		r := &KagiCertificateReconciler{
			Client: k8sClient, Scheme: k8sClient.Scheme(), KagiAPIURL: server.URL,
			OperatorNamespace: namespace, WorkloadTokens: tokens,
		}

		Expect(reconcileTwice(resource, r)).To(Succeed())

		var stored kagiv1alpha1.KagiCertificate
		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(resource), &stored)).To(Succeed())
		ready := readyCondition(stored.Status.Conditions)
		Expect(ready).NotTo(BeNil())
		Expect(ready.Status).To(Equal(metav1.ConditionFalse))
		Expect(ready.Reason).To(Equal(reasonWorkloadTokenCannotResolve))
		Expect(tokens.calls()).To(BeEmpty())
		Expect(fetches.Load()).To(BeZero())
	})
})
