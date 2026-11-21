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

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	kagiv1alpha1 "github.com/korurlabs/kagi-operator/api/v1alpha1"
)

// These specs run the ownership rules against the real API server (envtest):
// the resource lives in the operator's namespace and writes its Secret into
// another, the shape of every production KagiSecret, and deletion goes through
// the real finalizer flow. They complement the fake-client cases in
// managed_secret_ownership_test.go and managed_secret_policy_test.go, which
// cover every ownership state and reference rule.

const (
	ownershipAppNamespace   = "ownership-apps"
	ownershipOtherNamespace = "ownership-other"
	ownershipTokenSecret    = "ownership-token"
	ownershipResourceSuffix = "-res"

	// ownershipOperatorNamespace stands in for the operator's namespace.
	// envtest runs no operator Pod, so any namespace serves.
	ownershipOperatorNamespace = "default"
)

// ownershipKind is what the specs need to know about one resource kind.
type ownershipKind struct {
	kind       string
	prefix     string
	secretType corev1.SecretType
	victimData map[string][]byte
	syncedData map[string][]byte
	// identity holds the identity labels an earlier release wrote on the
	// Secret of every resource that newResource returns.
	identity map[string]string
	// newResource returns a resource in namespace whose managed Secret is
	// secretName in ownershipAppNamespace and whose token Secret is
	// ownershipTokenSecret in namespace.
	newResource   func(namespace, name, secretName string) client.Object
	setSecretType func(resource client.Object, secretType string)
	newReconciler func(kagiAPIURL, operatorNamespace string) reconcile.Reconciler
	conditions    func(key types.NamespacedName) []metav1.Condition
}

func ownershipKinds() []ownershipKind {
	token := func(namespace string) *kagiv1alpha1.TokenSecretRef {
		return &kagiv1alpha1.TokenSecretRef{Name: ownershipTokenSecret, Namespace: namespace}
	}
	return []ownershipKind{
		{
			kind:       kindKagiSecret,
			prefix:     "ks",
			secretType: corev1.SecretTypeOpaque,
			victimData: map[string][]byte{"original": []byte("untouched")},
			syncedData: map[string][]byte{"FOO": []byte("bar")},
			identity:   map[string]string{labelAppID: "3f2504e0-4f89-11d3-9a0c-0305e82c3302", labelEnv: "production"},
			newResource: func(namespace, name, secretName string) client.Object {
				return &kagiv1alpha1.KagiSecret{
					ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
					Spec: kagiv1alpha1.KagiSecretSpec{
						AppID:         "3f2504e0-4f89-11d3-9a0c-0305e82c3302",
						Environment:   "production",
						TokenSecret:   token(namespace),
						ManagedSecret: &kagiv1alpha1.ManagedSecretRef{Name: secretName, Namespace: ownershipAppNamespace},
					},
				}
			},
			setSecretType: func(resource client.Object, secretType string) {
				resource.(*kagiv1alpha1.KagiSecret).Spec.ManagedSecret.Type = secretType
			},
			newReconciler: func(kagiAPIURL, operatorNamespace string) reconcile.Reconciler {
				return &KagiSecretReconciler{Client: k8sClient, Scheme: k8sClient.Scheme(), KagiAPIURL: kagiAPIURL, OperatorNamespace: operatorNamespace}
			},
			conditions: func(key types.NamespacedName) []metav1.Condition {
				var stored kagiv1alpha1.KagiSecret
				Expect(k8sClient.Get(ctx, key, &stored)).To(Succeed())
				return stored.Status.Conditions
			},
		},
		{
			kind:       kindKagiCertificate,
			prefix:     "kc",
			secretType: corev1.SecretTypeTLS,
			victimData: map[string][]byte{"tls.crt": []byte("original-crt"), "tls.key": []byte("original-key")},
			syncedData: map[string][]byte{"tls.crt": []byte("crt"), "tls.key": []byte("key")},
			identity:   map[string]string{labelCertificateID: "3f2504e0-4f89-11d3-9a0c-0305e82c3303"},
			newResource: func(namespace, name, secretName string) client.Object {
				return &kagiv1alpha1.KagiCertificate{
					ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
					Spec: kagiv1alpha1.KagiCertificateSpec{
						CertificateID: "3f2504e0-4f89-11d3-9a0c-0305e82c3303",
						TokenSecret:   token(namespace),
						ManagedSecret: kagiv1alpha1.ManagedSecretRef{Name: secretName, Namespace: ownershipAppNamespace},
					},
				}
			},
			setSecretType: func(resource client.Object, secretType string) {
				resource.(*kagiv1alpha1.KagiCertificate).Spec.ManagedSecret.Type = secretType
			},
			newReconciler: func(kagiAPIURL, operatorNamespace string) reconcile.Reconciler {
				return &KagiCertificateReconciler{Client: k8sClient, Scheme: k8sClient.Scheme(), KagiAPIURL: kagiAPIURL, OperatorNamespace: operatorNamespace}
			},
			conditions: func(key types.NamespacedName) []metav1.Condition {
				var stored kagiv1alpha1.KagiCertificate
				Expect(k8sClient.Get(ctx, key, &stored)).To(Succeed())
				return stored.Status.Conditions
			},
		},
	}
}

var _ = Describe("Managed Secret ownership", func() {
	var (
		fetches atomic.Int32
		server  *httptest.Server
	)

	BeforeEach(func() {
		fetches.Store(0)
		server = ownershipKagiServer(&fetches)
		DeferCleanup(server.Close)

		for _, name := range []string{ownershipAppNamespace, ownershipOtherNamespace} {
			ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name}}
			if err := k8sClient.Create(ctx, ns); err != nil {
				Expect(apierrors.IsAlreadyExists(err)).To(BeTrue(), "create namespace %s: %v", name, err)
			}
		}
		for _, namespace := range []string{ownershipOperatorNamespace, ownershipAppNamespace, ownershipOtherNamespace} {
			token := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: ownershipTokenSecret, Namespace: namespace},
				Data:       map[string][]byte{"KAGI_TOKEN": []byte("vv_test")},
			}
			if err := k8sClient.Create(ctx, token); err != nil {
				Expect(apierrors.IsAlreadyExists(err)).To(BeTrue(), "create token Secret in %s: %v", namespace, err)
			}
		}
	})

	for _, k := range ownershipKinds() {
		Context(k.kind, func() {
			// createVictim creates the Secret a resource will point at.
			createVictim := func(name string, labels, annotations map[string]string) *corev1.Secret {
				secret := &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ownershipAppNamespace, Labels: labels, Annotations: annotations},
					Type:       k.secretType,
					Data:       k.victimData,
				}
				Expect(k8sClient.Create(ctx, secret)).To(Succeed())
				return secret
			}

			getSecret := func(name string) (*corev1.Secret, error) {
				var secret corev1.Secret
				err := k8sClient.Get(ctx, types.NamespacedName{Namespace: ownershipAppNamespace, Name: name}, &secret)
				return &secret, err
			}

			expectUntouched := func(before *corev1.Secret) {
				after, err := getSecret(before.Name)
				Expect(err).NotTo(HaveOccurred())
				Expect(after.UID).To(Equal(before.UID))
				Expect(after.ResourceVersion).To(Equal(before.ResourceVersion))
				Expect(after.Data).To(Equal(before.Data))
			}

			expectDeletedWithOwner := func(name string) {
				_, err := getSecret(name)
				Expect(apierrors.IsNotFound(err)).To(BeTrue(), "Secret %s/%s still exists: %v", ownershipAppNamespace, name, err)
			}

			// createAndReconcile creates the resource and reconciles it twice:
			// the first pass only adds the finalizer. It returns the error of
			// the second pass.
			createAndReconcile := func(resource client.Object, r reconcile.Reconciler) error {
				Expect(k8sClient.Create(ctx, resource)).To(Succeed())
				req := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(resource)}
				_, err := r.Reconcile(ctx, req)
				Expect(err).NotTo(HaveOccurred())
				_, err = r.Reconcile(ctx, req)
				return err
			}

			// deleteAndReconcile deletes the resource and reconciles the
			// deletion, which must always release the finalizer.
			deleteAndReconcile := func(resource client.Object, r reconcile.Reconciler) {
				Expect(k8sClient.Delete(ctx, resource)).To(Succeed())
				_, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(resource)})
				Expect(err).NotTo(HaveOccurred())
				err = k8sClient.Get(ctx, client.ObjectKeyFromObject(resource), resource)
				Expect(apierrors.IsNotFound(err)).To(BeTrue(), "resource still exists after deletion: %v", err)
			}

			expectRefused := func(key types.NamespacedName, reason, secretName string) {
				ready := readyCondition(k.conditions(key))
				Expect(ready).NotTo(BeNil())
				Expect(ready.Status).To(Equal(metav1.ConditionFalse))
				Expect(ready.Reason).To(Equal(reason))
				Expect(ready.Message).To(ContainSubstring(ownershipAppNamespace + "/" + secretName))
			}

			It("creates a missing Secret with the owner marker and deletes it with its owner", func() {
				name := k.prefix + "-missing"
				resource := k.newResource(ownershipOperatorNamespace, name+ownershipResourceSuffix, name)
				r := k.newReconciler(server.URL, ownershipOperatorNamespace)

				Expect(createAndReconcile(resource, r)).To(Succeed())
				created, err := getSecret(name)
				Expect(err).NotTo(HaveOccurred())
				Expect(created.Labels).To(HaveKeyWithValue(labelManagedBy, managedByValue))
				Expect(created.Annotations).To(HaveKeyWithValue(annotationOwner, managedSecretOwner(k.kind, resource)))
				Expect(created.Data).To(Equal(k.syncedData))

				deleteAndReconcile(resource, r)
				expectDeletedWithOwner(name)
			})

			It("leaves a Secret the operator did not create untouched on create and on delete", func() {
				name := k.prefix + "-foreign"
				victim := createVictim(name, map[string]string{"app": "payments"}, nil)
				resource := k.newResource(ownershipOperatorNamespace, name+ownershipResourceSuffix, name)
				r := k.newReconciler(server.URL, ownershipOperatorNamespace)

				Expect(createAndReconcile(resource, r)).To(HaveOccurred())
				expectRefused(client.ObjectKeyFromObject(resource), reasonSecretNotManaged, name)
				expectUntouched(victim)
				Expect(fetches.Load()).To(BeZero())

				deleteAndReconcile(resource, r)
				expectUntouched(victim)
			})

			It("leaves a Secret owned by another resource untouched on create and on delete", func() {
				name := k.prefix + "-other"
				victim := createVictim(name,
					map[string]string{labelManagedBy: managedByValue},
					map[string]string{annotationOwner: otherOwner})
				resource := k.newResource(ownershipOperatorNamespace, name+ownershipResourceSuffix, name)
				r := k.newReconciler(server.URL, ownershipOperatorNamespace)

				Expect(createAndReconcile(resource, r)).To(HaveOccurred())
				key := client.ObjectKeyFromObject(resource)
				expectRefused(key, reasonSecretOwnedByOther, name)
				Expect(readyCondition(k.conditions(key)).Message).To(ContainSubstring(otherOwner))
				expectUntouched(victim)
				Expect(fetches.Load()).To(BeZero())

				deleteAndReconcile(resource, r)
				expectUntouched(victim)
			})

			It("leaves a labelled Secret without a data hash, like the webhook certificate Secret, untouched on create and on delete", func() {
				name := k.prefix + "-label-only"
				victim := createVictim(name, map[string]string{labelManagedBy: managedByValue}, nil)
				resource := k.newResource(ownershipOperatorNamespace, name+ownershipResourceSuffix, name)
				r := k.newReconciler(server.URL, ownershipOperatorNamespace)

				Expect(createAndReconcile(resource, r)).To(HaveOccurred())
				expectRefused(client.ObjectKeyFromObject(resource), reasonSecretNotManaged, name)
				expectUntouched(victim)
				Expect(fetches.Load()).To(BeZero())

				deleteAndReconcile(resource, r)
				expectUntouched(victim)
			})

			// legacyLabels are the labels an earlier release wrote on the
			// Secret of a resource with identity.
			legacyLabels := func(identity map[string]string) map[string]string {
				return mergeLabels(map[string]string{labelManagedBy: managedByValue}, identity)
			}

			It("adopts a labelled Secret written by an earlier release and deletes it with its owner", func() {
				name := k.prefix + "-legacy"
				createVictim(name, legacyLabels(k.identity), map[string]string{annotationHash: legacyDataHash})
				resource := k.newResource(ownershipOperatorNamespace, name+ownershipResourceSuffix, name)
				r := k.newReconciler(server.URL, ownershipOperatorNamespace)

				Expect(createAndReconcile(resource, r)).To(Succeed())
				adopted, err := getSecret(name)
				Expect(err).NotTo(HaveOccurred())
				Expect(adopted.Annotations).To(HaveKeyWithValue(annotationOwner, managedSecretOwner(k.kind, resource)))
				Expect(adopted.Data).To(Equal(k.syncedData))

				deleteAndReconcile(resource, r)
				expectDeletedWithOwner(name)
			})

			It("adopts a Secret an earlier release wrote in the resource's own namespace only for a KagiCertificate", func() {
				name := k.prefix + "-own-namespace"
				victim := createVictim(name, legacyLabels(k.identity), map[string]string{annotationHash: legacyDataHash})
				resource := k.newResource(ownershipAppNamespace, name+ownershipResourceSuffix, name)
				r := k.newReconciler(server.URL, productionOperatorNamespace)

				if k.kind == kindKagiSecret {
					// The Secret's real owner lives in the operator's namespace,
					// so a KagiSecret next to the Secret may not race it.
					Expect(createAndReconcile(resource, r)).To(HaveOccurred())
					expectRefused(client.ObjectKeyFromObject(resource), reasonSecretNotManaged, name)
					expectUntouched(victim)
					Expect(fetches.Load()).To(BeZero())

					deleteAndReconcile(resource, r)
					expectUntouched(victim)
					return
				}
				Expect(createAndReconcile(resource, r)).To(Succeed())
				adopted, err := getSecret(name)
				Expect(err).NotTo(HaveOccurred())
				Expect(adopted.Annotations).To(HaveKeyWithValue(annotationOwner, managedSecretOwner(k.kind, resource)))
				Expect(adopted.Data).To(Equal(k.syncedData))

				deleteAndReconcile(resource, r)
				expectDeletedWithOwner(name)
			})

			It("refuses a Secret an earlier release wrote for another Kagi binding", func() {
				name := k.prefix + "-other-identity"
				victim := createVictim(name, legacyLabels(otherIdentity(k.identity)), map[string]string{annotationHash: legacyDataHash})
				resource := k.newResource(ownershipOperatorNamespace, name+ownershipResourceSuffix, name)
				r := k.newReconciler(server.URL, ownershipOperatorNamespace)

				Expect(createAndReconcile(resource, r)).To(HaveOccurred())
				expectRefused(client.ObjectKeyFromObject(resource), reasonSecretNotManaged, name)
				expectUntouched(victim)
				Expect(fetches.Load()).To(BeZero())

				deleteAndReconcile(resource, r)
				expectUntouched(victim)
			})

			It("denies a resource in another namespace that names the Secret of a resource in the operator's namespace", func() {
				name := k.prefix + "-hijack"
				victim := createVictim(name, legacyLabels(k.identity), map[string]string{annotationHash: legacyDataHash})
				resource := k.newResource(ownershipOtherNamespace, name+ownershipResourceSuffix, name)
				r := k.newReconciler(server.URL, ownershipOperatorNamespace)

				Expect(createAndReconcile(resource, r)).To(HaveOccurred())
				ready := readyCondition(k.conditions(client.ObjectKeyFromObject(resource)))
				Expect(ready).NotTo(BeNil())
				Expect(ready.Status).To(Equal(metav1.ConditionFalse))
				Expect(ready.Reason).To(Equal(reasonCrossNamespaceReferenceDenied))
				Expect(ready.Message).To(ContainSubstring("spec.managedSecret.namespace"))
				expectUntouched(victim)
				Expect(fetches.Load()).To(BeZero())

				deleteAndReconcile(resource, r)
				expectUntouched(victim)
			})

			It("rejects a service-account-token Secret type at admission", func() {
				resource := k.newResource(ownershipOperatorNamespace, k.prefix+"-sa-token"+ownershipResourceSuffix, k.prefix+"-sa-token")
				k.setSecretType(resource, string(corev1.SecretTypeServiceAccountToken))

				err := k8sClient.Create(ctx, resource)
				Expect(apierrors.IsInvalid(err)).To(BeTrue(), "create returned %v, want an Invalid error", err)
				Expect(err.Error()).To(ContainSubstring("spec.managedSecret.type"))
			})
		})
	}
})
