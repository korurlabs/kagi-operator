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
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	kagiv1alpha1 "github.com/korurlabs/kagi-operator/api/v1alpha1"
)

// spec.organization is sent verbatim as the X-Organization-ID cross-check. A
// value that is not a UUID can never match a Kagi organization id, and the two
// ways it fails both hide the cause: under tenancy enforcement STRICT the API
// answers 403 on every reconcile for as long as the object exists, and under
// OFF/SHADOW the mismatch is logged server-side while the request proceeds on
// the token's own organization -- so the cross-check the author asked for
// silently never happens. The CRD pattern turns both into one rejection at
// kubectl-apply time.
//
// These specs run against the real API server (envtest) with the generated CRDs
// from config/crd/bases, so they prove the schema as shipped, not the marker.
var _ = Describe("spec.organization admission", func() {
	const validOrganization = "3f2504e0-4f89-11d3-9a0c-0305e82c3301"

	newSecret := func(name, organization string) *kagiv1alpha1.KagiSecret {
		return &kagiv1alpha1.KagiSecret{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default"},
			Spec: kagiv1alpha1.KagiSecretSpec{
				AppID:        "3f2504e0-4f89-11d3-9a0c-0305e82c3302",
				Environment:  "production",
				Organization: organization,
				ManagedSecret: &kagiv1alpha1.ManagedSecretRef{
					Name:      "managed",
					Namespace: "default",
				},
			},
		}
	}

	newCertificate := func(name, organization string) *kagiv1alpha1.KagiCertificate {
		return &kagiv1alpha1.KagiCertificate{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default"},
			Spec: kagiv1alpha1.KagiCertificateSpec{
				CertificateID: "3f2504e0-4f89-11d3-9a0c-0305e82c3303",
				Organization:  organization,
				ManagedSecret: kagiv1alpha1.ManagedSecretRef{
					Name:      "managed-tls",
					Namespace: "default",
				},
			},
		}
	}

	It("rejects a KagiSecret whose organization is not a UUID", func() {
		err := k8sClient.Create(ctx, newSecret("org-admission-bad", "acme"))
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("spec.organization"))
	})

	It("rejects a KagiCertificate whose organization is not a UUID", func() {
		err := k8sClient.Create(ctx, newCertificate("org-admission-bad-cert", "acme-org"))
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("spec.organization"))
	})

	It("accepts a canonical UUID", func() {
		resource := newSecret("org-admission-good", validOrganization)
		Expect(k8sClient.Create(ctx, resource)).To(Succeed())
		DeferCleanup(func() {
			Expect(k8sClient.Delete(ctx, resource)).To(Succeed())
		})
	})

	// The empty string is how an unset chart value arrives
	// (`organization: {{ .Values.kagi.organization }}`) and how every
	// pre-existing object spells "use the token's bound organization". It must
	// keep being admitted or the tightening breaks working installs on their
	// next apply.
	It("accepts an explicitly empty organization", func() {
		resource := newSecret("org-admission-empty", "")
		Expect(k8sClient.Create(ctx, resource)).To(Succeed())
		DeferCleanup(func() {
			Expect(k8sClient.Delete(ctx, resource)).To(Succeed())
		})
	})
})
