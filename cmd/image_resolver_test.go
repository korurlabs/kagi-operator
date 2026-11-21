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

package main

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func resolverScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(s); err != nil {
		t.Fatalf("add clientgo scheme: %v", err)
	}
	return s
}

func ownPod(image string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "operator-abc123", Namespace: "kagi-system"},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{Name: "kube-rbac-proxy", Image: "rbac-proxy:1.0"},
				{Name: managerContainerName, Image: image},
			},
		},
	}
}

// resolveOwnImage returns the manager container's image from the operator's own
// pod.
func TestResolveOwnImageReturnsManagerImage(t *testing.T) {
	scheme := resolverScheme(t)
	pod := ownPod("registry.example/kagi-operator:0.0.42")
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(pod).Build()

	got, err := resolveOwnImage(context.Background(), c, "operator-abc123", "kagi-system", managerContainerName)
	if err != nil {
		t.Fatalf("resolveOwnImage: %v", err)
	}
	if want := "registry.example/kagi-operator:0.0.42"; got != want {
		t.Errorf("resolved image: got %q want %q", got, want)
	}
}

// A missing Downward API value is a loud error, never a silent placeholder.
func TestResolveOwnImageMissingEnvErrors(t *testing.T) {
	scheme := resolverScheme(t)
	c := fake.NewClientBuilder().WithScheme(scheme).Build()

	if _, err := resolveOwnImage(context.Background(), c, "", "kagi-system", managerContainerName); err == nil {
		t.Errorf("expected an error when POD_NAME is empty")
	}
	if _, err := resolveOwnImage(context.Background(), c, "operator-abc123", "", managerContainerName); err == nil {
		t.Errorf("expected an error when POD_NAMESPACE is empty")
	}
}

// A pod whose manager container is absent (or has no image) is a loud error.
func TestResolveOwnImageMissingContainerErrors(t *testing.T) {
	scheme := resolverScheme(t)
	pod := ownPod("registry.example/kagi-operator:0.0.42")
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(pod).Build()

	if _, err := resolveOwnImage(context.Background(), c, "operator-abc123", "kagi-system", "does-not-exist"); err == nil {
		t.Errorf("expected an error when the named container is absent")
	}
}

// An explicit override wins and short-circuits the pod lookup entirely (so it
// works even with an empty client and no Downward API values).
func TestResolveKagiInitImageOverrideWins(t *testing.T) {
	scheme := resolverScheme(t)
	c := fake.NewClientBuilder().WithScheme(scheme).Build()

	got, err := resolveKagiInitImage(context.Background(), c, "explicit/kagi-init:9.9.9", "", "", managerContainerName)
	if err != nil {
		t.Fatalf("resolveKagiInitImage with override: %v", err)
	}
	if want := "explicit/kagi-init:9.9.9"; got != want {
		t.Errorf("override image: got %q want %q", got, want)
	}
}

// With no override, resolveKagiInitImage falls through to the own-pod lookup.
func TestResolveKagiInitImageFallsBackToOwnImage(t *testing.T) {
	scheme := resolverScheme(t)
	pod := ownPod("registry.example/kagi-operator:0.0.42")
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(pod).Build()

	got, err := resolveKagiInitImage(context.Background(), c, "", "operator-abc123", "kagi-system", managerContainerName)
	if err != nil {
		t.Fatalf("resolveKagiInitImage fallback: %v", err)
	}
	if want := "registry.example/kagi-operator:0.0.42"; got != want {
		t.Errorf("fallback image: got %q want %q", got, want)
	}
}
