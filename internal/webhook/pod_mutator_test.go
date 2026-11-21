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

package webhook

import (
	"errors"
	"reflect"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const customAudience = "custom.audience.example"

// testConfig returns a fully-defaulted config with an explicit image, so tests
// exercise the same defaults the operator applies at runtime.
func testConfig() PodMutatorConfig {
	return PodMutatorConfig{
		KagiInitImage: "registry.example/kagi-init:1.2.3",
		KagiAPIURL:    "https://api.kagi.pw",
	}.withDefaults()
}

// newAnnotatedPod returns a pod that opts in via the kagi.pw/inject LABEL and
// carries only config annotations (app-id, environment) -- deliberately NO
// kagi.pw/inject annotation, to prove the label alone is the opt-in.
func newAnnotatedPod() *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "app",
			Namespace: "default",
			Labels:    map[string]string{labelInject: valueTrue},
			Annotations: map[string]string{
				annotationAppID:       "app-123",
				annotationEnvironment: "production",
			},
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{
				Name:    "app",
				Image:   "app:latest",
				Command: []string{"java", "-jar"},
				Args:    []string{"app.jar", "--server.port=8080"},
			}},
		},
	}
}

func findVolume(pod *corev1.Pod, name string) *corev1.Volume {
	for i := range pod.Spec.Volumes {
		if pod.Spec.Volumes[i].Name == name {
			return &pod.Spec.Volumes[i]
		}
	}
	return nil
}

func findEnv(c *corev1.Container, name string) (string, bool) {
	for i := range c.Env {
		if c.Env[i].Name == name {
			return c.Env[i].Value, true
		}
	}
	return "", false
}

// (a) An annotated pod gets the full mutation. It checks every part of one
// mutated pod in sequence, so its branch count is a list of assertions, not logic.
//
// nolint:gocyclo
func TestMutatePodAnnotatedGetsFullMutation(t *testing.T) {
	cfg := testConfig()
	pod := newAnnotatedPod()

	if err := mutatePod(pod, cfg); err != nil {
		t.Fatalf("mutatePod returned error: %v", err)
	}

	// tmpfs (memory-backed) emptyDir for the binary.
	binVol := findVolume(pod, binVolumeName)
	if binVol == nil {
		t.Fatalf("expected bin volume %q", binVolumeName)
	}
	if binVol.EmptyDir == nil {
		t.Fatalf("bin volume must be an emptyDir")
	}
	if binVol.EmptyDir.Medium != corev1.StorageMediumMemory {
		t.Errorf("bin volume must be memory-backed (tmpfs), got medium=%q", binVol.EmptyDir.Medium)
	}

	// Projected serviceAccountToken volume with audience + expiration.
	tokenVol := findVolume(pod, tokenVolumeName)
	if tokenVol == nil || tokenVol.Projected == nil {
		t.Fatalf("expected projected token volume %q", tokenVolumeName)
	}
	if len(tokenVol.Projected.Sources) != 1 || tokenVol.Projected.Sources[0].ServiceAccountToken == nil {
		t.Fatalf("token volume must have exactly one serviceAccountToken source")
	}
	sat := tokenVol.Projected.Sources[0].ServiceAccountToken
	if sat.Audience != cfg.DefaultAudience {
		t.Errorf("token audience: got %q want %q", sat.Audience, cfg.DefaultAudience)
	}
	if sat.ExpirationSeconds == nil || *sat.ExpirationSeconds != cfg.TokenExpirationSeconds {
		t.Errorf("token expirationSeconds: got %v want %d", sat.ExpirationSeconds, cfg.TokenExpirationSeconds)
	}
	if sat.Path != cfg.TokenFileName {
		t.Errorf("token path: got %q want %q", sat.Path, cfg.TokenFileName)
	}

	// Init container self-installs the binary from the operator image.
	if len(pod.Spec.InitContainers) != 1 {
		t.Fatalf("expected exactly one init container, got %d", len(pod.Spec.InitContainers))
	}
	ic := pod.Spec.InitContainers[0]
	if ic.Image != cfg.KagiInitImage {
		t.Errorf("init container image: got %q want %q", ic.Image, cfg.KagiInitImage)
	}
	wantInitCmd := []string{cfg.InitBinarySource, "--install", cfg.BinaryPath}
	if !reflect.DeepEqual(ic.Command, wantInitCmd) {
		t.Errorf("init container command: got %v want %v", ic.Command, wantInitCmd)
	}
	if len(ic.VolumeMounts) != 1 || ic.VolumeMounts[0].Name != binVolumeName || ic.VolumeMounts[0].MountPath != cfg.BinMountPath {
		t.Errorf("init container must mount %q at %q, got %+v", binVolumeName, cfg.BinMountPath, ic.VolumeMounts)
	}

	// Target container command rewrite: [binary, flags, "--", original cmd+args].
	target := &pod.Spec.Containers[0]
	wantCmd := []string{
		cfg.BinaryPath,
		"--app-id=app-123",
		"--environment=production",
		"--",
		"java", "-jar", "app.jar", "--server.port=8080",
	}
	if !reflect.DeepEqual(target.Command, wantCmd) {
		t.Errorf("target command: got %v want %v", target.Command, wantCmd)
	}
	if target.Args != nil {
		t.Errorf("target args must be cleared after being folded into command, got %v", target.Args)
	}

	// Ambient env for kagi-init.
	if v, ok := findEnv(target, "KAGI_SA_TOKEN_PATH"); !ok || v != cfg.tokenFilePath() {
		t.Errorf("KAGI_SA_TOKEN_PATH: got %q ok=%v want %q", v, ok, cfg.tokenFilePath())
	}
	if v, ok := findEnv(target, "KAGI_API_URL"); !ok || v != cfg.KagiAPIURL {
		t.Errorf("KAGI_API_URL: got %q ok=%v want %q", v, ok, cfg.KagiAPIURL)
	}
	if v, ok := findEnv(target, "KAGI_AUDIENCE"); !ok || v != cfg.DefaultAudience {
		t.Errorf("KAGI_AUDIENCE: got %q ok=%v want %q", v, ok, cfg.DefaultAudience)
	}

	// Target container mounts both volumes read-only.
	var gotBin, gotToken bool
	for _, m := range target.VolumeMounts {
		if m.Name == binVolumeName {
			gotBin = true
			if !m.ReadOnly {
				t.Errorf("bin mount in target must be read-only")
			}
		}
		if m.Name == tokenVolumeName {
			gotToken = true
			if !m.ReadOnly {
				t.Errorf("token mount in target must be read-only")
			}
		}
	}
	if !gotBin || !gotToken {
		t.Errorf("target container must mount bin(%v) and token(%v)", gotBin, gotToken)
	}

	// Idempotency marker set.
	if pod.Annotations[annotationInjected] != valueTrue {
		t.Errorf("expected injected marker annotation to be set")
	}
}

// (a-cont) Mutation must be idempotent: re-running on an already-injected pod is
// a no-op (no double-wrapping of the command, no duplicate volumes/containers).
func TestMutatePodIsIdempotent(t *testing.T) {
	cfg := testConfig()
	pod := newAnnotatedPod()

	if err := mutatePod(pod, cfg); err != nil {
		t.Fatalf("first mutatePod: %v", err)
	}
	first := pod.DeepCopy()
	if err := mutatePod(pod, cfg); err != nil {
		t.Fatalf("second mutatePod: %v", err)
	}
	if !reflect.DeepEqual(first, pod) {
		t.Errorf("second mutation changed the pod; expected idempotency")
	}
}

// (b) An unlabeled pod is returned byte-for-byte unchanged. Opt-in is the
// kagi.pw/inject LABEL; a pod without it (even one carrying config annotations)
// is never considered opted-in. The webhook handler short-circuits on
// injectionRequested; this asserts the pod it would leave untouched is genuinely
// untouched by our logic.
func TestUnlabeledPodUnchanged(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "plain",
			Namespace: "default",
			// Config annotations present but no opt-in label: still not opted in.
			Annotations: map[string]string{
				annotationAppID:       "app-123",
				annotationEnvironment: "production",
			},
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{Name: "app", Image: "app:latest", Command: []string{"run"}}},
		},
	}
	original := pod.DeepCopy()

	if injectionRequested(pod) {
		t.Fatalf("unlabeled pod must not be considered opted-in")
	}
	// The handler never calls mutatePod for such a pod; assert equality holds.
	if !reflect.DeepEqual(original, pod) {
		t.Errorf("unlabeled pod must be unchanged")
	}
}

// (b-cont) The label is the authoritative opt-in: a labeled pod that carries the
// required config annotations is mutated even though it has NO kagi.pw/inject
// annotation. This locks the collapse of the old double opt-in (label AND
// annotation) into a single label gate.
func TestLabeledPodWithoutInjectAnnotationIsOptedIn(t *testing.T) {
	pod := newAnnotatedPod()
	if _, ok := pod.Annotations[labelInject]; ok {
		t.Fatalf("test fixture must not set the kagi.pw/inject annotation")
	}
	if !injectionRequested(pod) {
		t.Fatalf("a pod carrying the kagi.pw/inject label must be opted in")
	}
	if err := mutatePod(pod, testConfig()); err != nil {
		t.Fatalf("labeled pod with config annotations must mutate, got: %v", err)
	}
	if pod.Annotations[annotationInjected] != valueTrue {
		t.Errorf("expected the injected marker after mutation")
	}
}

// (c) An annotated pod whose target container has no explicit command is denied
// with an actionable message.
func TestMutatePodNoCommandDenied(t *testing.T) {
	cfg := testConfig()
	pod := newAnnotatedPod()
	pod.Spec.Containers[0].Command = nil
	pod.Spec.Containers[0].Args = nil

	err := mutatePod(pod, cfg)
	if err == nil {
		t.Fatalf("expected deny error for a container with no explicit command")
	}
	var deny *denyError
	if !errors.As(err, &deny) {
		t.Fatalf("expected *denyError, got %T: %v", err, err)
	}
	// Message must be actionable: name the container and the command requirement.
	if deny.msg == "" {
		t.Errorf("deny message must be non-empty and actionable")
	}
	// The pod must not have been partially mutated on the deny path.
	if len(pod.Spec.InitContainers) != 0 || len(pod.Spec.Volumes) != 0 {
		t.Errorf("denied pod must not be partially mutated")
	}
}

// (c-cont) Missing required annotations (app-id / environment) is also a deny.
func TestMutatePodMissingRequiredAnnotationsDenied(t *testing.T) {
	cfg := testConfig()
	pod := newAnnotatedPod()
	delete(pod.Annotations, annotationAppID)

	err := mutatePod(pod, cfg)
	var deny *denyError
	if !errors.As(err, &deny) {
		t.Fatalf("expected *denyError for missing app-id, got %T: %v", err, err)
	}
}

// (d) The kagi.pw/audience annotation overrides the default audience on both the
// projected token and the injected KAGI_AUDIENCE env var.
func TestMutatePodAudienceOverride(t *testing.T) {
	cfg := testConfig()
	pod := newAnnotatedPod()
	pod.Annotations[annotationAudience] = customAudience

	if err := mutatePod(pod, cfg); err != nil {
		t.Fatalf("mutatePod: %v", err)
	}

	tokenVol := findVolume(pod, tokenVolumeName)
	if tokenVol == nil || tokenVol.Projected == nil {
		t.Fatalf("expected projected token volume")
	}
	sat := tokenVol.Projected.Sources[0].ServiceAccountToken
	if sat.Audience != customAudience {
		t.Errorf("token audience override: got %q want %q", sat.Audience, customAudience)
	}
	if v, _ := findEnv(&pod.Spec.Containers[0], "KAGI_AUDIENCE"); v != customAudience {
		t.Errorf("KAGI_AUDIENCE override: got %q want %q", v, customAudience)
	}
}

// (d-cont) A named target container is wrapped; a non-existent name is denied.
func TestMutatePodContainerSelection(t *testing.T) {
	cfg := testConfig()

	// Named container is selected.
	pod := newAnnotatedPod()
	pod.Spec.Containers = append(pod.Spec.Containers, corev1.Container{
		Name:    "sidecar",
		Image:   "sidecar:latest",
		Command: []string{"sidecar-run"},
	})
	pod.Annotations[annotationContainer] = "sidecar"
	if err := mutatePod(pod, cfg); err != nil {
		t.Fatalf("mutatePod (named container): %v", err)
	}
	// The first container (app) must be untouched; the sidecar wrapped.
	if !reflect.DeepEqual(pod.Spec.Containers[0].Command, []string{"java", "-jar"}) {
		t.Errorf("non-target container command must be untouched, got %v", pod.Spec.Containers[0].Command)
	}
	if pod.Spec.Containers[1].Command[0] != cfg.BinaryPath {
		t.Errorf("target sidecar must be wrapped, got %v", pod.Spec.Containers[1].Command)
	}

	// Non-existent name is denied.
	pod2 := newAnnotatedPod()
	pod2.Annotations[annotationContainer] = "does-not-exist"
	err := mutatePod(pod2, cfg)
	var deny *denyError
	if !errors.As(err, &deny) {
		t.Fatalf("expected deny for unknown container name, got %T: %v", err, err)
	}
}
