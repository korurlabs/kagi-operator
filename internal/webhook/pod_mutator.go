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

// Package webhook implements the Kagi pod-injection mutating admission webhook.
//
// The webhook turns an image-agnostic, single-label opt-in (kagi.pw/inject:
// "true", matched by the configuration's objectSelector) plus per-pod config
// annotations into a secretless-delivery pod: it injects an init container that
// stages the static
// kagi-init binary onto a memory-backed volume, mounts a short-lived projected
// ServiceAccount token, and rewrites the target container's command to run
// through kagi-init. At runtime kagi-init exchanges the SA token for a scoped
// Kagi token, fetches the secrets, and execs the original command with the
// merged environment -- so no secret value (and no long-lived credential) is
// ever persisted in the cluster.
//
// See docs/k8s-secretless-delivery-design.md (Section 3 Option 2, Section 5.2).
package webhook

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"path"

	corev1 "k8s.io/api/core/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

// webhookPath is the admission review path served by the pod mutator. It MUST
// match the clientConfig path in config/webhook/manifests.yaml.
const webhookPath = "/mutate--v1-pod"

// labelInject is the single, authoritative opt-in for pod injection (design
// Section 5.2). The MutatingWebhookConfiguration's objectSelector matches this
// LABEL, so only labeled pods ever reach the webhook -- it is the
// failurePolicy: Fail safety boundary that keeps unlabeled pods away. The
// handler re-checks the label as defense in depth against a mis-scoped
// selector. There is deliberately no separate opt-in annotation: carrying the
// label IS the opt-in.
const labelInject = "kagi.pw/inject"

// valueTrue is the value the inject label and the boolean annotations carry.
const valueTrue = "true"

// Pod configuration annotations (design Section 5.2). These carry per-pod
// injection config; they do NOT gate opt-in (labelInject does). A labeled pod
// MUST supply annotationAppID and annotationEnvironment; the rest are optional.
const (
	// annotationAppID is the Kagi app ID whose secrets kagi-init fetches (required).
	annotationAppID = "kagi.pw/app-id"
	// annotationEnvironment is the environment slug to fetch (required).
	annotationEnvironment = "kagi.pw/environment"
	// annotationWatchVersion enables kagi-init's PID-1 version watcher.
	annotationWatchVersion = "kagi.pw/watch-version"
	// annotationContainer names the target container (default: first container).
	annotationContainer = "kagi.pw/container"
	// annotationAudience optionally overrides the projected token audience.
	annotationAudience = "kagi.pw/audience"
	// annotationInjected is stamped by the webhook after a successful mutation so
	// a reinvocation (or a resubmitted pod) is a no-op instead of double-wrapping.
	annotationInjected = "kagi.pw/injected"
)

// Injected resource names. Kept stable so the idempotency guards can detect a
// prior mutation by name.
const (
	binVolumeName   = "kagi-init-bin"
	tokenVolumeName = "kagi-sa-token"
	initContainer   = "kagi-init"
)

// PodMutatorConfig carries the operator-level, non-per-pod settings the webhook
// bakes into every mutated pod. Everything here is defaulted by withDefaults so
// a zero value (except KagiInitImage) is usable.
type PodMutatorConfig struct {
	// KagiInitImage is the container image that ships the static kagi-init
	// binary at InitBinarySource. Required -- the webhook cannot be enabled
	// without it. Configured via the operator's --kagi-init-image flag /
	// KAGI_INIT_IMAGE env; never hardcoded to a registry here.
	KagiInitImage string
	// InitBinarySource is the path to the kagi-init binary inside KagiInitImage.
	InitBinarySource string
	// BinMountPath is the directory the memory-backed binary volume mounts at.
	BinMountPath string
	// BinaryPath is the absolute path kagi-init lands at inside the pod
	// (BinMountPath + "/kagi-init"); it becomes argv[0] of the rewritten command.
	BinaryPath string
	// TokenMountDir is the directory the projected SA token mounts at.
	TokenMountDir string
	// TokenFileName is the projected token's file name within TokenMountDir.
	TokenFileName string
	// TokenExpirationSeconds is the projected token TTL. Short by design; the
	// kubelet rotates it.
	TokenExpirationSeconds int64
	// DefaultAudience is the projected-token audience when a pod does not
	// override it via annotationAudience.
	DefaultAudience string
	// KagiAPIURL is passed to kagi-init (env KAGI_API_URL) so it knows where to
	// exchange the token and fetch secrets.
	KagiAPIURL string
}

// withDefaults returns a copy of the config with every unset field populated
// with its documented default. KagiInitImage is deliberately left as-is: an
// empty image is an error the caller must surface, not silently default.
func (c PodMutatorConfig) withDefaults() PodMutatorConfig {
	if c.InitBinarySource == "" {
		c.InitBinarySource = "/kagi-init"
	}
	if c.BinMountPath == "" {
		c.BinMountPath = "/kagi"
	}
	if c.BinaryPath == "" {
		c.BinaryPath = path.Join(c.BinMountPath, "kagi-init")
	}
	if c.TokenMountDir == "" {
		c.TokenMountDir = "/var/run/secrets/kagi.pw/serviceaccount"
	}
	if c.TokenFileName == "" {
		c.TokenFileName = "token"
	}
	if c.TokenExpirationSeconds == 0 {
		c.TokenExpirationSeconds = 600
	}
	if c.DefaultAudience == "" {
		c.DefaultAudience = "api.kagi.pw"
	}
	if c.KagiAPIURL == "" {
		c.KagiAPIURL = "https://api.kagi.pw"
	}
	return c
}

// tokenFilePath is the absolute path the projected token lands at; handed to
// kagi-init via KAGI_SA_TOKEN_PATH.
func (c PodMutatorConfig) tokenFilePath() string {
	return path.Join(c.TokenMountDir, c.TokenFileName)
}

// PodMutator is the admission handler for the pod-injection webhook.
type PodMutator struct {
	Config  PodMutatorConfig
	decoder admission.Decoder
}

// denyError signals that a pod is opted in but cannot be safely mutated (e.g. it
// declares no explicit command). It maps to an admission Denied response with an
// actionable message rather than a 500 -- the caller must fix the pod spec.
type denyError struct {
	msg string
}

func (e *denyError) Error() string { return e.msg }

func denyf(format string, args ...any) *denyError {
	return &denyError{msg: fmt.Sprintf(format, args...)}
}

// Handle implements admission.Handler. Unannotated pods pass through untouched;
// opted-in pods are mutated in place; opted-in pods that cannot be safely
// mutated are denied with a clear message. No error path is swallowed.
func (m *PodMutator) Handle(ctx context.Context, req admission.Request) admission.Response {
	log := logf.FromContext(ctx)

	pod := &corev1.Pod{}
	if err := m.decoder.Decode(req, pod); err != nil {
		log.Error(err, "Failed to decode pod from admission request")
		return admission.Errored(http.StatusBadRequest, err)
	}

	// Defense in depth: the objectSelector should already keep unlabeled pods
	// away from this webhook, but never mutate a pod that did not opt in.
	if !injectionRequested(pod) {
		return admission.Allowed("kagi.pw/inject label not set; pod left unchanged")
	}

	if err := mutatePod(pod, m.Config); err != nil {
		var deny *denyError
		if errors.As(err, &deny) {
			log.Info("Denying pod admission", "namespace", pod.Namespace, "generateName", pod.GenerateName, "reason", deny.msg)
			return admission.Denied(deny.msg)
		}
		log.Error(err, "Failed to mutate pod", "namespace", pod.Namespace, "generateName", pod.GenerateName)
		return admission.Errored(http.StatusInternalServerError, err)
	}

	marshaled, err := json.Marshal(pod)
	if err != nil {
		log.Error(err, "Failed to marshal mutated pod")
		return admission.Errored(http.StatusInternalServerError, err)
	}
	return admission.PatchResponseFromRaw(req.Object.Raw, marshaled)
}

// injectionRequested reports whether the pod carries the opt-in LABEL. The
// objectSelector already guarantees this for every pod that reaches the webhook;
// the handler re-checks it as defense in depth against a mis-scoped selector.
// The opt-in is the label alone -- no separate annotation is required.
func injectionRequested(pod *corev1.Pod) bool {
	return pod.Labels[labelInject] == valueTrue
}

// mutatePod applies the secretless-delivery mutation to an opted-in pod in
// place. It is a pure function of (pod, cfg) so it is unit-testable without the
// admission plumbing. It returns a *denyError for a pod that cannot be safely
// mutated, and a plain error for an unexpected internal failure.
func mutatePod(pod *corev1.Pod, cfg PodMutatorConfig) error {
	cfg = cfg.withDefaults()

	// Idempotency: a reinvocation or a resubmit must not double-wrap.
	if pod.Annotations[annotationInjected] == valueTrue {
		return nil
	}

	appID := pod.Annotations[annotationAppID]
	environment := pod.Annotations[annotationEnvironment]
	if appID == "" || environment == "" {
		return denyf("pod is labeled %s=true for kagi injection but is missing required annotation(s): %s and %s must both be set",
			labelInject, annotationAppID, annotationEnvironment)
	}

	if len(pod.Spec.Containers) == 0 {
		return denyf("pod requests kagi injection but declares no containers")
	}

	idx, err := targetContainerIndex(pod, pod.Annotations[annotationContainer])
	if err != nil {
		return err
	}
	target := &pod.Spec.Containers[idx]

	// The webhook cannot read the image ENTRYPOINT, so the target container MUST
	// declare an explicit command. Denying here (rather than passing through) is
	// the design's required, actionable failure.
	if len(target.Command) == 0 {
		return denyf("container %q must declare an explicit command/args for kagi injection: "+
			"the admission webhook cannot read the image ENTRYPOINT, so set spec.containers[%d].command "+
			"(and args) to the process kagi-init should exec", target.Name, idx)
	}

	audience := cfg.DefaultAudience
	if a := pod.Annotations[annotationAudience]; a != "" {
		audience = a
	}

	addBinVolume(pod)
	addTokenVolume(pod, cfg, audience)
	addInitContainer(pod, cfg)
	addTargetVolumeMounts(target, cfg)
	setTargetEnv(target, cfg, audience)
	rewriteCommand(target, cfg, appID, environment, pod.Annotations[annotationWatchVersion] == valueTrue)

	if pod.Annotations == nil {
		pod.Annotations = map[string]string{}
	}
	pod.Annotations[annotationInjected] = valueTrue
	return nil
}

// targetContainerIndex resolves the index of the container to wrap. An empty
// name selects the first container; a named container that does not exist is a
// deny (the pod asked for something that cannot be honored).
func targetContainerIndex(pod *corev1.Pod, name string) (int, error) {
	if name == "" {
		return 0, nil
	}
	for i := range pod.Spec.Containers {
		if pod.Spec.Containers[i].Name == name {
			return i, nil
		}
	}
	return 0, denyf("annotation %s=%q names a container that does not exist in the pod", annotationContainer, name)
}

// addBinVolume adds the memory-backed emptyDir the init container stages the
// binary onto. tmpfs (medium: Memory) -- never node disk. No-op if present.
func addBinVolume(pod *corev1.Pod) {
	if hasVolume(pod, binVolumeName) {
		return
	}
	pod.Spec.Volumes = append(pod.Spec.Volumes, corev1.Volume{
		Name: binVolumeName,
		VolumeSource: corev1.VolumeSource{
			EmptyDir: &corev1.EmptyDirVolumeSource{Medium: corev1.StorageMediumMemory},
		},
	})
}

// addTokenVolume adds the projected ServiceAccount token volume (audience-bound,
// short-lived, kubelet-rotated). No-op if present.
func addTokenVolume(pod *corev1.Pod, cfg PodMutatorConfig, audience string) {
	if hasVolume(pod, tokenVolumeName) {
		return
	}
	pod.Spec.Volumes = append(pod.Spec.Volumes, corev1.Volume{
		Name: tokenVolumeName,
		VolumeSource: corev1.VolumeSource{
			Projected: &corev1.ProjectedVolumeSource{
				Sources: []corev1.VolumeProjection{{
					ServiceAccountToken: &corev1.ServiceAccountTokenProjection{
						Audience:          audience,
						ExpirationSeconds: new(cfg.TokenExpirationSeconds),
						Path:              cfg.TokenFileName,
					},
				}},
			},
		},
	})
}

// addInitContainer prepends the init container that stages the static kagi-init
// binary onto the memory-backed volume. Prepended so the binary is present
// before any of the pod's own init containers run. No-op if present.
//
// The kagi-init image is distroless -- no shell, no cp -- so the binary
// self-installs: kagi-init --install <dest> copies its own binary (never a
// secret) to the shared volume. In-image binary path is InitBinarySource.
func addInitContainer(pod *corev1.Pod, cfg PodMutatorConfig) {
	for i := range pod.Spec.InitContainers {
		if pod.Spec.InitContainers[i].Name == initContainer {
			return
		}
	}
	ic := corev1.Container{
		Name:    initContainer,
		Image:   cfg.KagiInitImage,
		Command: []string{cfg.InitBinarySource, "--install", cfg.BinaryPath},
		VolumeMounts: []corev1.VolumeMount{{
			Name:      binVolumeName,
			MountPath: cfg.BinMountPath,
		}},
		SecurityContext: restrictedSecurityContext(),
	}
	pod.Spec.InitContainers = append([]corev1.Container{ic}, pod.Spec.InitContainers...)
}

// addTargetVolumeMounts mounts the staged binary (read-only) and the projected
// token (read-only) into the target container. No-op per mount if present.
func addTargetVolumeMounts(c *corev1.Container, cfg PodMutatorConfig) {
	if !hasMount(c, binVolumeName) {
		c.VolumeMounts = append(c.VolumeMounts, corev1.VolumeMount{
			Name:      binVolumeName,
			MountPath: cfg.BinMountPath,
			ReadOnly:  true,
		})
	}
	if !hasMount(c, tokenVolumeName) {
		c.VolumeMounts = append(c.VolumeMounts, corev1.VolumeMount{
			Name:      tokenVolumeName,
			MountPath: cfg.TokenMountDir,
			ReadOnly:  true,
		})
	}
}

// setTargetEnv injects the ambient configuration kagi-init needs to exchange the
// SA token and reach the Kagi API. Per-app selectors (app id, environment) go on
// the command line; these are the environment-wide knobs. Existing values are
// preserved so a pod can override them.
func setTargetEnv(c *corev1.Container, cfg PodMutatorConfig, audience string) {
	setEnvIfAbsent(c, "KAGI_API_URL", cfg.KagiAPIURL)
	setEnvIfAbsent(c, "KAGI_SA_TOKEN_PATH", cfg.tokenFilePath())
	setEnvIfAbsent(c, "KAGI_AUDIENCE", audience)
}

// rewriteCommand rewrites the target container's command to run the original
// process under kagi-init. The per-app selectors are passed as flags before the
// "--" separator; everything after it is the original command+args kagi-init
// execs unchanged.
func rewriteCommand(c *corev1.Container, cfg PodMutatorConfig, appID, environment string, watchVersion bool) {
	original := make([]string, 0, len(c.Command)+len(c.Args))
	original = append(original, c.Command...)
	original = append(original, c.Args...)

	newCommand := []string{
		cfg.BinaryPath,
		"--app-id=" + appID,
		"--environment=" + environment,
	}
	if watchVersion {
		newCommand = append(newCommand, "--watch-version")
	}
	newCommand = append(newCommand, "--")
	newCommand = append(newCommand, original...)

	c.Command = newCommand
	c.Args = nil
}

// restrictedSecurityContext returns a security context compatible with the
// "restricted" Pod Security Standard for the injected init container.
func restrictedSecurityContext() *corev1.SecurityContext {
	return &corev1.SecurityContext{
		AllowPrivilegeEscalation: new(false),
		Capabilities:             &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
		SeccompProfile:           &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
	}
}

func hasVolume(pod *corev1.Pod, name string) bool {
	for i := range pod.Spec.Volumes {
		if pod.Spec.Volumes[i].Name == name {
			return true
		}
	}
	return false
}

func hasMount(c *corev1.Container, name string) bool {
	for i := range c.VolumeMounts {
		if c.VolumeMounts[i].Name == name {
			return true
		}
	}
	return false
}

func setEnvIfAbsent(c *corev1.Container, name, value string) {
	for i := range c.Env {
		if c.Env[i].Name == name {
			return
		}
	}
	c.Env = append(c.Env, corev1.EnvVar{Name: name, Value: value})
}

// +kubebuilder:webhook:path=/mutate--v1-pod,mutating=true,failurePolicy=fail,sideEffects=None,groups="",resources=pods,verbs=create,versions=v1,name=mpod.kagi.pw,admissionReviewVersions=v1,reinvocationPolicy=never

// SetupPodWebhookWithManager registers the pod-injection mutating webhook with
// the manager's webhook server. It returns an error when the kagi-init image is
// unset, since a webhook that cannot name an injectable image would deny (or
// fail-closed) every annotated pod at admission time.
func SetupPodWebhookWithManager(mgr ctrl.Manager, cfg PodMutatorConfig) error {
	cfg = cfg.withDefaults()
	if cfg.KagiInitImage == "" {
		return fmt.Errorf("pod injection webhook requires a kagi-init image (set --kagi-init-image or KAGI_INIT_IMAGE)")
	}
	mgr.GetWebhookServer().Register(webhookPath, &admission.Webhook{
		Handler: &PodMutator{
			Config:  cfg,
			decoder: admission.NewDecoder(mgr.GetScheme()),
		},
	})
	return nil
}
