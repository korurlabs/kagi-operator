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
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// managerContainerName is the name of the operator's own container in its Pod
// spec (see config/manager/manager.yaml). resolveOwnImage reads this
// container's image to default the injected kagi-init init-container image to
// the operator's own running image -- the kagi-init binary ships bundled inside
// the operator image at /kagi-init, so the two are always the same build.
const managerContainerName = "manager"

// The operator reads its own Pod at startup to default the injected kagi-init
// image to its own running image (resolveOwnImage). Only get is needed.
// +kubebuilder:rbac:groups="",resources=pods,verbs=get

// resolveKagiInitImage decides the kagi-init image the pod-injection webhook
// stages. An explicit override (from --kagi-init-image / KAGI_INIT_IMAGE) always
// wins; otherwise the image is resolved from the operator's own running pod so
// it tracks the auto-tagged operator build.
func resolveKagiInitImage(
	ctx context.Context, reader client.Reader, override, podName, podNamespace, containerName string,
) (string, error) {
	if override != "" {
		return override, nil
	}
	return resolveOwnImage(ctx, reader, podName, podNamespace, containerName)
}

// resolveOwnImage looks up the operator's own Pod (identified by the Downward
// API POD_NAME/POD_NAMESPACE values) and returns the image of the named
// container. It is how the operator defaults the kagi-init init-container image
// to its own running image when no explicit override is configured.
//
// It never silently falls back: a missing Downward API value, a failed Get, or
// a missing/empty container image all return an error so the caller can fail
// startup loudly rather than inject a broken placeholder image.
func resolveOwnImage(
	ctx context.Context, reader client.Reader, podName, podNamespace, containerName string,
) (string, error) {
	if podName == "" || podNamespace == "" {
		return "", fmt.Errorf("cannot resolve operator image: POD_NAME/POD_NAMESPACE not set "+
			"(expose them via the Downward API, or set --kagi-init-image/KAGI_INIT_IMAGE): got name=%q namespace=%q",
			podName, podNamespace)
	}

	var pod corev1.Pod
	if err := reader.Get(ctx, types.NamespacedName{Name: podName, Namespace: podNamespace}, &pod); err != nil {
		return "", fmt.Errorf("failed to get own pod %s/%s to resolve operator image: %w", podNamespace, podName, err)
	}

	for i := range pod.Spec.Containers {
		if pod.Spec.Containers[i].Name != containerName {
			continue
		}
		image := pod.Spec.Containers[i].Image
		if image == "" {
			return "", fmt.Errorf("container %q in own pod %s/%s has no image set", containerName, podNamespace, podName)
		}
		return image, nil
	}
	return "", fmt.Errorf("container %q not found in own pod %s/%s", containerName, podNamespace, podName)
}
