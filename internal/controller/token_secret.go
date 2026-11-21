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
	"fmt"
	"maps"
	"slices"

	corev1 "k8s.io/api/core/v1"
)

// The keys a token Secret is read from when no explicit key is configured, in
// order. KAGI_TOKEN is the env-style name a Secret consumed via envFrom would
// carry; token is what the Helm chart writes.
const (
	tokenSecretKeyEnvStyle = "KAGI_TOKEN"
	tokenSecretKeyPlain    = "token"
)

// tokenFromSecret extracts the Kagi PAT from a token Secret.
//
// key is the explicitly configured key, wired from --default-token-key (the
// chart's auth.existingSecretKey). When it is set it is used EXCLUSIVELY, and a
// Secret that does not carry it is a hard error naming the Secret, the key and
// the keys that are present.
//
// That loudness is the point. auth.existingSecretKey was documented by the
// chart and consumed only when the chart itself created the Secret; the
// operator hardcoded the KAGI_TOKEN -> token lookup, so setting the value to
// anything else produced an operator that authenticated with whatever happened
// to sit under those two names, or failed with an error naming neither -- a
// silent failure of a documented setting.
//
// When key is empty the historical KAGI_TOKEN -> token fallback applies
// unchanged, so installs that never set it behave exactly as before.
func tokenFromSecret(secret *corev1.Secret, key string) (string, error) {
	ref := fmt.Sprintf("%s/%s", secret.Namespace, secret.Name)

	if key != "" {
		token, ok := secret.Data[key]
		if !ok {
			return "", fmt.Errorf("token secret %s does not contain the configured key %q "+
				"(--default-token-key, chart auth.existingSecretKey); the keys it does hold are %v",
				ref, key, secretDataKeys(secret))
		}
		if len(token) == 0 {
			return "", fmt.Errorf("token secret %s holds an empty value under the configured key %q "+
				"(--default-token-key, chart auth.existingSecretKey)", ref, key)
		}
		return string(token), nil
	}

	token, ok := secret.Data[tokenSecretKeyEnvStyle]
	if !ok {
		token, ok = secret.Data[tokenSecretKeyPlain]
	}
	if !ok {
		return "", fmt.Errorf("token secret %s does not contain key %q or %q",
			ref, tokenSecretKeyEnvStyle, tokenSecretKeyPlain)
	}
	return string(token), nil
}

// secretDataKeys lists a Secret's key NAMES (never their values) in a stable
// order, so the error above can tell an operator what they should have
// configured instead.
func secretDataKeys(secret *corev1.Secret) []string {
	return slices.Sorted(maps.Keys(secret.Data))
}
