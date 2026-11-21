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
	"fmt"

	kagi "github.com/korurlabs/kagi-operator/internal/kagiclient"
)

// The values of --kagi-auth: how the operator itself authenticates to the Kagi
// API when an object names no spec.tokenSecret.
const (
	// kagiAuthTokenSecret reads a PAT from --default-token-secret. It is the
	// default, so an install that never sets the flag behaves as before.
	kagiAuthTokenSecret = "token-secret"

	// kagiAuthExchange exchanges the operator's projected ServiceAccount token
	// at /kagi/auth/token for a short-lived token per (app, environment) pair.
	// The admin grants the pairs with a workload role in the portal whose
	// Kubernetes rule trusts the operator's namespace and service account.
	kagiAuthExchange = "exchange"
)

// workloadTokenSource validates the --kagi-auth value and returns the token
// source the reconcilers use in place of the default token Secret: nil for
// token-secret, a WorkloadTokenSource reading the projected token at
// kagi.DefaultServiceAccountTokenPath for exchange. Any other value is an error
// that fails start-up, so a typo never silently falls back to the PAT.
func workloadTokenSource(mode, kagiAPIURL string) (kagi.TokenSource, error) {
	switch mode {
	case kagiAuthTokenSecret:
		return nil, nil
	case kagiAuthExchange:
		return kagi.NewWorkloadTokenSource(kagiAPIURL), nil
	default:
		return nil, fmt.Errorf("--kagi-auth %q is not supported; use %q or %q", mode, kagiAuthTokenSecret, kagiAuthExchange)
	}
}
