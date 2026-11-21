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
	"os"
	"strings"
	"testing"

	kagi "github.com/korurlabs/kagi-operator/internal/kagiclient"
)

// The flag's default comes from KAGI_AUTH and falls back to token-secret, so
// an install that sets neither keeps reading its PAT.
func TestKagiAuthDefaultsToTokenSecret(t *testing.T) {
	t.Setenv("KAGI_AUTH", "")
	if got := envOr("KAGI_AUTH", kagiAuthTokenSecret); got != kagiAuthTokenSecret {
		t.Errorf("default with KAGI_AUTH unset = %q, want %q", got, kagiAuthTokenSecret)
	}
	t.Setenv("KAGI_AUTH", kagiAuthExchange)
	if got := envOr("KAGI_AUTH", kagiAuthTokenSecret); got != kagiAuthExchange {
		t.Errorf("default with KAGI_AUTH=exchange = %q, want %q", got, kagiAuthExchange)
	}
}

// Under exchange the source reads the projected token at the path the
// manager manifest and the chart mount it.
func TestExchangeSourceReadsTheMountedProjectedToken(t *testing.T) {
	if _, err := os.Stat(kagi.DefaultServiceAccountTokenPath); err == nil {
		t.Skipf("%s exists on this machine; the test needs it absent", kagi.DefaultServiceAccountTokenPath)
	}
	source, err := workloadTokenSource(kagiAuthExchange, "https://api.kagi.pw")
	if err != nil {
		t.Fatalf("workloadTokenSource returned error: %v", err)
	}

	_, err = source.Token(context.Background(), kagi.TokenScope{AppID: "app-1", EnvironmentSlug: "production"})
	if !kagi.IsExchangeError(err) {
		t.Fatalf("Token err = %v, want an exchange error", err)
	}
	if !strings.Contains(err.Error(), kagi.DefaultServiceAccountTokenPath) {
		t.Errorf("err = %q, want it to name %s", err.Error(), kagi.DefaultServiceAccountTokenPath)
	}
}
