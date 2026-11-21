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
	"strings"
	"testing"
)

func TestWebhookReadyCheckIsNotReadyUntilRegistrationCompletes(t *testing.T) {
	serving := make(chan struct{})
	check := webhookReadyCheck(true, serving)

	// Before registration nothing is listening on 9443. Reporting Ready here is
	// what lets a rolling upgrade terminate the old pod and leave the API server
	// with connection-refused on a fail-closed webhook.
	err := check(nil)
	if err == nil {
		t.Fatal("readiness must report not-ready until the webhook is registered and serving")
	}
	if !strings.Contains(err.Error(), "not serving yet") {
		t.Fatalf("error should explain what is being waited on, got %v", err)
	}

	close(serving)

	if err := check(nil); err != nil {
		t.Fatalf("readiness must go green once the webhook is serving, got %v", err)
	}
}

func TestWebhookReadyCheckIsAlwaysReadyWhenInjectionIsDisabled(t *testing.T) {
	// With --enable-pod-injection=false nothing ever closes the channel, so the
	// check must not hold the pod out of Endpoints forever.
	check := webhookReadyCheck(false, make(chan struct{}))

	if err := check(nil); err != nil {
		t.Fatalf("with injection disabled the webhook check must always pass, got %v", err)
	}
}
