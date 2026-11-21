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
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

func requestFor(name string) reconcile.Request {
	return reconcile.Request{NamespacedName: types.NamespacedName{Namespace: "default", Name: name}}
}

// TestFailureRateLimiterBackoffSchedule pins the retry schedule for one object
// that keeps failing: 5s, doubling, capped at 5m. It also proves that another
// object starts from the base regardless, and that Forget (what
// controller-runtime calls after a successful reconcile) resets the object.
func TestFailureRateLimiterBackoffSchedule(t *testing.T) {
	limiter, err := newFailureRateLimiter(0, 0)
	if err != nil {
		t.Fatalf("newFailureRateLimiter(0, 0) returned an error: %v", err)
	}

	failing := requestFor("failing")
	want := []time.Duration{
		5 * time.Second,
		10 * time.Second,
		20 * time.Second,
		40 * time.Second,
		80 * time.Second,
		160 * time.Second,
		5 * time.Minute, // 320s, capped
		5 * time.Minute, // stays at the cap
		5 * time.Minute,
	}
	for i, expected := range want {
		if got := limiter.When(failing); got != expected {
			t.Fatalf("failure %d of %s: delay %s, want %s", i+1, failing.Name, got, expected)
		}
	}
	if got := limiter.NumRequeues(failing); got != len(want) {
		t.Fatalf("NumRequeues(%s) = %d, want %d", failing.Name, got, len(want))
	}

	other := requestFor("healthy")
	if got := limiter.When(other); got != DefaultFailureBackoffBase {
		t.Fatalf("first failure of an unrelated object: delay %s, want %s", got, DefaultFailureBackoffBase)
	}
	if got := limiter.NumRequeues(other); got != 1 {
		t.Fatalf("NumRequeues(%s) = %d, want 1", other.Name, got)
	}
	// The unrelated object's failure must not have moved the failing one off the cap.
	if got := limiter.When(failing); got != DefaultFailureBackoffMax {
		t.Fatalf("failing object after an unrelated failure: delay %s, want %s", got, DefaultFailureBackoffMax)
	}

	limiter.Forget(failing)
	if got := limiter.NumRequeues(failing); got != 0 {
		t.Fatalf("NumRequeues(%s) after Forget = %d, want 0", failing.Name, got)
	}
	if got := limiter.When(failing); got != DefaultFailureBackoffBase {
		t.Fatalf("first failure after Forget: delay %s, want %s", got, DefaultFailureBackoffBase)
	}
}

// TestFailureRateLimiterCustomDurations checks that configured values replace
// the defaults rather than being ignored.
func TestFailureRateLimiterCustomDurations(t *testing.T) {
	limiter, err := newFailureRateLimiter(2*time.Second, 7*time.Second)
	if err != nil {
		t.Fatalf("newFailureRateLimiter(2s, 7s) returned an error: %v", err)
	}
	item := requestFor("custom")
	for i, expected := range []time.Duration{2 * time.Second, 4 * time.Second, 7 * time.Second, 7 * time.Second} {
		if got := limiter.When(item); got != expected {
			t.Fatalf("failure %d: delay %s, want %s", i+1, got, expected)
		}
	}
}

func TestFailureRateLimiterRejectsInvalidDurations(t *testing.T) {
	cases := []struct {
		name     string
		base     time.Duration
		maxDelay time.Duration
	}{
		{name: "negative base", base: -time.Second, maxDelay: time.Minute},
		{name: "negative max", base: time.Second, maxDelay: -time.Minute},
		{name: "max below base", base: time.Minute, maxDelay: time.Second},
		{name: "default max below explicit base", base: 10 * time.Minute, maxDelay: 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := newFailureRateLimiter(tc.base, tc.maxDelay); err == nil {
				t.Fatalf("newFailureRateLimiter(%s, %s) returned no error", tc.base, tc.maxDelay)
			}
		})
	}
}
