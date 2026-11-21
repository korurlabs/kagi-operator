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
	"time"

	"golang.org/x/time/rate"
	"k8s.io/client-go/util/workqueue"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

// DefaultFailureBackoffBase is the delay before the first retry of an object
// whose reconcile returned an error. Each further consecutive failure of the
// same object doubles it, up to DefaultFailureBackoffMax.
//
// controller-runtime's own default starts at 5ms, which retries a failing
// object about ten times in its first five seconds. Every one of those retries
// is a Kagi API call (and usually a database read behind it), so during a
// backend incident the operator would add load exactly when the backend can
// least take it. A 5s floor keeps a transient blip cheap to recover from while
// removing that burst. main wires it from --failure-backoff-base.
const DefaultFailureBackoffBase = 5 * time.Second

// DefaultFailureBackoffMax caps the per-object retry delay. It matches
// kagiSecretResyncInterval, so a persistently failing KagiSecret is retried no
// less often than a healthy one is resynced. main wires it from
// --failure-backoff-max.
const DefaultFailureBackoffMax = 5 * time.Minute

// The overall (all objects together) retry budget: a token bucket refilled at
// failureRetryQPS with room for failureRetryBurst. These are the values of
// client-go's DefaultTypedControllerRateLimiter. They bound how fast the
// operator retries when many objects fail at once, independently of the
// per-object backoff. Steady-state resyncs (RequeueAfter) never draw from this
// bucket; only error retries do.
const (
	failureRetryQPS   = 10
	failureRetryBurst = 100
)

// newFailureRateLimiter returns the workqueue rate limiter both controllers
// use for objects whose reconcile returned an error.
//
// The delay for an object is the larger of a per-object exponential backoff
// (base, 2*base, 4*base, ... capped at maxDelay) and the shared token bucket
// described above. A successful reconcile, including one that returns
// RequeueAfter, makes controller-runtime call Forget on the object, which
// resets its backoff to base. Objects never share a backoff: one failing
// KagiSecret does not slow the retries of another.
//
// A zero base or maxDelay selects the default, so a reconciler built without
// these fields (tests, or a caller that never set them) keeps the documented
// behaviour. A negative value, or a cap below the base, is a configuration
// error and is returned rather than silently corrected.
func newFailureRateLimiter(base, maxDelay time.Duration) (workqueue.TypedRateLimiter[reconcile.Request], error) {
	if base == 0 {
		base = DefaultFailureBackoffBase
	}
	if maxDelay == 0 {
		maxDelay = DefaultFailureBackoffMax
	}
	if base < 0 || maxDelay < 0 {
		return nil, fmt.Errorf("failure backoff durations must not be negative: base %s, max %s", base, maxDelay)
	}
	if maxDelay < base {
		return nil, fmt.Errorf("failure backoff max %s is below the base %s", maxDelay, base)
	}
	return workqueue.NewTypedMaxOfRateLimiter(
		workqueue.NewTypedItemExponentialFailureRateLimiter[reconcile.Request](base, maxDelay),
		&workqueue.TypedBucketRateLimiter[reconcile.Request]{
			Limiter: rate.NewLimiter(rate.Limit(failureRetryQPS), failureRetryBurst),
		},
	), nil
}
