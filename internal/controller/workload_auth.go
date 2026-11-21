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

	kagi "github.com/korurlabs/kagi-operator/internal/kagiclient"
)

// Ready reasons of an object the operator authenticates through the workload
// token exchange (--kagi-auth exchange).
const (
	// reasonWorkloadTokenCannotResolve: the object asks for something the
	// exchange cannot authenticate. The exchange grants (app, environment)
	// pairs, so a KagiSecret that names its app by spec.folderPath (resolving
	// the path needs a credential before the app is known) and a
	// KagiCertificate cannot use it. The object is not retried: only a change
	// to its spec can fix it.
	reasonWorkloadTokenCannotResolve = "WorkloadTokenCannotResolve"

	// reasonWorkloadAccessDenied: the exchange refused the operator's identity
	// for the object's pair (401), because no workload role of the
	// organization grants it. The reconcile fails and backs off like any other
	// failed reconcile, so a role the admin adds later is picked up.
	reasonWorkloadAccessDenied = "WorkloadAccessDenied"

	// reasonTokenResolutionFailed: no credential could be obtained, for
	// example a missing token Secret or an unreadable projected token.
	reasonTokenResolutionFailed = "TokenResolutionFailed"
)

// folderPathUnderExchangeMessage explains why a KagiSecret addressed by
// spec.folderPath cannot be served by the exchange, and the two ways out.
const folderPathUnderExchangeMessage = "spec.folderPath cannot be resolved with --kagi-auth exchange: " +
	"the workload token exchange grants (app, environment) pairs, and resolving a folder path needs " +
	"a credential before the app is known. Set spec.appId to the app's id, or give this object a spec.tokenSecret"

// certificateUnderExchangeMessage explains why a KagiCertificate cannot be
// served by the exchange.
const certificateUnderExchangeMessage = "a KagiCertificate cannot authenticate with --kagi-auth exchange: " +
	"the workload token exchange grants (app, environment) pairs, and a certificate is not one. " +
	"Give this object a spec.tokenSecret"

// exchangeFailure maps a failed token exchange to its Ready reason and
// message. ok is false when err is not an exchange failure.
func exchangeFailure(err error, appID, environment string) (reason, message string, ok bool) {
	if !kagi.IsExchangeError(err) {
		return "", "", false
	}
	if kagi.IsWorkloadAccessDenied(err) {
		return reasonWorkloadAccessDenied, fmt.Sprintf(
			"Kagi refused the operator's Kubernetes identity for app %s environment %s: no workload role grants it. "+
				"The denial is listed on the operator's connection under Integrations in the portal; grant the pair "+
				"there, or give this object a spec.tokenSecret (%v)", appID, environment, err), true
	}
	return reasonTokenResolutionFailed, err.Error(), true
}
