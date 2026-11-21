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
	"crypto/tls"
	"flag"
	"fmt"
	"net/http"
	"os"
	"time"

	// Import all Kubernetes client auth plugins (e.g. Azure, GCP, OIDC, etc.)
	// to ensure that exec-entrypoint and run can make use of them.
	_ "k8s.io/client-go/plugin/pkg/client/auth"

	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/metrics/filters"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	"sigs.k8s.io/controller-runtime/pkg/webhook"

	kagiv1alpha1 "github.com/korurlabs/kagi-operator/api/v1alpha1"
	"github.com/korurlabs/kagi-operator/internal/certs"
	"github.com/korurlabs/kagi-operator/internal/controller"
	kagi "github.com/korurlabs/kagi-operator/internal/kagiclient"
	kagiwebhook "github.com/korurlabs/kagi-operator/internal/webhook"
	// +kubebuilder:scaffold:imports
)

// envOr returns the value of the environment variable named by key, or def when
// it is unset or empty. Used to let a flag default read from the environment
// without letting the env silently override an explicit flag.
func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

var (
	scheme   = runtime.NewScheme()
	setupLog = ctrl.Log.WithName("setup")
)

// webhookReadyCheck reports the pod NOT ready until the pod-injection webhook is
// actually registered and serving.
//
// Readiness has to mean "admission works", not "the probe endpoint is up".
// /mutate--v1-pod is registered only after cache sync, certificate bootstrap and
// caBundle convergence -- tens of seconds on a large cluster -- and until then
// nothing listens on 9443 at all. Going Ready before that means a rolling
// upgrade puts the new pod into Endpoints, the old pod is terminated, and the
// API server gets connection-refused: with failurePolicy: Fail, every labeled
// pod in the cluster is un-creatable for the whole window.
//
// webhookServer.StartedChecker() is NOT a substitute -- the server starts
// listening before Register is called, so it would go green too early.
func webhookReadyCheck(enabled bool, serving <-chan struct{}) healthz.Checker {
	return func(_ *http.Request) error {
		if !enabled {
			return nil
		}
		select {
		case <-serving:
			return nil
		default:
			return fmt.Errorf("pod injection webhook is not serving yet: waiting for the certificate " +
				"and the MutatingWebhookConfiguration caBundle to converge")
		}
	}
}

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))

	utilruntime.Must(kagiv1alpha1.AddToScheme(scheme))
	// +kubebuilder:scaffold:scheme
}

// nolint:gocyclo
func main() {
	var metricsAddr string
	var metricsCertPath, metricsCertName, metricsCertKey string
	var webhookCertPath, webhookCertName, webhookCertKey string
	var enableLeaderElection bool
	var probeAddr string
	var secureMetrics bool
	var enableHTTP2 bool
	var tlsOpts []func(*tls.Config)

	// Kagi operator flags.
	var kagiAPIURL string
	var kagiAuth string
	var defaultTokenSecret string
	var defaultTokenNamespace string
	var defaultTokenKey string
	var maxConcurrentReconciles int
	var enablePodInjection bool
	var kagiInitImage string
	var saTokenAudience string
	var webhookCertSecret string
	var webhookCertManaged bool
	var webhookServiceName string
	var mutatingWebhookName string
	var webhookCABundleWait time.Duration
	var failureBackoffBase time.Duration
	var failureBackoffMax time.Duration

	flag.StringVar(&metricsAddr, "metrics-bind-address", "0", "The address the metrics endpoint binds to. "+
		"Use :8443 for HTTPS or :8080 for HTTP, or leave as 0 to disable the metrics service.")
	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081", "The address the probe endpoint binds to.")
	flag.BoolVar(&enableLeaderElection, "leader-elect", false,
		"Enable leader election for controller manager. "+
			"Enabling this will ensure there is only one active controller manager.")
	flag.BoolVar(&secureMetrics, "metrics-secure", true,
		"If set, the metrics endpoint is served securely via HTTPS. Use --metrics-secure=false to use HTTP instead.")
	flag.StringVar(&webhookCertPath, "webhook-cert-path", "", "The directory that contains the webhook certificate.")
	flag.StringVar(&webhookCertName, "webhook-cert-name", "tls.crt", "The name of the webhook certificate file.")
	flag.StringVar(&webhookCertKey, "webhook-cert-key", "tls.key", "The name of the webhook key file.")
	flag.StringVar(&metricsCertPath, "metrics-cert-path", "",
		"The directory that contains the metrics server certificate.")
	flag.StringVar(&metricsCertName, "metrics-cert-name", "tls.crt", "The name of the metrics server certificate file.")
	flag.StringVar(&metricsCertKey, "metrics-cert-key", "tls.key", "The name of the metrics server key file.")
	flag.BoolVar(&enableHTTP2, "enable-http2", false,
		"If set, HTTP/2 will be enabled for the metrics and webhook servers")

	// Kagi operator flags.
	flag.StringVar(&kagiAPIURL, "kagi-api-url", "https://api.kagi.pw", "Base URL of the Kagi API.")
	flag.StringVar(&kagiAuth, "kagi-auth", envOr("KAGI_AUTH", kagiAuthTokenSecret),
		"How the operator authenticates to the Kagi API when an object names no spec.tokenSecret (env KAGI_AUTH). "+
			"token-secret (default) reads a PAT from --default-token-secret. exchange trades the operator's projected "+
			"ServiceAccount token (audience: the API host, at "+kagi.DefaultServiceAccountTokenPath+") at "+
			"/kagi/auth/token for a short-lived token per (app, environment) pair; a workload role in the portal must "+
			"trust the operator's namespace and service account and cover the pairs its KagiSecrets read. Under exchange "+
			"a KagiSecret needs spec.appId (spec.folderPath cannot be resolved) and a KagiCertificate needs its own "+
			"spec.tokenSecret; --kagi-api-url must be the public API host the exchange checks resources against. "+
			"Any other value fails start-up.")
	flag.StringVar(&defaultTokenSecret, "default-token-secret", "",
		"Name of a K8s Secret containing the default Kagi PAT.")
	flag.StringVar(&defaultTokenNamespace, "default-token-namespace", "", "Namespace of the default token Secret.")
	flag.StringVar(&defaultTokenKey, "default-token-key", "",
		"Key inside the default token Secret that holds the PAT (chart: auth.existingSecretKey). When set it is used "+
			"EXCLUSIVELY, and a Secret that does not carry it is a hard error naming the Secret, the key and the keys "+
			"that are present -- the alternative is authenticating with whatever happens to sit under a different name. "+
			"Leave it empty to keep the historical KAGI_TOKEN -> token fallback, which is what every existing install "+
			"relies on. It applies to --default-token-secret only: a per-object spec.tokenSecret names a Secret its own "+
			"author controls and the CRD gives them no way to declare a key, so those keep the fallback.")
	flag.IntVar(&maxConcurrentReconciles, "max-concurrent-reconciles", 4,
		"Maximum number of KagiSecret objects reconciled concurrently. "+
			"Higher drains a backlog faster at the cost of more concurrent kagi-api load.")
	flag.DurationVar(&failureBackoffBase, "failure-backoff-base", controller.DefaultFailureBackoffBase,
		"Delay before retrying a KagiSecret or KagiCertificate whose reconcile failed (for example because the Kagi API "+
			"was unreachable). Each further consecutive failure of the same object doubles the delay, up to "+
			"--failure-backoff-max; a successful reconcile resets it. Objects back off independently. "+
			"0 selects the default.")
	flag.DurationVar(&failureBackoffMax, "failure-backoff-max", controller.DefaultFailureBackoffMax,
		"Upper bound on the per-object retry delay after repeated reconcile failures. "+
			"Must not be below --failure-backoff-base. 0 selects the default.")
	flag.BoolVar(&enablePodInjection, "enable-pod-injection", true,
		"Enable the pod-injection mutating webhook. "+
			"Only pods carrying the LABEL kagi.pw/inject=\"true\" are ever sent to it; "+
			"unlabeled pods are never touched. It must be a label, not an annotation -- "+
			"the webhook's objectSelector matches labels only, "+
			"so a pod merely annotated kagi.pw/inject=\"true\" is silently never injected.")
	flag.StringVar(&kagiInitImage, "kagi-init-image", envOr("KAGI_INIT_IMAGE", ""),
		"Container image that ships the static kagi-init binary the pod-injection webhook stages into labeled pods. "+
			"When unset, the operator defaults it to its own running image (the kagi-init binary is bundled at /kagi-init "+
			"inside the operator image), resolved via the Downward API POD_NAME/POD_NAMESPACE. An explicit value wins.")
	flag.StringVar(&saTokenAudience, "sa-token-audience", "api.kagi.pw",
		"Default audience for the projected ServiceAccount token the pod-injection webhook mounts. "+
			"Overridable per pod via the kagi.pw/audience annotation.")

	// Webhook TLS is owned by the operator itself (internal/certs): it issues,
	// stores, renews and publishes its own serving certificate, so no
	// cert-manager (or any other certificate tooling) is required. These three
	// names tell it which objects to bootstrap against; the Helm chart and the
	// kustomize overlay both pass them explicitly, and the defaults match a
	// `helm install kagi-operator` with no name overrides.
	flag.StringVar(&webhookCertSecret, "webhook-cert-secret",
		envOr("KAGI_WEBHOOK_CERT_SECRET", "kagi-operator-webhook-server-cert"),
		"Name of the Secret, in the operator's own namespace, holding the webhook's TLS serving certificate. "+
			"The operator creates it if absent and rotates it before expiry; it is the shared source of truth across replicas.")
	flag.BoolVar(&webhookCertManaged, "webhook-cert-managed", true,
		"Whether the operator owns the webhook serving certificate. True (default) means it issues, stores and rotates "+
			"its own -- nothing to install or renew. Set to false only when your organization requires certificates from "+
			"its own PKI: --webhook-cert-secret then names a Secret YOU create and rotate (it must carry tls.crt, tls.key "+
			"and ca.crt), the operator never writes to it, and it only keeps the MutatingWebhookConfiguration's caBundle "+
			"in sync with your ca.crt.")
	flag.StringVar(&webhookServiceName, "webhook-service-name",
		envOr("KAGI_WEBHOOK_SERVICE_NAME", "kagi-operator-webhook"),
		"Name of the Service fronting the webhook server. Determines the serving certificate's SANs "+
			"(<svc>.<ns>.svc and <svc>.<ns>.svc.cluster.local).")
	flag.StringVar(&mutatingWebhookName, "mutating-webhook-name",
		envOr("KAGI_MUTATING_WEBHOOK_NAME", "kagi-operator-mutating-webhook-configuration"),
		"Name of the MutatingWebhookConfiguration whose caBundle the operator keeps in sync with the certificate it issues.")
	flag.DurationVar(&webhookCABundleWait, "webhook-cabundle-wait", 5*time.Minute,
		"How long to wait for the MutatingWebhookConfiguration's caBundle to match the operator-issued CA before failing "+
			"startup. Generous by default because Helm creates the MutatingWebhookConfiguration after the Deployment.")

	opts := zap.Options{
		Development: true,
	}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()

	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))

	workloadTokens, err := workloadTokenSource(kagiAuth, kagiAPIURL)
	if err != nil {
		setupLog.Error(err, "Invalid --kagi-auth")
		os.Exit(1)
	}
	if workloadTokens != nil {
		setupLog.Info("Authenticating through the workload token exchange; the default token Secret is not read",
			"kagi-auth", kagiAuth, "serviceAccountTokenPath", kagi.DefaultServiceAccountTokenPath)
	}

	// if the enable-http2 flag is false (the default), http/2 should be disabled
	// due to its vulnerabilities. More specifically, disabling http/2 will
	// prevent from being vulnerable to the HTTP/2 Stream Cancellation and
	// Rapid Reset CVEs. For more information see:
	// - https://github.com/advisories/GHSA-qppj-fm5r-hxr3
	// - https://github.com/advisories/GHSA-4374-p667-p6c8
	disableHTTP2 := func(c *tls.Config) {
		setupLog.Info("Disabling HTTP/2")
		c.NextProtos = []string{"http/1.1"}
	}

	if !enableHTTP2 {
		tlsOpts = append(tlsOpts, disableHTTP2)
	}

	// Initial webhook TLS options
	webhookTLSOpts := tlsOpts
	webhookServerOptions := webhook.Options{
		TLSOpts: webhookTLSOpts,
	}

	// With pod injection on, the operator always serves TLS from a directory it
	// populates itself, so an unset --webhook-cert-path is a configuration gap
	// rather than a "no certificate" mode. Default it to controller-runtime's
	// own CertDir instead of silently starting a webhook server with no cert.
	if enablePodInjection && webhookCertPath == "" {
		webhookCertPath = certs.DefaultCertDir
		setupLog.Info("Defaulting webhook certificate directory", "webhook-cert-path", webhookCertPath)
	}

	if len(webhookCertPath) > 0 {
		setupLog.Info("Initializing webhook certificate watcher using provided certificates",
			"webhook-cert-path", webhookCertPath, "webhook-cert-name", webhookCertName, "webhook-cert-key", webhookCertKey)

		webhookServerOptions.CertDir = webhookCertPath
		webhookServerOptions.CertName = webhookCertName
		webhookServerOptions.KeyName = webhookCertKey
	}

	webhookServer := webhook.NewServer(webhookServerOptions)

	// Metrics endpoint is enabled in 'config/default/kustomization.yaml'. The Metrics options configure the server.
	metricsServerOptions := metricsserver.Options{
		BindAddress:   metricsAddr,
		SecureServing: secureMetrics,
		TLSOpts:       tlsOpts,
	}

	if secureMetrics {
		metricsServerOptions.FilterProvider = filters.WithAuthenticationAndAuthorization
	}

	if len(metricsCertPath) > 0 {
		setupLog.Info("Initializing metrics certificate watcher using provided certificates",
			"metrics-cert-path", metricsCertPath, "metrics-cert-name", metricsCertName, "metrics-cert-key", metricsCertKey)

		metricsServerOptions.CertDir = metricsCertPath
		metricsServerOptions.CertName = metricsCertName
		metricsServerOptions.KeyName = metricsCertKey
	}

	restConfig := ctrl.GetConfigOrDie()
	mgr, err := ctrl.NewManager(restConfig, ctrl.Options{
		Scheme:                 scheme,
		Metrics:                metricsServerOptions,
		WebhookServer:          webhookServer,
		HealthProbeBindAddress: probeAddr,
		LeaderElection:         enableLeaderElection,
		LeaderElectionID:       "f449781f.sensey.io",
	})
	if err != nil {
		setupLog.Error(err, "Failed to start manager")
		os.Exit(1)
	}

	// Only a KagiSecret or KagiCertificate in the operator's own namespace may
	// name a Secret in another namespace. Without POD_NAMESPACE (a local
	// `make run`) the operator cannot tell, so it holds every resource to its
	// own namespace.
	operatorNamespace := os.Getenv("POD_NAMESPACE")
	if operatorNamespace == "" {
		setupLog.Info("POD_NAMESPACE is not set; every KagiSecret and KagiCertificate " +
			"may only name Secrets in its own namespace")
	}

	// The reconcilers emit core/v1 Events through record.EventRecorder, which
	// the operator's RBAC grants; see the matching note in internal/certs.

	if err := (&controller.KagiSecretReconciler{
		Client:                      mgr.GetClient(),
		Scheme:                      mgr.GetScheme(),
		KagiAPIURL:                  kagiAPIURL,
		APIReader:                   mgr.GetAPIReader(),
		Recorder:                    mgr.GetEventRecorderFor("kagisecret-controller"), //nolint:staticcheck
		OperatorNamespace:           operatorNamespace,
		DefaultTokenSecretName:      defaultTokenSecret,
		DefaultTokenSecretNamespace: defaultTokenNamespace,
		DefaultTokenSecretKey:       defaultTokenKey,
		WorkloadTokens:              workloadTokens,
		MaxConcurrentReconciles:     maxConcurrentReconciles,
		FailureBackoffBase:          failureBackoffBase,
		FailureBackoffMax:           failureBackoffMax,
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "Failed to create controller", "controller", "KagiSecret")
		os.Exit(1)
	}
	if err := (&controller.KagiCertificateReconciler{
		Client:                      mgr.GetClient(),
		Scheme:                      mgr.GetScheme(),
		KagiAPIURL:                  kagiAPIURL,
		APIReader:                   mgr.GetAPIReader(),
		Recorder:                    mgr.GetEventRecorderFor("kagicertificate-controller"), //nolint:staticcheck
		OperatorNamespace:           operatorNamespace,
		DefaultTokenSecretName:      defaultTokenSecret,
		DefaultTokenSecretNamespace: defaultTokenNamespace,
		DefaultTokenSecretKey:       defaultTokenKey,
		WorkloadTokens:              workloadTokens,
		FailureBackoffBase:          failureBackoffBase,
		FailureBackoffMax:           failureBackoffMax,
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "Failed to create controller", "controller", "KagiCertificate")
		os.Exit(1)
	}

	// One signal handler for the whole process: the manager and the deferred
	// webhook registration below both shut down on it. ctrl.SetupSignalHandler
	// panics if called twice, so it is created here and shared.
	ctx := ctrl.SetupSignalHandler()

	// Closed once /mutate--v1-pod is actually registered and serving. The readyz
	// check below gates on it; see the comment there for why that matters.
	webhookServing := make(chan struct{})

	if enablePodInjection {
		// Resolve the injected kagi-init image. An explicit override wins;
		// otherwise it defaults to the operator's own running image (the kagi-init
		// binary ships bundled inside the operator image, and CI auto-tags that
		// image, so it must never be hand-pinned). No silent fallback: a failed
		// resolution with no override fails startup loudly.
		resolveClient, err := client.New(restConfig, client.Options{Scheme: scheme})
		if err != nil {
			setupLog.Error(err, "Failed to build client to resolve the operator's own image")
			os.Exit(1)
		}
		kagiInitImage, err = resolveKagiInitImage(context.Background(), resolveClient,
			kagiInitImage, os.Getenv("POD_NAME"), os.Getenv("POD_NAMESPACE"), managerContainerName)
		if err != nil {
			setupLog.Error(err, "Failed to resolve kagi-init image from the operator's own pod; "+
				"set --kagi-init-image or KAGI_INIT_IMAGE to override")
			os.Exit(1)
		}
		setupLog.Info("Resolved kagi-init image for pod injection", "image", kagiInitImage)

		// By default the operator owns its own webhook serving certificate -- no
		// cert-manager, no chart-generated keypair. --webhook-cert-managed=false
		// is the opt-in escape hatch for organizations whose policy requires
		// certificates from their own PKI. See internal/certs.
		certOptions := certs.Options{
			Namespace:               os.Getenv("POD_NAMESPACE"),
			SecretName:              webhookCertSecret,
			ServiceName:             webhookServiceName,
			MutatingWebhookName:     mutatingWebhookName,
			CertDir:                 webhookCertPath,
			CABundleWaitTimeout:     webhookCABundleWait,
			UserSuppliedCertificate: !webhookCertManaged,
		}
		if err := certOptions.Validate(); err != nil {
			setupLog.Error(err, "Invalid webhook certificate configuration")
			os.Exit(1)
		}

		if !certOptions.UserSuppliedCertificate {
			// cert-controller only ever Updates the cert Secret, so it has to
			// exist before the manager starts or the rotator takes the manager
			// down.
			if err := certs.EnsureCertSecret(context.Background(), resolveClient, certOptions.SecretKey()); err != nil {
				setupLog.Error(err, "Failed to ensure the webhook certificate Secret exists")
				os.Exit(1)
			}
		} else {
			// The Secret is the user's. Refuse to start on a missing or
			// half-populated one rather than serve behind a webhook whose
			// caBundle we could never fill in.
			if _, err := certs.LoadSuppliedCertSecret(context.Background(), resolveClient,
				certOptions.SecretKey(), certOptions.DNSName()); err != nil {
				setupLog.Error(err, "Unusable user-supplied webhook certificate Secret "+
					"(--webhook-cert-managed=false / injection.existingCertSecret)")
				os.Exit(1)
			}
		}

		certsReady := make(chan struct{})
		if err := certs.Setup(mgr, certOptions, certsReady); err != nil {
			setupLog.Error(err, "Failed to set up webhook certificate handling", "mode", certOptions.Mode())
			os.Exit(1)
		}
		setupLog.Info("Webhook certificate handling enabled",
			"mode", certOptions.Mode(),
			"secret", certOptions.SecretKey().String(),
			"dnsName", certOptions.DNSName(),
			"mutatingWebhookConfiguration", mutatingWebhookName,
			"certDir", webhookCertPath)

		podMutatorConfig := kagiwebhook.PodMutatorConfig{
			KagiInitImage:   kagiInitImage,
			KagiAPIURL:      kagiAPIURL,
			DefaultAudience: saTokenAudience,
		}

		// Registration is deferred until the certificate is on disk AND the API
		// server's caBundle matches it. Registering earlier would start the
		// webhook server on a certificate the API server does not trust, which
		// -- with failurePolicy: Fail -- makes every pod labeled
		// kagi.pw/inject: "true" un-creatable. Nothing outside that
		// objectSelector is ever affected.
		go func() {
			select {
			case <-certsReady:
			case <-ctx.Done():
				setupLog.Info("Shutting down before the webhook certificate was ready; pod injection webhook not registered")
				return
			}

			if err := certs.AwaitWebhookCABundle(ctx, resolveClient, certOptions); err != nil {
				if ctx.Err() != nil {
					setupLog.Info("Shutting down while waiting for the webhook CA bundle; pod injection webhook not registered")
					return
				}
				setupLog.Error(err, "Refusing to serve the pod-injection webhook: the API server does not trust the "+
					"certificate this operator serves")
				os.Exit(1)
			}

			// SetupPodWebhookWithManager is what calls mgr.GetWebhookServer(),
			// and that call is load-bearing HERE, not earlier: controller-runtime
			// adds the webhook server to the manager lazily, on the first
			// GetWebhookServer() call. Hoisting it up into main() would start the
			// server before a certificate exists, and on a fresh install (where
			// the operator has to mint that certificate itself) the manager would
			// die reading an absent cert file -- a permanent crash-loop, because
			// the only process that can create the cert is the one crashing.
			if err := kagiwebhook.SetupPodWebhookWithManager(mgr, podMutatorConfig); err != nil {
				setupLog.Error(err, "Failed to set up pod injection webhook")
				os.Exit(1)
			}
			close(webhookServing)
			setupLog.Info("Pod injection webhook registered and serving")
		}()
	}
	// +kubebuilder:scaffold:builder

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		setupLog.Error(err, "Failed to set up health check")
		os.Exit(1)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		setupLog.Error(err, "Failed to set up ready check")
		os.Exit(1)
	}
	// See webhookReadyCheck. Registered unconditionally (it returns nil when
	// injection is off) because AddReadyzCheck must run before mgr.Start.
	if err := mgr.AddReadyzCheck("webhook", webhookReadyCheck(enablePodInjection, webhookServing)); err != nil {
		setupLog.Error(err, "Failed to set up the webhook ready check")
		os.Exit(1)
	}

	setupLog.Info("Starting manager")
	if err := mgr.Start(ctx); err != nil {
		setupLog.Error(err, "Failed to run manager")
		os.Exit(1)
	}
}
