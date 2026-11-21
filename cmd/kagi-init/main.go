// Command kagi-init is the secretless-delivery launcher injected into workload
// pods by the Kagi operator's mutating webhook (design: Option 1/2, Section 3 of
// docs/k8s-secretless-delivery-design.md).
//
// It exchanges the pod's projected Kubernetes ServiceAccount JWT at the Kagi
// token exchange (POST /kagi/auth/token) for a short-lived WORKLOAD token that
// reads only the pod's (app, environment) pair, fetches that pair's secrets,
// merges them over the inherited process environment (fetched values win), and
// execs the real workload command that follows a "--" separator.
//
// Hard constraints (design Sections 2/3/6, non-negotiable):
//   - No fallback cache of any kind. A cache would reintroduce the in-cluster
//     persistence this design exists to remove. On startup the fetch is retried
//     with exponential backoff and then FAILS (non-zero exit -> CrashLoopBackOff).
//   - Secret values live ONLY in the child process environment. They are never
//     written to a file or to disk.
//   - No silent failures: every error path wraps and returns (surfaced on stderr
//     and a non-zero exit) or logs to stderr with context.
//
// With --watch-version the process runs as PID 1, supervises the child, and
// polls the decrypt-free version endpoint on an interval; on a version change it
// sends the child SIGTERM so it exits and the pod is restarted with fresh
// secrets (design Section 3, Option 2 rotation secondary mechanism).
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	kagi "github.com/korurlabs/kagi-operator/internal/kagiclient"
)

const (
	// defaultAudience is the audience the projected ServiceAccount token is
	// minted with by the webhook. It is informational here (kagi-init reads the
	// already-projected token from disk); it is retained for forward
	// compatibility and startup logging.
	defaultAudience = "api.kagi.pw"

	// defaultWatchInterval matches the operator's 5-minute version probe cadence.
	defaultWatchInterval = 5 * time.Minute

	// defaultStartupTimeout bounds the total time spent retrying the initial
	// secret fetch before the process gives up and exits non-zero.
	defaultStartupTimeout = 5 * time.Minute

	backoffInitialInterval = 1 * time.Second
	backoffMaxInterval     = 30 * time.Second
)

// envNamePattern is the set of keys kagi-init passes into the environment. Kagi
// accepts `-` and `.` in key names because a Kubernetes Secret does, but a shell
// cannot name or export such a variable. Leading digits stay usable so that
// existing keys such as `1KEY` keep being injected.
var envNamePattern = regexp.MustCompile(`^[A-Za-z0-9_]+$`)

var (
	errMissingSeparator = errors.New(
		"missing '--' separator before the child command (usage: kagi-init [flags] -- <command> [args...])")
	errEmptyCommand = errors.New("no child command specified after '--'")
)

// config holds the resolved runtime configuration for a single kagi-init run.
type config struct {
	appID          string
	environment    string
	apiURL         string
	audience       string
	saTokenPath    string
	organizationID string
	watchVersion   bool
	watchInterval  time.Duration
	startupTimeout time.Duration
	installDest    string
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "kagi-init: %v\n", err)
		os.Exit(1)
	}
}

// run wires configuration, obtains secrets, and hands off to the child. It
// returns an error for any failure so main can surface it on stderr and exit
// non-zero; on the successful non-watch path it does not return (syscall.Exec
// replaces the process image), and on the successful watch path it calls
// os.Exit with the child's exit code.
func run(args []string) error {
	flagArgs, cmdArgs, hasSep := splitArgs(args)

	fs := flag.NewFlagSet("kagi-init", flag.ContinueOnError)
	cfg, err := parseConfig(fs, flagArgs)
	if err != nil {
		return err
	}

	logf := func(format string, a ...any) {
		fmt.Fprintf(os.Stderr, format+"\n", a...)
	}

	// Self-install mode: copy this binary to a destination (used by the webhook's
	// init container to place kagi-init on the shared memory-backed emptyDir
	// without needing a shell in the distroless image). This copies the binary
	// itself, never any secret value.
	if cfg.installDest != "" {
		return installSelf(cfg.installDest)
	}

	command, err := childCommand(hasSep, cmdArgs)
	if err != nil {
		return err
	}
	if err := cfg.validate(); err != nil {
		return err
	}

	// A signal during the startup-fetch phase must abort the retry loop cleanly.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	client := newKagiClient(cfg)

	logf("kagi-init: fetching secrets for app=%s environment=%s from %s (audience %s)",
		cfg.appID, cfg.environment, cfg.apiURL, cfg.audience)
	secrets, err := fetchWithRetry(ctx, cfg, client, logf)
	if err != nil {
		return err
	}
	logf("kagi-init: fetched %d secret(s); launching child", len(secrets))

	// A key that cannot be a variable name is skipped rather than failing the pod,
	// so one such key never blocks the workload. Only names are logged, never values.
	usable, skipped := envUsableSecrets(secrets)
	if len(skipped) > 0 {
		logf("%s", skippedKeysMessage(skipped))
	}

	// Secrets exist only in the child's environment from here on -- never on disk.
	env := mergeEnv(os.Environ(), usable)

	if cfg.watchVersion {
		// The supervised path installs its own signal forwarding, so release the
		// startup-phase signal handler to avoid double handling.
		stop()
		code, superviseErr := superviseChild(context.Background(), cfg, client, command, env, logf)
		if superviseErr != nil {
			return superviseErr
		}
		os.Exit(code)
	}

	// Non-watch path: replace this process image entirely. Signals and exit code
	// then belong to the child with no supervision overhead.
	return execChild(command, env)
}

// newKagiClient builds a Kagi SDK client that authenticates via the projected
// ServiceAccount token exchange rather than a static PAT. The client only ever
// reads the pair of the pod's kagi.pw/app-id and kagi.pw/environment
// annotations, so the exchange is asked for that one pair; the admin's workload
// roles decide whether it is granted.
func newKagiClient(cfg *config) *kagi.Client {
	tokenSource := kagi.NewWorkloadTokenSource(
		cfg.apiURL,
		kagi.WithServiceAccountTokenPath(cfg.saTokenPath),
	)
	opts := []kagi.Option{kagi.WithTokenSource(tokenSource)}
	if cfg.organizationID != "" {
		opts = append(opts, kagi.WithOrganization(cfg.organizationID))
	}
	// The static token is unused because WithTokenSource overrides it.
	return kagi.NewClient(cfg.apiURL, "", opts...)
}

// parseConfig registers flags (each defaulting from its environment variable)
// on fs and parses flagArgs into a config.
func parseConfig(fs *flag.FlagSet, flagArgs []string) (*config, error) {
	cfg := &config{}
	fs.StringVar(&cfg.appID, "app-id", envOr("KAGI_APP_ID", ""),
		"Kagi app ID whose secrets to fetch (env KAGI_APP_ID)")
	fs.StringVar(&cfg.environment, "environment", envOr("KAGI_ENVIRONMENT", ""),
		"environment slug to fetch (env KAGI_ENVIRONMENT)")
	fs.StringVar(&cfg.apiURL, "api-url", envOr("KAGI_API_URL", ""),
		"Kagi API base URL, e.g. https://api.kagi.pw (env KAGI_API_URL)")
	fs.StringVar(&cfg.audience, "audience", envOr("KAGI_AUDIENCE", defaultAudience),
		"expected audience of the projected ServiceAccount token (env KAGI_AUDIENCE)")
	fs.StringVar(&cfg.saTokenPath, "sa-token-path", envOr("KAGI_SA_TOKEN_PATH", kagi.DefaultServiceAccountTokenPath),
		"path to the projected ServiceAccount JWT (env KAGI_SA_TOKEN_PATH)")
	fs.StringVar(&cfg.organizationID, "organization", envOr("KAGI_ORGANIZATION_ID", ""),
		"optional organization UUID cross-check header (env KAGI_ORGANIZATION_ID)")
	fs.BoolVar(&cfg.watchVersion, "watch-version", envBool("KAGI_WATCH_VERSION", false),
		"run as PID 1 and SIGTERM the child when the secrets version changes (env KAGI_WATCH_VERSION)")
	fs.DurationVar(&cfg.watchInterval, "watch-interval", envDuration("KAGI_WATCH_INTERVAL", defaultWatchInterval),
		"interval between secrets version probes when --watch-version is set (env KAGI_WATCH_INTERVAL)")
	fs.DurationVar(&cfg.startupTimeout, "startup-timeout", envDuration("KAGI_STARTUP_TIMEOUT", defaultStartupTimeout),
		"total time to retry the initial secret fetch before failing (env KAGI_STARTUP_TIMEOUT)")
	fs.StringVar(&cfg.installDest, "install", "",
		"copy this binary to the given path and exit (used by the injector init container)")

	if err := fs.Parse(flagArgs); err != nil {
		return nil, err
	}
	return cfg, nil
}

// validate ensures the configuration required to fetch and launch is present.
func (c *config) validate() error {
	var missing []string
	if c.appID == "" {
		missing = append(missing, "--app-id/KAGI_APP_ID")
	}
	if c.environment == "" {
		missing = append(missing, "--environment/KAGI_ENVIRONMENT")
	}
	if c.apiURL == "" {
		missing = append(missing, "--api-url/KAGI_API_URL")
	}
	if c.saTokenPath == "" {
		missing = append(missing, "--sa-token-path/KAGI_SA_TOKEN_PATH")
	}
	if len(missing) > 0 {
		return fmt.Errorf("missing required configuration: %s", strings.Join(missing, ", "))
	}
	// A malformed organization id is refused here rather than sent. The Kagi API
	// would either reject every request with 403 for the life of the pod (tenancy
	// enforcement STRICT) or drop the cross-check without telling this process
	// (OFF/SHADOW), so an unvalidated typo turns into either an unexplained crash
	// loop or a safety check that silently never runs.
	if err := kagi.ValidateOrganizationID(c.organizationID); err != nil {
		return fmt.Errorf("invalid --organization/KAGI_ORGANIZATION_ID: %w", err)
	}
	return nil
}

// splitArgs separates the kagi-init flag arguments from the child command using
// the first "--" separator. hasSep reports whether a separator was present; when
// absent, all args are treated as flag args and cmdArgs is nil.
func splitArgs(args []string) (flagArgs, cmdArgs []string, hasSep bool) {
	for i, a := range args {
		if a == "--" {
			return args[:i], args[i+1:], true
		}
	}
	return args, nil, false
}

// childCommand validates that a child command was supplied after "--".
func childCommand(hasSep bool, cmdArgs []string) ([]string, error) {
	if !hasSep {
		return nil, errMissingSeparator
	}
	if len(cmdArgs) == 0 {
		return nil, errEmptyCommand
	}
	return cmdArgs, nil
}

// envUsableSecrets splits secrets into the keys that can be environment variable
// names and the sorted names of those that cannot.
func envUsableSecrets(secrets map[string]string) (map[string]string, []string) {
	usable := make(map[string]string, len(secrets))
	var skipped []string
	for key, val := range secrets {
		if envNamePattern.MatchString(key) {
			usable[key] = val
			continue
		}
		skipped = append(skipped, key)
	}
	sort.Strings(skipped)
	return usable, skipped
}

// skippedKeysMessage is the log line naming the keys envUsableSecrets skipped.
func skippedKeysMessage(skipped []string) string {
	if len(skipped) == 1 {
		return "kagi-init: skipped 1 key that can't be an environment variable: " + skipped[0]
	}
	return fmt.Sprintf("kagi-init: skipped %d keys that can't be environment variables: %s",
		len(skipped), strings.Join(skipped, ", "))
}

// mergeEnv merges fetched secrets over a base environment (as produced by
// os.Environ()). Fetched values win over any base entry of the same key; base
// keys not present in overrides are preserved. The result is deduplicated (so a
// child's getenv is unambiguous regardless of libc duplicate-key behavior) and
// deterministic: base keys keep their original order, then override-only keys
// are appended in sorted order.
func mergeEnv(base []string, overrides map[string]string) []string {
	values := make(map[string]string, len(base)+len(overrides))
	order := make([]string, 0, len(base))

	for _, kv := range base {
		key, val, found := strings.Cut(kv, "=")
		if !found || key == "" {
			continue
		}
		if _, exists := values[key]; !exists {
			order = append(order, key)
		}
		values[key] = val
	}

	newKeys := make([]string, 0, len(overrides))
	for key, val := range overrides {
		if _, exists := values[key]; !exists {
			newKeys = append(newKeys, key)
		}
		values[key] = val
	}
	sort.Strings(newKeys)
	order = append(order, newKeys...)

	result := make([]string, 0, len(order))
	for _, key := range order {
		result = append(result, key+"="+values[key])
	}
	return result
}

// fetchWithRetry fetches secrets, retrying transient failures with exponential
// backoff up to cfg.startupTimeout. There is deliberately no fallback cache: on
// exhaustion it returns an error so the process exits non-zero (CrashLoopBackOff).
func fetchWithRetry(
	ctx context.Context, cfg *config, client *kagi.Client, logf func(string, ...any),
) (map[string]string, error) {
	deadline := time.Now().Add(cfg.startupTimeout)
	delay := backoffInitialInterval

	for attempt := 1; ; attempt++ {
		secrets, err := client.FetchSecrets(ctx, cfg.appID, cfg.environment)
		if err == nil {
			return secrets, nil
		}

		logf("kagi-init: secret fetch attempt %d failed: %v", attempt, err)

		if time.Now().After(deadline) {
			return nil, fmt.Errorf("giving up fetching secrets after %d attempt(s) over %s: %w",
				attempt, cfg.startupTimeout, err)
		}

		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("interrupted while fetching secrets: %w", ctx.Err())
		case <-time.After(delay):
		}

		delay *= 2
		if delay > backoffMaxInterval {
			delay = backoffMaxInterval
		}
	}
}

// execChild replaces the current process image with the child command, so the
// child inherits PID 1 and all signals directly. On success it does not return.
func execChild(cmdArgs, env []string) error {
	binary, err := exec.LookPath(cmdArgs[0])
	if err != nil {
		return fmt.Errorf("cannot resolve child command %q: %w", cmdArgs[0], err)
	}
	if err := syscall.Exec(binary, cmdArgs, env); err != nil {
		return fmt.Errorf("failed to exec %q: %w", binary, err)
	}
	return nil // unreachable on success
}

// superviseChild starts the child under supervision (used in --watch-version
// mode), forwards signals to it, watches the secrets version, and returns the
// child's exit code. On a version change the watcher SIGTERMs the child so it
// exits and the pod is restarted with fresh secrets.
func superviseChild(
	ctx context.Context, cfg *config, client *kagi.Client, cmdArgs, env []string, logf func(string, ...any),
) (int, error) {
	binary, err := exec.LookPath(cmdArgs[0])
	if err != nil {
		return 1, fmt.Errorf("cannot resolve child command %q: %w", cmdArgs[0], err)
	}

	child := exec.Command(binary, cmdArgs[1:]...)
	child.Env = env
	child.Stdin = os.Stdin
	child.Stdout = os.Stdout
	child.Stderr = os.Stderr

	if err := child.Start(); err != nil {
		return 1, fmt.Errorf("failed to start child %q: %w", binary, err)
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT)
	go func() {
		for sig := range sigCh {
			if child.Process != nil {
				_ = child.Process.Signal(sig)
			}
		}
	}()

	watchCtx, cancelWatch := context.WithCancel(ctx)
	defer cancelWatch()
	go watchVersion(watchCtx, cfg, client, child, logf)

	waitErr := child.Wait()
	signal.Stop(sigCh)
	close(sigCh)

	if waitErr != nil {
		var exitErr *exec.ExitError
		if errors.As(waitErr, &exitErr) {
			return exitErr.ExitCode(), nil
		}
		return 1, fmt.Errorf("child %q terminated abnormally: %w", binary, waitErr)
	}
	return 0, nil
}

// watchVersion polls the decrypt-free secrets version endpoint and SIGTERMs the
// child when the version changes. A probe failure while the child is healthy is
// logged and tolerated (a transient API blip must not kill a running workload);
// this is a deliberate, surfaced non-fatal path, not a silent swallow.
func watchVersion(ctx context.Context, cfg *config, client *kagi.Client, child *exec.Cmd, logf func(string, ...any)) {
	initial, err := client.GetSecretsVersion(ctx, cfg.appID, cfg.environment)
	if err != nil {
		logf("kagi-init: initial version probe failed, version watching disabled: %v", err)
		return
	}
	logf("kagi-init: watching secrets version %q every %s", initial, cfg.watchInterval)

	ticker := time.NewTicker(cfg.watchInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			current, probeErr := client.GetSecretsVersion(ctx, cfg.appID, cfg.environment)
			if probeErr != nil {
				logf("kagi-init: version probe failed (keeping child running): %v", probeErr)
				continue
			}
			if current != initial {
				logf("kagi-init: secrets version changed %q -> %q; signalling child to exit", initial, current)
				if child.Process != nil {
					if sigErr := child.Process.Signal(syscall.SIGTERM); sigErr != nil {
						logf("kagi-init: failed to SIGTERM child after version change: %v", sigErr)
					}
				}
				return
			}
		}
	}
}

// installSelf copies the running executable to dest with executable permissions.
// It is used by the injector init container to stage kagi-init onto the shared
// memory-backed emptyDir; it copies the binary itself, never a secret value.
func installSelf(dest string) error {
	src, err := os.Executable()
	if err != nil {
		return fmt.Errorf("cannot locate own executable for install: %w", err)
	}

	in, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("cannot open own executable %q: %w", src, err)
	}
	// in is opened read-only, so its close error cannot lose data; out's close is checked below.
	defer func() { _ = in.Close() }()

	out, err := os.OpenFile(dest, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755)
	if err != nil {
		return fmt.Errorf("cannot create install destination %q: %w", dest, err)
	}

	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return fmt.Errorf("failed to copy binary to %q: %w", dest, err)
	}
	if err := out.Close(); err != nil {
		return fmt.Errorf("failed to finalize install destination %q: %w", dest, err)
	}

	fmt.Fprintf(os.Stderr, "kagi-init: installed binary to %s\n", dest)
	return nil
}

// envOr returns the value of the environment variable key, or fallback when it
// is unset or empty.
func envOr(key, fallback string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return fallback
}

// envBool parses a boolean environment variable, falling back on unset/invalid.
func envBool(key string, fallback bool) bool {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return fallback
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return fallback
	}
	return b
}

// envDuration parses a duration environment variable, falling back on
// unset/invalid.
func envDuration(key string, fallback time.Duration) time.Duration {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return fallback
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return fallback
	}
	return d
}
