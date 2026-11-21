package main

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestSplitArgs(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		wantFlags  []string
		wantCmd    []string
		wantHasSep bool
	}{
		{
			name:       "flags then command",
			args:       []string{"--app-id", "abc", "--environment", "production", "--", "java", "-jar", "app.jar"},
			wantFlags:  []string{"--app-id", "abc", "--environment", "production"},
			wantCmd:    []string{"java", "-jar", "app.jar"},
			wantHasSep: true,
		},
		{
			name:       "separator with empty command",
			args:       []string{"--app-id", "abc", "--"},
			wantFlags:  []string{"--app-id", "abc"},
			wantCmd:    []string{},
			wantHasSep: true,
		},
		{
			name:       "no separator",
			args:       []string{"--app-id", "abc", "java", "-jar"},
			wantFlags:  []string{"--app-id", "abc", "java", "-jar"},
			wantCmd:    nil,
			wantHasSep: false,
		},
		{
			name:       "separator first",
			args:       []string{"--", "sh", "-c", "echo hi"},
			wantFlags:  []string{},
			wantCmd:    []string{"sh", "-c", "echo hi"},
			wantHasSep: true,
		},
		{
			name:       "empty args",
			args:       []string{},
			wantFlags:  []string{},
			wantCmd:    nil,
			wantHasSep: false,
		},
		{
			name:       "first separator wins, later dashes belong to child",
			args:       []string{"--app-id", "abc", "--", "cmd", "--", "flag"},
			wantFlags:  []string{"--app-id", "abc"},
			wantCmd:    []string{"cmd", "--", "flag"},
			wantHasSep: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotFlags, gotCmd, gotHasSep := splitArgs(tt.args)
			if gotHasSep != tt.wantHasSep {
				t.Errorf("hasSep = %v, want %v", gotHasSep, tt.wantHasSep)
			}
			if !equalStringSlice(gotFlags, tt.wantFlags) {
				t.Errorf("flagArgs = %#v, want %#v", gotFlags, tt.wantFlags)
			}
			if !equalStringSlice(gotCmd, tt.wantCmd) {
				t.Errorf("cmdArgs = %#v, want %#v", gotCmd, tt.wantCmd)
			}
		})
	}
}

func TestChildCommand(t *testing.T) {
	tests := []struct {
		name    string
		hasSep  bool
		cmdArgs []string
		want    []string
		wantErr error
	}{
		{
			name:    "missing separator errors",
			hasSep:  false,
			cmdArgs: nil,
			wantErr: errMissingSeparator,
		},
		{
			name:    "separator present but empty command errors",
			hasSep:  true,
			cmdArgs: []string{},
			wantErr: errEmptyCommand,
		},
		{
			name:    "valid command",
			hasSep:  true,
			cmdArgs: []string{"java", "-jar", "app.jar"},
			want:    []string{"java", "-jar", "app.jar"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := childCommand(tt.hasSep, tt.cmdArgs)
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("err = %v, want %v", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !equalStringSlice(got, tt.want) {
				t.Errorf("command = %#v, want %#v", got, tt.want)
			}
		})
	}
}

func TestMergeEnv(t *testing.T) {
	tests := []struct {
		name      string
		base      []string
		overrides map[string]string
		want      []string
	}{
		{
			name:      "fetched value overrides base, base preserved, new appended sorted",
			base:      []string{"PATH=/usr/bin", "SECRET=old", "HOME=/root"},
			overrides: map[string]string{"SECRET": "new", "DB_URL": "postgres://x", "API_KEY": "k"},
			// base keys keep original order with overridden values; new keys sorted.
			want: []string{"PATH=/usr/bin", "SECRET=new", "HOME=/root", "API_KEY=k", "DB_URL=postgres://x"},
		},
		{
			name:      "no overrides preserves base as-is",
			base:      []string{"A=1", "B=2"},
			overrides: map[string]string{},
			want:      []string{"A=1", "B=2"},
		},
		{
			name:      "empty base yields sorted overrides",
			base:      []string{},
			overrides: map[string]string{"Z": "26", "A": "1", "M": "13"},
			want:      []string{"A=1", "M=13", "Z=26"},
		},
		{
			name:      "value containing equals sign is preserved",
			base:      []string{"BASE64=aGVsbG8="},
			overrides: map[string]string{"TOKEN": "a=b=c"},
			want:      []string{"BASE64=aGVsbG8=", "TOKEN=a=b=c"},
		},
		{
			name:      "malformed base entries without equals are dropped",
			base:      []string{"GOOD=1", "MALFORMED", "=noKey"},
			overrides: map[string]string{},
			want:      []string{"GOOD=1"},
		},
		{
			name:      "override replaces value in place without duplicating key",
			base:      []string{"A=1", "B=2", "C=3"},
			overrides: map[string]string{"B": "99"},
			want:      []string{"A=1", "B=99", "C=3"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := mergeEnv(tt.base, tt.overrides)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("mergeEnv() = %#v, want %#v", got, tt.want)
			}
			assertNoDuplicateKeys(t, got)
		})
	}
}

// assertNoDuplicateKeys guards the core invariant a child's getenv relies on: no
// environment key appears twice in the merged result.
func assertNoDuplicateKeys(t *testing.T, env []string) {
	t.Helper()
	seen := map[string]bool{}
	for _, kv := range env {
		key := kv
		for i := 0; i < len(kv); i++ {
			if kv[i] == '=' {
				key = kv[:i]
				break
			}
		}
		if seen[key] {
			t.Errorf("duplicate key %q in merged env %#v", key, env)
		}
		seen[key] = true
	}
}

func equalStringSlice(a, b []string) bool {
	if len(a) == 0 && len(b) == 0 {
		return true
	}
	return reflect.DeepEqual(a, b)
}

// validate refuses a malformed --organization before any request is made. Left
// unchecked, the value reaches the Kagi API as X-Organization-ID, where a typo
// is answered with a 403 on every fetch for the life of the pod (tenancy
// enforcement STRICT) or is discarded server-side while the request proceeds on
// the token's own organization (OFF/SHADOW) -- a cross-check that silently never
// happens. Failing here turns both into one startup error naming the value.
func TestValidateOrganizationID(t *testing.T) {
	base := func() *config {
		return &config{
			appID:       "11111111-1111-1111-1111-111111111111",
			environment: "production",
			apiURL:      "https://api.kagi.pw",
			saTokenPath: "/var/run/secrets/kagi/token",
		}
	}

	cases := []struct {
		name           string
		organizationID string
		wantErr        bool
	}{
		{"unset keeps the token's organization", "", false},
		{"a canonical UUID is accepted", "3f2504e0-4f89-11d3-9a0c-0305e82c3301", false},
		{"a slug is refused", "acme", true},
		{"a truncated UUID is refused", "3f2504e0-4f89-11d3-9a0c", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := base()
			cfg.organizationID = tc.organizationID
			err := cfg.validate()
			if tc.wantErr {
				if err == nil {
					t.Fatalf("validate() with organization %q = nil, want an error", tc.organizationID)
				}
				if !strings.Contains(err.Error(), "KAGI_ORGANIZATION_ID") {
					t.Errorf("validate() error = %q, want it to name --organization/KAGI_ORGANIZATION_ID", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("validate() with organization %q = %v, want nil", tc.organizationID, err)
			}
		})
	}
}

func TestEnvUsableSecretsSkipsKeysThatCannotBeVariables(t *testing.T) {
	secrets := map[string]string{
		"A":              "a-value",
		"tls.crt":        "cert-value",
		"redis-password": "redis-value",
	}

	usable, skipped := envUsableSecrets(secrets)

	if want := map[string]string{"A": "a-value"}; !reflect.DeepEqual(usable, want) {
		t.Errorf("usable = %#v, want %#v", usable, want)
	}
	if want := []string{"redis-password", "tls.crt"}; !reflect.DeepEqual(skipped, want) {
		t.Errorf("skipped = %#v, want %#v", skipped, want)
	}

	env := mergeEnv([]string{"PATH=/bin"}, usable)
	if want := []string{"PATH=/bin", "A=a-value"}; !reflect.DeepEqual(env, want) {
		t.Errorf("env = %#v, want %#v", env, want)
	}

	msg := skippedKeysMessage(skipped)
	want := "kagi-init: skipped 2 keys that can't be environment variables: redis-password, tls.crt"
	if msg != want {
		t.Errorf("message = %q, want %q", msg, want)
	}
	for _, val := range secrets {
		if strings.Contains(msg, val) {
			t.Errorf("message %q contains the secret value %q", msg, val)
		}
	}
}

func TestEnvUsableSecretsKeepsVariableNames(t *testing.T) {
	secrets := map[string]string{
		"DB_PASSWORD": "x",
		"apiKey":      "y",
		"1KEY":        "z",
		"_private":    "w",
	}

	usable, skipped := envUsableSecrets(secrets)

	if !reflect.DeepEqual(usable, secrets) {
		t.Errorf("usable = %#v, want every key %#v", usable, secrets)
	}
	if len(skipped) != 0 {
		t.Errorf("skipped = %#v, want none", skipped)
	}
}

func TestSkippedKeysMessageSingular(t *testing.T) {
	got := skippedKeysMessage([]string{"tls.crt"})
	want := "kagi-init: skipped 1 key that can't be an environment variable: tls.crt"
	if got != want {
		t.Errorf("message = %q, want %q", got, want)
	}
}
