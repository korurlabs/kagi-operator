package kagiclient

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// crdOrganizationPatternFiles are every file that restates the organization-id
// pattern. controller-gen writes the two under config/crd/bases from the
// +kubebuilder:validation:Pattern markers on KagiSecretSpec.Organization and
// KagiCertificateSpec.Organization; the two under charts/ are hand-maintained
// copies shipped by the Helm chart, and nothing in the build compares them to
// the generated pair. This test is that comparison.
var crdOrganizationPatternFiles = []string{
	"../../config/crd/bases/kagi.pw_kagisecrets.yaml",
	"../../config/crd/bases/kagi.pw_kagicertificates.yaml",
	"../../charts/kagi-operator/templates/crds/kagisecrets.yaml",
	"../../charts/kagi-operator/templates/crds/kagicertificates.yaml",
}

// The CRD schema must accept exactly what ValidateOrganizationID accepts: a
// canonical UUID, or the empty string meaning "no cross-check". If the two drift,
// one of the two paths that can set spec.organization -- kubectl apply and
// kagi-init's flag -- starts admitting a value the other refuses, and the
// difference only shows up as a 403 loop or a cross-check that never runs.
func TestCRDOrganizationPatternMatchesValidator(t *testing.T) {
	want := "pattern: ^$|" + organizationIDPattern.String()

	for _, path := range crdOrganizationPatternFiles {
		t.Run(filepath.Base(filepath.Dir(path))+"/"+filepath.Base(path), func(t *testing.T) {
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read %s: %v", path, err)
			}
			content := string(raw)
			count := strings.Count(content, want)
			if count != 1 {
				t.Fatalf("%s: found %d occurrences of %q, want exactly 1 "+
					"(regenerate with `make manifests` and copy the schema into the chart CRD)",
					path, count, want)
			}
		})
	}
}

// The empty-string alternative is load-bearing: a chart that templates
// `organization: {{ .Values.kagi.organization }}` with no value emits
// `organization: ""`, which every install relies on meaning "use the token's
// bound organization". A pattern without it would reject those objects at
// admission on the next apply.
func TestEmptyOrganizationIDStaysValid(t *testing.T) {
	if err := ValidateOrganizationID(""); err != nil {
		t.Fatalf(`ValidateOrganizationID("") = %v, want nil`, err)
	}
	for _, path := range crdOrganizationPatternFiles {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		if !strings.Contains(string(raw), "pattern: ^$|") {
			t.Errorf("%s: organization pattern does not allow the empty string", path)
		}
	}
}
