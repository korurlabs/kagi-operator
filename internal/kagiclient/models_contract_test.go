package kagiclient

import (
	"encoding/json"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// Contract tests for the models of this package against the committed operator bundle, the
// spec slice zz_generated_api.go is generated from. The SDK twin is
// projects/kagi/cli/sdk/models_contract_test.go; the operator never imports the SDK, so the two are
// deliberately separate copies rather than a shared helper.
//
// Two kinds of drift are caught here:
//
//   - an exported name that stops being an alias of its generated model, and so starts reading a
//     field the backend no longer sends (or never sent);
//   - KagiProblem, the Problem Details body every error answer carries, drifting from the bundle's
//     schema, or failing to decode the shape the backend really sends.
const (
	// contractSpecPath is contract/clients/operator.json, relative to this package.
	contractSpecPath = "../../contract/clients/operator.json"
	// problemSchemaName is the Problem Details schema of every error response.
	problemSchemaName = "KagiProblem"
)

// specSchema is the part of a component schema these tests read.
type specSchema struct {
	Properties map[string]json.RawMessage `json:"properties"`
	Required   []string                   `json:"required"`
}

// readSpecSchema returns one component schema of the committed spec.
func readSpecSchema(t *testing.T, name string) specSchema {
	t.Helper()

	raw, err := os.ReadFile(contractSpecPath)
	if err != nil {
		t.Fatalf("read %s: %v", contractSpecPath, err)
	}
	var spec struct {
		Components struct {
			Schemas map[string]specSchema `json:"schemas"`
		} `json:"components"`
	}
	if err := json.Unmarshal(raw, &spec); err != nil {
		t.Fatalf("parse %s: %v", contractSpecPath, err)
	}
	schema, ok := spec.Components.Schemas[name]
	if !ok {
		t.Fatalf("%s has no component schema %s", contractSpecPath, name)
	}
	return schema
}

// jsonTags returns the JSON field names of a struct type, and reports any that carry omitempty.
// Every property of a Kagi response is present on the wire — the backend serializes an absent value
// as null rather than dropping the key (plan 05 §3.4.1) — so omitempty on a wire model would hide a
// field the contract says is always there.
func jsonTags(t *testing.T, value any) ([]string, []string) {
	t.Helper()

	structType := reflect.TypeOf(value)
	if structType.Kind() != reflect.Struct {
		t.Fatalf("%T is not a struct", value)
	}

	tags := make([]string, 0, structType.NumField())
	var omitEmpty []string
	for field := range structType.Fields() {
		tag, declared := field.Tag.Lookup("json")
		if !declared {
			t.Fatalf("%s.%s has no json tag", structType.Name(), field.Name)
		}
		name, options, _ := strings.Cut(tag, ",")
		if name == "-" {
			continue
		}
		if strings.Contains(options, "omitempty") {
			omitEmpty = append(omitEmpty, name)
		}
		tags = append(tags, name)
	}
	sort.Strings(tags)
	sort.Strings(omitEmpty)
	return tags, omitEmpty
}

// requiredSorted returns the schema's required members, sorted.
func requiredSorted(schema specSchema) []string {
	required := append([]string(nil), schema.Required...)
	sort.Strings(required)
	return required
}

func TestProblem_MatchesTheBundledSchema(t *testing.T) {
	schema := readSpecSchema(t, problemSchemaName)

	wire := make([]string, 0, len(schema.Properties))
	for property := range schema.Properties {
		wire = append(wire, property)
	}
	sort.Strings(wire)

	got, omitEmpty := jsonTags(t, KagiProblem{})
	if strings.Join(got, ",") != strings.Join(wire, ",") {
		t.Errorf("KagiProblem json tags = %v, %s properties = %v; run make api-generate", got, problemSchemaName, wire)
	}

	optional := map[string]bool{}
	for _, name := range omitEmpty {
		optional[name] = true
	}
	var always []string
	for _, name := range got {
		if !optional[name] {
			always = append(always, name)
		}
	}
	if want := requiredSorted(schema); strings.Join(always, ",") != strings.Join(want, ",") {
		t.Errorf("KagiProblem always-present members = %v, %s required = %v", always, problemSchemaName, want)
	}

	// APIError reads code, detail and title; each must stay in the schema.
	for _, member := range []string{"code", "detail", "title"} {
		if _, ok := schema.Properties[member]; !ok {
			t.Errorf("%s has no %s member, which APIError reads", problemSchemaName, member)
		}
	}
}

// TestProblem_DecodesAFailureBody decodes a body of the shape the backend sends
// on a refusal, including an errorValues map with scalar values (a Java
// Map<String, Object>, additionalProperties: true in the spec).
func TestProblem_DecodesAFailureBody(t *testing.T) {
	body := []byte(`{
		"type": "urn:kagi:error:GEN_SEC_002",
		"title": "Access forbidden.",
		"status": 403,
		"detail": "No access to library SECRETS.",
		"instance": "/kagi/folders/secrets/children/fepatex",
		"code": "GEN_SEC_002",
		"errorValues": {"library": "SECRETS", "attempts": 3}
	}`)

	var problem KagiProblem
	if err := json.Unmarshal(body, &problem); err != nil {
		t.Fatalf("decode problem: %v", err)
	}
	if problem.Code != "GEN_SEC_002" || problem.Status != 403 || problem.Title != "Access forbidden." {
		t.Errorf("problem = %+v", problem)
	}
	if problem.ErrorValues == nil {
		t.Fatal("ErrorValues = nil, want the two keys the body carries")
	}
	values := *problem.ErrorValues
	if values["library"] != "SECRETS" || values["attempts"] != float64(3) {
		t.Errorf("ErrorValues = %v", values)
	}

	apiErr := newAPIError(403, body)
	if apiErr.Code != "GEN_SEC_002" || apiErr.Message != "No access to library SECRETS." {
		t.Errorf("newAPIError = %+v, want code GEN_SEC_002 and the detail as message", apiErr)
	}
}

// wireModels is one row per name this package exports for a generated wire model: the exported
// name, the generated type it must resolve to, and a zero value of each so the tests can read their
// JSON tags by reflection.
//
// Each exported name must stay an alias (type X = Y), never a re-declared struct: a copy would drift
// from the backend DTO silently, and that is exactly what plan 05 removes. Once a name is an alias
// the subset check below is trivially true, which is the point — it fails the moment someone turns
// one back into a struct and gives it a field the backend does not send. A batch that aliases
// another model adds a row here.
var wireModels = []struct {
	exported      string
	generated     string
	exportedZero  any
	generatedZero any
}{
	{"App", "FolderAppResponse", App{}, FolderAppResponse{}},
	{"Folder", "FolderResponse", Folder{}, FolderResponse{}},
	{"FolderChildren", "FolderChildrenResponse", FolderChildren{}, FolderChildrenResponse{}},
	{"Environment", "KagiEnvironmentListResponse", Environment{}, KagiEnvironmentListResponse{}},
	{"SecretFetchResponse", "KagiSecretFetchResponse", SecretFetchResponse{}, KagiSecretFetchResponse{}},
	{"SecretVersionResponse", "KagiSecretVersionResponse", SecretVersionResponse{}, KagiSecretVersionResponse{}},
	{"CertificateResolveResponse", "KagiCertificateResolveResponse", CertificateResolveResponse{}, KagiCertificateResolveResponse{}},
}

func TestWireModels_ResolveToTheGeneratedType(t *testing.T) {
	for _, model := range wireModels {
		got := reflect.TypeOf(model.exportedZero).Name()
		if got != model.generated {
			t.Errorf("%s resolves to type %s, want the generated %s. "+
				"Re-declaring it as a struct hand-writes a wire shape; keep it as `type %s = %s`.",
				model.exported, got, model.generated, model.exported, model.generated)
		}
	}
}

func TestWireModels_TagsAreASubsetOfTheGenerated(t *testing.T) {
	for _, model := range wireModels {
		exported, _ := jsonTags(t, model.exportedZero)
		generated, _ := jsonTags(t, model.generatedZero)

		known := make(map[string]bool, len(generated))
		for _, tag := range generated {
			known[tag] = true
		}

		var extra []string
		for _, tag := range exported {
			if !known[tag] {
				extra = append(extra, tag)
			}
		}
		if len(extra) > 0 {
			t.Errorf("%s reads %v, which %s does not carry. The backend does not send those fields; "+
				"fix the DTO or drop them here.", model.exported, extra, model.generated)
		}
	}
}

// Compile-time proof that the aliases are assignable both ways. A re-declared struct would fail here
// before any test runs.
var (
	_ FolderResponse                 = Folder{}
	_ Folder                         = FolderResponse{}
	_ FolderAppResponse              = App{}
	_ FolderChildrenResponse         = FolderChildren{}
	_ KagiCertificateResolveResponse = CertificateResolveResponse{}
)
