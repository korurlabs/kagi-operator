package kagiclient

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// The generator is the only writer of a wire shape in this package (plan 05
// §6.6, workstream W9g; api-contract-convention "Absolute rule").
//
// models_contract_test.go beside this file proves that the models this client HAS
// adopted really are aliases of their generated counterparts, row by row. It
// cannot see a model nobody added a row for, which is the regression that
// matters: a hand-written struct that quietly re-declares a shape the backend
// already describes drifts from the DTO with nothing to notice, and that is
// exactly what plan 05 exists to remove.
//
// Three gates here, in increasing order of how much they actually bite:
//
//  1. NAME. No hand-written struct may take a name zz_generated_api.go declares,
//     nor the name that file's model would obviously be aliased under -- the same
//     name without the backend's "Kagi" prefix, without its "Response"/"Request"
//     suffix, or without both. The exact-name case is also a Go redeclaration
//     error, so the compiler would catch it first; the NEAR-name case is the one
//     that compiles, and it is how a shadow survives adoption. The moment a
//     schema joins the operator bundle while its hand-written copy stays, this
//     fails and names both sides.
//
//  2. FIELD SET. No hand-written struct may carry exactly the JSON field names of
//     a generated model, whatever it is called. This is the name-independent form
//     of the same defect: renaming the copy does not make it less of a copy.
//
//  3. INVENTORY. Every hand-written struct in this package that carries JSON tags
//     is a wire shape by definition, so each one is pinned below with the reason
//     it is not generated yet. Adding a hand-written wire struct therefore takes
//     an explicit, reviewed edit to this file. Structs with no JSON tags are not
//     wire shapes and are not pinned -- Client, APIError, StaticTokenSource and
//     WorkloadTokenSource are all internal state, never decoded from a
//     response.
//
// Parsing is go/ast rather than a line scan. `type (...)` groups, embedded
// fields, and struct literals inside function bodies all read as `struct {` to a
// regex, and a scan that misreads them is a gate that passes for the wrong
// reason.
//
// The sibling copy in the SDK (projects/kagi/cli/sdk/wire_structs_contract_test.go)
// is deliberate duplication, not an oversight: the two are separate Go modules
// and the SDK must import only the standard library, so there is no shared helper
// package either of them could take this from.

// generatedModelsFile is the oapi-codegen output of this package, written by
// `make api-generate` from projects/kagi/contract/clients/operator.json.
const generatedModelsFile = "zz_generated_api.go"

// declaredTypes is the top-level type declarations of one group of files: every
// type name that group declares, mapped to the file declaring it, and the sorted
// JSON field names of those that are structs CARRYING JSON TAGS.
//
// jsonTags is deliberately the narrower map. A struct with no JSON tag is not a
// wire shape, so the inventory gate must not ask for a row for one.
//
// A type ALIAS (type X = Y) is in neither map. It declares no new shape, which is
// precisely why every adopted model in models.go is one.
type declaredTypes struct {
	fileOf   map[string]string
	jsonTags map[string][]string
}

// parsePackageTypes reads this package's directory and splits its top-level type
// declarations into the generated file's and the hand-written files'. Test files
// are excluded from both: a fixture struct is not a shipped wire shape.
func parsePackageTypes(t *testing.T) (generated, handWritten declaredTypes) {
	t.Helper()

	generated = declaredTypes{fileOf: map[string]string{}, jsonTags: map[string][]string{}}
	handWritten = declaredTypes{fileOf: map[string]string{}, jsonTags: map[string][]string{}}

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package directory: %v", err)
	}

	fset := token.NewFileSet()
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}

		file, err := parser.ParseFile(fset, name, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}

		target := &handWritten
		if name == generatedModelsFile {
			target = &generated
		}

		for _, decl := range file.Decls {
			genDecl, ok := decl.(*ast.GenDecl)
			if !ok || genDecl.Tok != token.TYPE {
				continue
			}
			for _, spec := range genDecl.Specs {
				typeSpec, ok := spec.(*ast.TypeSpec)
				if !ok || typeSpec.Assign.IsValid() {
					continue
				}
				target.fileOf[typeSpec.Name.Name] = name
				structType, ok := typeSpec.Type.(*ast.StructType)
				if !ok {
					continue
				}
				if tags := structJSONFieldNames(t, structType); len(tags) > 0 {
					target.jsonTags[typeSpec.Name.Name] = tags
				}
			}
		}
	}
	return generated, handWritten
}

// structJSONFieldNames returns the sorted JSON field names of a parsed struct
// type. A field tagged json:"-" is not on the wire and is skipped; an embedded
// field carries no name and no tag in this package and is skipped too.
func structJSONFieldNames(t *testing.T, structType *ast.StructType) []string {
	t.Helper()

	var names []string
	for _, field := range structType.Fields.List {
		if len(field.Names) == 0 || field.Tag == nil {
			continue
		}
		raw, err := strconv.Unquote(field.Tag.Value)
		if err != nil {
			t.Fatalf("unquote struct tag %s: %v", field.Tag.Value, err)
		}
		name, _, _ := strings.Cut(reflect.StructTag(raw).Get("json"), ",")
		if name == "" || name == "-" {
			continue
		}
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// generatedModelAliases returns the names a hand-written struct could plausibly
// be a shadow of for one generated type: the generated name itself, and the forms
// it loses when a caller-friendly alias is derived from it. The backend DTO names
// carry a "Kagi" prefix and a "Response"/"Request" suffix that this client's
// public names drop -- Folder for FolderResponse, Environment for
// KagiEnvironmentListResponse -- so those are the shapes a shadow takes.
func generatedModelAliases(name string) []string {
	stems := []string{name}
	if trimmed, ok := strings.CutPrefix(name, "Kagi"); ok && trimmed != "" {
		stems = append(stems, trimmed)
	}

	var forms []string
	for _, stem := range stems {
		forms = append(forms, stem)
		for _, suffix := range []string{"Response", "Request"} {
			if trimmed, ok := strings.CutSuffix(stem, suffix); ok && trimmed != "" {
				forms = append(forms, trimmed)
			}
		}
	}
	return forms
}

// handWrittenWireStructs is the pinned inventory of gate 3: every hand-written
// struct in this package that carries JSON tags, with the reason it is not
// generated. A row is a deferral, not an endorsement. Every wire shape the
// operator reads or sends is in its bundle today, so the inventory is empty.
var handWrittenWireStructs = map[string]string{}

// TestWireStructScanSeesBothSides asserts the scan found something before any
// gate asserts anything about what it found. A coverage gate whose directory walk
// matched nothing passes silently, and that is the way this kind of test fails.
func TestWireStructScanSeesBothSides(t *testing.T) {
	generated, handWritten := parsePackageTypes(t)

	if len(generated.fileOf) == 0 {
		t.Fatalf("no type declarations found in %s; the file, the directory or the parse is wrong, not the tree", generatedModelsFile)
	}
	for _, anchor := range []string{"FolderResponse", "KagiProblem", "CertificateEntry"} {
		if _, ok := generated.fileOf[anchor]; !ok {
			t.Errorf("%s declares no %s; the scan is reading the wrong file", generatedModelsFile, anchor)
		}
	}
	if len(handWritten.fileOf) == 0 {
		t.Fatal("no hand-written type declarations found in this package; the scan is broken")
	}
	// Client and APIError are hand-written structs in client.go; a scan that
	// misses them is reading the wrong files.
	for _, anchor := range []string{"Client", "APIError"} {
		if handWritten.fileOf[anchor] != "client.go" {
			t.Errorf("the hand-written scan found %s in %q, want client.go", anchor, handWritten.fileOf[anchor])
		}
	}
}

func TestNoHandWrittenStructTakesAGeneratedModelName(t *testing.T) {
	generated, handWritten := parsePackageTypes(t)

	// Candidate name -> the generated type it would shadow. First writer wins; the
	// generated names are distinct and their alias forms do not collide today.
	shadowOf := map[string]string{}
	for name := range generated.fileOf {
		for _, candidate := range generatedModelAliases(name) {
			if _, taken := shadowOf[candidate]; !taken {
				shadowOf[candidate] = name
			}
		}
	}

	names := make([]string, 0, len(handWritten.fileOf))
	for name := range handWritten.fileOf {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		model, shadowed := shadowOf[name]
		if !shadowed {
			continue
		}
		t.Errorf("%s declares struct %s, which shadows the generated %s. "+
			"The generator is the only writer of a wire shape: delete the struct and alias the generated type "+
			"(type %s = %s), or, if it is genuinely a different shape, rename it so the two cannot be confused.",
			handWritten.fileOf[name], name, model, name, model)
	}
}

func TestNoHandWrittenStructDuplicatesAGeneratedFieldSet(t *testing.T) {
	generated, handWritten := parsePackageTypes(t)

	// Three fields is the floor for calling an identical field set a copy rather
	// than a coincidence. Below it, two unrelated shapes really can share their
	// field names -- {"id","name"} says nothing.
	const minimumFields = 3

	byFieldSet := map[string]string{}
	for name, tags := range generated.jsonTags {
		if len(tags) < minimumFields {
			continue
		}
		byFieldSet[strings.Join(tags, ",")] = name
	}

	names := make([]string, 0, len(handWritten.jsonTags))
	for name := range handWritten.jsonTags {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		tags := handWritten.jsonTags[name]
		if len(tags) < minimumFields {
			continue
		}
		model, duplicated := byFieldSet[strings.Join(tags, ",")]
		if !duplicated {
			continue
		}
		t.Errorf("%s declares struct %s with exactly the JSON fields of the generated %s (%v). "+
			"Renaming a copy does not stop it drifting from the backend DTO: alias the generated type instead.",
			handWritten.fileOf[name], name, model, tags)
	}
}

func TestHandWrittenWireStructsArePinned(t *testing.T) {
	_, handWritten := parsePackageTypes(t)

	names := make([]string, 0, len(handWritten.jsonTags))
	for name := range handWritten.jsonTags {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		if _, pinned := handWrittenWireStructs[name]; pinned {
			continue
		}
		t.Errorf("%s declares struct %s with JSON tags, which makes it a wire shape, and nothing sanctions it. "+
			"Generate it instead: tag its operation with x-kagi-clients operator, rebundle, run `make api-generate`, and "+
			"alias the generated type. If it cannot be generated, add a row to handWrittenWireStructs here saying why, and say "+
			"the same in a doc comment on the struct.",
			handWritten.fileOf[name], name)
	}

	pinned := make([]string, 0, len(handWrittenWireStructs))
	for name := range handWrittenWireStructs {
		pinned = append(pinned, name)
	}
	sort.Strings(pinned)

	for _, name := range pinned {
		if _, declared := handWritten.jsonTags[name]; !declared {
			t.Errorf("handWrittenWireStructs pins %s, but this package declares no hand-written struct of that name "+
				"with JSON tags. If it became an alias of a generated model, the deferral is done -- delete the row.", name)
		}
	}
}
