package server

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

	"gopkg.in/yaml.v3"

	"github.com/deevnet/deevnet-provisioning-api/internal/tenant"
)

// The published reference is rendered from api/openapi.yaml, which is written
// by hand: the mux has no route list to generate one from. These tests are
// what keep it honest. A route or a wire field added here without the spec, or
// documented there without the code, fails the build.

const specPath = "../../api/openapi.yaml"

type openAPISpec struct {
	Paths      map[string]map[string]yaml.Node `yaml:"paths"`
	Components struct {
		Schemas map[string]struct {
			Required   []string             `yaml:"required"`
			Properties map[string]yaml.Node `yaml:"properties"`
		} `yaml:"schemas"`
	} `yaml:"components"`
}

func loadSpec(t *testing.T) openAPISpec {
	t.Helper()
	raw, err := os.ReadFile(specPath)
	if err != nil {
		t.Fatal(err)
	}
	var spec openAPISpec
	if err := yaml.Unmarshal(raw, &spec); err != nil {
		t.Fatalf("%s: %v", specPath, err)
	}
	return spec
}

// registeredRoutes reads the method patterns out of this package's source.
// ServeMux cannot list what it holds, and reading the source keeps the test
// from needing a configured tenant service to see the tenant routes.
func registeredRoutes(t *testing.T) []string {
	t.Helper()
	pkgs, err := parser.ParseDir(token.NewFileSet(), ".", func(fi os.FileInfo) bool {
		return !strings.HasSuffix(fi.Name(), "_test.go")
	}, 0)
	if err != nil {
		t.Fatal(err)
	}
	var routes []string
	for _, pkg := range pkgs {
		for _, file := range pkg.Files {
			ast.Inspect(file, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok || len(call.Args) == 0 {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok || (sel.Sel.Name != "HandleFunc" && sel.Sel.Name != "Handle") {
					return true
				}
				lit, ok := call.Args[0].(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					t.Errorf("a route pattern that is not a string literal cannot be checked against the spec")
					return true
				}
				pattern, err := strconv.Unquote(lit.Value)
				if err != nil {
					t.Fatal(err)
				}
				// The one pattern with no method: the /v1/ subtree, mounted
				// behind the token and ending in the 501 catch-all.
				if pattern == "/v1/" {
					return true
				}
				routes = append(routes, pattern)
				return true
			})
		}
	}
	sort.Strings(routes)
	return routes
}

func TestOpenAPIRoutesMatchTheMux(t *testing.T) {
	var documented []string
	for path, item := range loadSpec(t).Paths {
		for key := range item {
			switch key {
			case "get", "put", "post", "delete", "patch", "head", "options":
				documented = append(documented, strings.ToUpper(key)+" "+path)
			}
		}
	}
	sort.Strings(documented)

	registered := registeredRoutes(t)
	if len(registered) == 0 {
		t.Fatal("found no routes in the source; the scan is broken")
	}
	inSpec := map[string]bool{}
	for _, r := range documented {
		inSpec[r] = true
	}
	inCode := map[string]bool{}
	for _, r := range registered {
		inCode[r] = true
		if !inSpec[r] {
			t.Errorf("%s is served but not in %s", r, specPath)
		}
	}
	for _, r := range documented {
		if !inCode[r] {
			t.Errorf("%s is in %s but not served", r, specPath)
		}
	}
}

// wireSchemas pairs each wire type with the schema that documents it. A new
// request or response type belongs here, or its fields are unchecked.
var wireSchemas = map[string]any{
	"AdmissionRequest":     admitBody{},
	"TenantRequest":        createBody{},
	"TenantNetwork":        networkView{},
	"TenantFabric":         fabricView{},
	"TenantDNS":            dnsView{},
	"TenantState":          stateView{},
	"TenantLog":            logView{},
	"TenantDashboard":      dashboardView{},
	"TenantStep":           stepView{},
	"Tenant":               tenantView{},
	"WorkloadRequest":      workloadBody{},
	"Workload":             workloadView{},
	"RecordRequest":        recordBody{},
	"DeviceRequest":        deviceBody{},
	"Device":               deviceView{},
	"AddressRequest":       addressBody{},
	"Address":              addressView{},
	"WifiKeyRequest":       wifiKeyBody{},
	"WifiKey":              wifiKeyView{},
	"BrokerAccountRequest": brokerAccountBody{},
	"BrokerAccount":        brokerAccountView{},
	"EgressVRF":            tenant.EgressVRF{},
}

func TestOpenAPISchemasMatchTheWireTypes(t *testing.T) {
	schemas := loadSpec(t).Components.Schemas
	for name, v := range wireSchemas {
		schema, ok := schemas[name]
		if !ok {
			t.Errorf("schema %s is not in %s", name, specPath)
			continue
		}
		required := map[string]bool{}
		for _, f := range schema.Required {
			required[f] = true
		}
		typ := reflect.TypeOf(v)
		isResponse := !strings.HasSuffix(name, "Request")
		fields := map[string]bool{}
		for i := 0; i < typ.NumField(); i++ {
			tag := typ.Field(i).Tag.Get("json")
			field, opts, _ := strings.Cut(tag, ",")
			if field == "" || field == "-" {
				t.Errorf("%s.%s has no json name", typ.Name(), typ.Field(i).Name)
				continue
			}
			fields[field] = true
			if _, ok := schema.Properties[field]; !ok {
				t.Errorf("%s: field %q is on the wire but not in the schema", name, field)
			}
			// A response field without omitempty is always sent, and the
			// schema should promise as much. Requests are validated by the
			// service, whose rules the schema states by hand.
			if always := !strings.Contains(opts, "omitempty"); isResponse && always != required[field] {
				t.Errorf("%s: field %q always sent = %v, but required in the schema = %v", name, field, always, required[field])
			}
		}
		for field := range schema.Properties {
			if !fields[field] {
				t.Errorf("%s: property %q is in the schema but not on the wire", name, field)
			}
		}
	}
}
