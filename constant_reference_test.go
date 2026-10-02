// SPDX-License-Identifier: Apache-2.0
package gocrypto

import (
	"fmt"
	"go/ast"
	"go/constant"
	"go/parser"
	"go/token"
	"go/types"
	"testing"
)

// The independent reference uses the real go/types constant checker on trusted
// generated fixtures with no imports. It does not build or execute any fixture.
func TestConstantReferenceOracle(t *testing.T) {
	fixtures := []struct{ decl, expr, want string }{
		{"", "^uint16(0xfcfc)", "uint16"}, {"const a uint16=65535;const b=a+772;", "b-65535", "uint16"},
		{"", "uint8(1)==256", "bool"}, {"", "uint16(771)+uint32(0)", "uint16"},
		{"const a uint16=0xfcfc;", "^a", "uint16"}, {"", "int64(2048)", "int"},
		{"const a=1<<(10+iota);const b=a;", "b", "int"},
	}
	for a := 0; a < 8; a++ {
		for b := 0; b < 8; b++ {
			fixtures = append(fixtures, struct{ decl, expr, want string }{"", fmt.Sprintf("(%d<<%d)+1024", a, b), "int"})
		}
	}
	for _, tt := range fixtures {
		src := `package fixture;` + tt.decl + `func sink(v ` + tt.want + `){};func f(){sink(` + tt.expr + `)}`
		fs := token.NewFileSet()
		file, e := parser.ParseFile(fs, "fixture.go", src, parser.DeclarationErrors)
		if e != nil {
			t.Fatal(e)
		}
		var expr ast.Expr
		ast.Inspect(file, func(n ast.Node) bool {
			if c, ok := n.(*ast.CallExpr); ok {
				if id, ok := c.Fun.(*ast.Ident); ok && id.Name == "sink" {
					expr = c.Args[0]
				}
			}
			return true
		})
		info := types.Info{Types: map[ast.Expr]types.TypeAndValue{}}
		cfg := types.Config{Error: func(error) {}}
		_, oracleError := cfg.Check("fixture", fs, []*ast.File{file}, &info)
		f := &fileReview{r: newReport(standard(), DefaultLimits()), index: 1, fset: fs, file: file, imports: map[string]string{}, bindings: map[*ast.Object]binding{}, writes: map[*ast.Object]bool{}, escaped: map[*ast.Object]bool{}, constantTypes: map[ast.Expr]constantType{}}
		f.collect()
		var known bool
		var got constant.Value
		if tt.want == "bool" {
			v, k := f.boolean(expr)
			known = k
			got = constant.MakeBool(v)
		} else {
			v, k := f.policyInteger(expr, tt.want)
			known = k
			got = constant.MakeInt64(v)
		}
		oracle := info.Types[expr].Value
		if oracleError != nil {
			if known {
				t.Fatalf("invalid fixture was resolved: %s", tt.expr)
			}
			continue
		}
		if oracle == nil || !known || !constant.Compare(got, token.EQL, oracle) {
			t.Fatalf("constant mismatch %s: %v vs %v", tt.expr, got, oracle)
		}
	}
}
func TestGenericRandomAndFunctionValueRemainOpen(t *testing.T) {
	for _, src := range []string{`package p;import("math/rand/v2";"crypto/tls");var c=tls.Config{MinVersion:tls.VersionTLS12};var x=rand.N[int](10)`, `package p;import("math/rand";"crypto/tls");var c=tls.Config{MinVersion:tls.VersionTLS12};var f=rand.Intn;var x=f(10)`} {
		if r := analyze(src, standard()); r.Status != Open || r.FindingCount != 0 {
			t.Fatal(string(r.JSON()))
		}
	}
}
func TestTargetSourceIsNeverExecuted(t *testing.T) {
	src := `package p;import("os";"crypto/tls");func init(){panic("DO_NOT_EXECUTE");os.WriteFile("DO_NOT_WRITE",nil,0600)};var c=tls.Config{MinVersion:tls.VersionTLS12}`
	if r := analyze(src, standard()); r.Status != Pass {
		t.Fatal(string(r.JSON()))
	}
}
func TestServerSkipVerifyAndTargetDebugAreOpen(t *testing.T) {
	o := standard()
	o.TLSRole = "server"
	r := analyze(tlsSrc("InsecureSkipVerify:true,MinVersion:tls.VersionTLS12"), o)
	if r.Status != Open || r.FindingCount != 0 || !contains(r, "server_skip_verify_effect_unassessed") {
		t.Fatal(string(r.JSON()))
	}
	if r := analyze("//go:debug tls10server=1\n"+tlsSrc("MinVersion:tls.VersionTLS12"), standard()); r.Status != Open || !contains(r, "target_debug_directive_not_evaluated") {
		t.Fatal(string(r.JSON()))
	}
}
func TestCrossFileBuiltinShadowCannotBecomePass(t *testing.T) {
	for _, tt := range []struct{ a, b string }{{`package p;const false=true`, tlsSrc("InsecureSkipVerify:false,MinVersion:tls.VersionTLS12")}, {`package p;type uint16 int`, tlsSrc("MinVersion:uint16(771)")}, {`package p;var nil=custom`, `package p;import "crypto/ed25519";func f(){ed25519.GenerateKey(nil)}`}} {
		r := Review([][]byte{[]byte(tt.a), []byte(tt.b)}, standard(), DefaultLimits())
		if r.Status != Open || r.FindingCount != 0 || !contains(r, "cross_file_builtin_shadow_unresolved") {
			t.Fatal(string(r.JSON()))
		}
	}
}

func TestPortableArchitectureConstantOracle(t *testing.T) {
	for _, tt := range []struct {
		expr, status string
		known        bool
	}{
		{`(^uint(0)>>32)!=0`, Open, false},
		{`(^uint32(0)>>32)!=0`, Pass, true},
		{`(^uint64(0)>>32)!=0`, Fail, true},
		{`(uint(1)<<32)!=0`, Open, false},
		{`(int(1)<<32)!=0`, Open, false},
		{`uint(0xffffffff)==0xffffffff`, Fail, true},
		{`(^int(0)>>32)!=0`, Fail, true},
	} {
		var refs []constant.Value
		for _, arch := range []string{"386", "amd64"} {
			fs := token.NewFileSet()
			file, err := parser.ParseFile(fs, "fixture.go", `package p; const skip=`+tt.expr, parser.DeclarationErrors)
			if err != nil {
				t.Fatal(err)
			}
			expr := file.Decls[0].(*ast.GenDecl).Specs[0].(*ast.ValueSpec).Values[0]
			info := types.Info{Types: map[ast.Expr]types.TypeAndValue{}}
			cfg := types.Config{Sizes: types.SizesFor("gc", arch), Error: func(error) {}}
			_, oracleError := cfg.Check("fixture", fs, []*ast.File{file}, &info)
			if oracleError != nil {
				refs = append(refs, nil)
			} else {
				refs = append(refs, info.Types[expr].Value)
			}
			f := &fileReview{r: newReport(standard(), DefaultLimits()), index: 1, fset: fs, file: file, imports: map[string]string{}, bindings: map[*ast.Object]binding{}, writes: map[*ast.Object]bool{}, escaped: map[*ast.Object]bool{}, constantTypes: map[ast.Expr]constantType{}}
			f.collect()
			got, known := f.boolean(expr)
			if known != tt.known || (known && (oracleError != nil || refs[len(refs)-1] == nil || got != constant.BoolVal(refs[len(refs)-1]))) {
				t.Fatalf("%s on %s: analyzer (%v,%v), oracle %v/error %v", tt.expr, arch, got, known, refs[len(refs)-1], oracleError)
			}
		}
		if tt.known && !constant.Compare(refs[0], token.EQL, refs[1]) {
			t.Fatalf("resolved architecture-dependent expression %s", tt.expr)
		}
		r := analyze(tlsSrc("InsecureSkipVerify:"+tt.expr+",MinVersion:tls.VersionTLS12"), standard())
		if r.Status != tt.status {
			t.Fatalf("%s: %s", tt.expr, r.JSON())
		}
	}
}
