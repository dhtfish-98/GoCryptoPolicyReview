// SPDX-License-Identifier: Apache-2.0
package gocrypto

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func analyze(src string, o Options) *Report { return Review([][]byte{[]byte(src)}, o, DefaultLimits()) }
func standard() Options {
	return Options{GoMinor: 26, TLSRole: "client", TLSDefaults: "standard", CryptoRandom: "standard"}
}
func oldGo() Options {
	return Options{GoMinor: 25, TLSRole: "client", TLSDefaults: "standard", CryptoRandom: "standard"}
}
func has(r *Report, rule, status string) bool {
	for _, v := range r.Results {
		if v.Rule == rule && v.Status == status {
			return true
		}
	}
	return false
}
func contains(r *Report, reason string) bool {
	for _, v := range r.Unknowns {
		if v == reason {
			return true
		}
	}
	for _, v := range r.Results {
		if v.Reason == reason {
			return true
		}
	}
	return false
}
func tlsSrc(fields string) string {
	return `package p; import "crypto/tls"; var c=tls.Config{` + fields + `}`
}
func rsaSrc(bits string) string {
	return `package p; import("crypto/rsa";"crypto/rand");func f(){_,_=rsa.GenerateKey(rand.Reader,` + bits + `)}`
}

func TestTLSBooleanExpressions(t *testing.T) {
	for _, tt := range []struct{ expr, status string }{{"true", Fail}, {"false", Pass}, {"!true", Pass}, {"!false", Fail}, {"true == false", Pass}, {"false || true", Fail}, {"flag", Open}} {
		t.Run(tt.expr, func(t *testing.T) {
			r := analyze(tlsSrc("InsecureSkipVerify:"+tt.expr+",MinVersion:tls.VersionTLS12"), standard())
			if !has(r, "tls_verify", tt.status) {
				t.Fatal(r.JSON())
			}
		})
	}
}
func TestTLSConstantAndMutableBindings(t *testing.T) {
	for _, tt := range []struct{ decl, expr, status string }{{"const b = !false;", "b", Fail}, {"var b = true;", "b", Open}, {"const true = false;", "true", Pass}, {"const b = external;", "b", Open}} {
		src := `package p;import "crypto/tls";` + tt.decl + `var c=tls.Config{InsecureSkipVerify:` + tt.expr + `,MinVersion:tls.VersionTLS12}`
		if r := analyze(src, standard()); !has(r, "tls_verify", tt.status) {
			t.Fatal(tt, r.JSON())
		}
	}
}
func TestTLSMinimumKnownAndUnknown(t *testing.T) {
	for _, tt := range []struct{ expr, status string }{{"tls.VersionSSL30", Fail}, {"tls.VersionTLS10", Fail}, {"tls.VersionTLS11", Fail}, {"tls.VersionTLS12", Pass}, {"tls.VersionTLS13", Pass}, {"0x303", Pass}, {"768+3", Pass}, {"65535", Open}, {"uint16(65536+771)", Open}, {"dynamic()", Open}, {"0", Pass}} {
		r := analyze(tlsSrc("MinVersion:"+tt.expr), standard())
		if !has(r, "tls_minimum", tt.status) {
			t.Fatal(tt, r.JSON())
		}
	}
}
func TestTLSDefaultsRequireAssertions(t *testing.T) {
	for _, tt := range []struct {
		o      Options
		status string
	}{{Options{}, Open}, {Options{GoMinor: 25}, Open}, {Options{GoMinor: 26, TLSRole: "server"}, Open}, {Options{GoMinor: 22, TLSRole: "server", TLSDefaults: "standard"}, Pass}, {Options{GoMinor: 26, TLSRole: "server", TLSDefaults: "server_legacy"}, Fail}, {Options{GoMinor: 22, TLSRole: "client"}, Pass}} {
		if r := analyze(tlsSrc(""), tt.o); !has(r, "tls_minimum", tt.status) {
			t.Fatal(tt, r.JSON())
		}
	}
}
func TestTLSAliasesAndLexicalShadowing(t *testing.T) {
	src := `package p;import wire "crypto/tls";type C=wire.Config;var c=C{InsecureSkipVerify:true,MinVersion:wire.VersionTLS12}`
	if r := analyze(src, standard()); !has(r, "tls_verify", Fail) {
		t.Fatal(r.JSON())
	}
	src = `package p;import wire "crypto/tls";func f(wire struct{ Config func() int }){_ = wire.Config()}`
	if r := analyze(src, standard()); r.FindingCount != 0 || r.Status != Open {
		t.Fatal(r.JSON())
	}
}
func TestTLSFieldAssignmentsAndZeroInitializers(t *testing.T) {
	for _, decl := range []string{`var c tls.Config`, `c:=new(tls.Config)`, `c:=&tls.Config{MinVersion:tls.VersionTLS12}`} {
		src := `package p;import "crypto/tls";func f(){` + decl + `;c.InsecureSkipVerify=true}`
		if r := analyze(src, standard()); !has(r, "tls_verify", Fail) {
			t.Fatal(decl, r.JSON())
		}
	}
	if r := analyze(`package p;import "crypto/tls";func f(c *tls.Config){c.MinVersion=tls.VersionTLS10}`, standard()); !has(r, "tls_minimum", Fail) {
		t.Fatal(r.JSON())
	}
	if r := analyze(`package p;import "crypto/tls";var c tls.Config`, Options{}); !contains(r, "tls_default_assertions_missing") {
		t.Fatal(r.JSON())
	}
}
func TestTLSUnknownAndInvalidShapes(t *testing.T) {
	for _, src := range []string{tlsSrc("true"), tlsSrc("MinVersion:tls.VersionTLS12,MinVersion:tls.VersionTLS13"), tlsSrc("MinVersion:tls.VersionTLS13,MaxVersion:tls.VersionTLS12"), tlsSrc("MinVersion:tls.VersionTLS12,MaxVersion:dynamic"), `package p;import "crypto/tls";type Other tls.Config;var c=Other{InsecureSkipVerify:true}`} {
		if r := analyze(src, standard()); r.Status != Open {
			t.Fatal(src, r.JSON())
		}
	}
}
func TestCustomVerificationIsUnassessed(t *testing.T) {
	r := analyze(tlsSrc("MinVersion:tls.VersionTLS12,InsecureSkipVerify:true,VerifyConnection:check"), standard())
	if !contains(r, "builtin_verification_disabled_custom_hook_unassessed") || r.RuntimeSecurity != Open {
		t.Fatal(r.JSON())
	}
}
func TestRSAIntegerExpressions(t *testing.T) {
	for _, tt := range []struct{ expr, status string }{{"1024", Fail}, {"1<<10", Fail}, {"2048", Pass}, {"4096", Pass}, {"(1<<12)/2", Pass}, {"2049%2048", Fail}, {"0x800", Pass}, {"0b100000000000", Pass}, {"2_048", Pass}, {"-1", Open}, {"0", Open}, {"1e3", Open}, {"1/0", Open}, {"1<<5000", Open}, {"uint8(2048)", Open}, {"unknown", Open}, {"cfg.Bits", Open}} {
		r := analyze(rsaSrc(tt.expr), standard())
		if !has(r, "rsa_bits", tt.status) {
			t.Fatal(tt, r.JSON())
		}
	}
}
func TestRSAConstantsAndIota(t *testing.T) {
	for _, tt := range []struct{ decl, expr, status string }{{"const bits=1<<10;", "bits", Fail}, {"var bits=1024;", "bits", Open}, {"const(a=1<<(10+iota);b);", "b", Pass}, {"const(a uint8=1<<iota;b;c;d;e;ff;g;h;i);", "i", Open}, {"const a=b; const b=a;", "a", Open}} {
		src := strings.Replace(rsaSrc(tt.expr), "func f()", tt.decl+"func f()", 1)
		if r := analyze(src, standard()); !has(r, "rsa_bits", tt.status) {
			t.Fatal(tt, r.JSON())
		}
	}
}
func TestRSAAliasesAndShadowing(t *testing.T) {
	src := `package p;import(k "crypto/rsa";r "crypto/rand");func f(){_,_=k.GenerateKey(r.Reader,1024)}`
	if r := analyze(src, standard()); !has(r, "rsa_bits", Fail) {
		t.Fatal(r.JSON())
	}
	src = `package p;import "crypto/rsa";func f(rsa struct{GenerateKey func(any,int)}){rsa.GenerateKey(nil,1024)}`
	if r := analyze(src, standard()); r.FindingCount != 0 || r.Status != Open {
		t.Fatal(r.JSON())
	}
}
func TestRSAInvalidArityAndMultiPrime(t *testing.T) {
	for _, body := range []string{"rsa.GenerateKey()", "rsa.GenerateKey(nil)", "rsa.GenerateKey(nil,1024,3)", "rsa.GenerateMultiPrimeKey(nil,2)"} {
		if r := analyze(`package p;import "crypto/rsa";func f(){`+body+`}`, standard()); r.Status != Open || r.FindingCount != 0 {
			t.Fatal(body, r.JSON())
		}
	}
	if r := analyze(`package p;import "crypto/rsa";func f(){rsa.GenerateMultiPrimeKey(nil,3,1024)}`, standard()); !has(r, "rsa_bits", Fail) {
		t.Fatal(r.JSON())
	}
}
func TestFunctionAliasIsOpen(t *testing.T) {
	src := `package p;import("crypto/tls";"crypto/rsa");var c=tls.Config{MinVersion:tls.VersionTLS12};func f(){g:=rsa.GenerateKey;g(nil,1024)}`
	if r := analyze(src, standard()); !contains(r, "selected_function_alias_unresolved") || r.Status != Open {
		t.Fatal(r.JSON())
	}
}
func readerSrc(pkg, call string) string {
	return `package p;import("math/rand";"crypto/` + pkg + `");func f(){r:=rand.New(rand.NewSource(7));` + call + `}`
}
func TestRandomSimulationIsNotFinding(t *testing.T) {
	for _, src := range []string{`package p;import "math/rand";var sample=rand.Intn(10)`, `package p;import r "math/rand/v2";var sample=r.IntN(10)`, `package p;import "math/rand";func f(){r:=rand.New(rand.NewSource(7));r.Intn(10)}`} {
		if r := analyze(src, oldGo()); r.FindingCount != 0 || r.Status != Open || !has(r, "random_observation", Open) {
			t.Fatal(r.JSON())
		}
	}
}
func TestReaderSecurityContextAndGo26Change(t *testing.T) {
	src := readerSrc("rsa", "rsa.GenerateKey(r,2048)")
	for _, tt := range []struct {
		o      Options
		status string
	}{{oldGo(), Fail}, {standard(), Pass}, {Options{GoMinor: 26, CryptoRandom: "custom"}, Fail}, {Options{GoMinor: 26}, Open}, {Options{}, Open}} {
		if r := analyze(src, tt.o); !has(r, "rsa_reader", tt.status) || (tt.status != Fail && r.FindingCount > 0) {
			t.Fatal(tt, r.JSON())
		}
	}
}
func TestECDSAUsesSecondReaderArgument(t *testing.T) {
	src := readerSrc("ecdsa", "ecdsa.GenerateKey(curve,r)")
	if r := analyze(src, oldGo()); !has(r, "ecdsa_reader", Fail) {
		t.Fatal(r.JSON())
	}
	if r := analyze(src, standard()); !has(r, "ecdsa_reader", Pass) {
		t.Fatal(r.JSON())
	}
}
func TestEd25519CustomReaderStillUsedIn26(t *testing.T) {
	if r := analyze(readerSrc("ed25519", "ed25519.GenerateKey(r)"), standard()); !has(r, "ed25519_reader", Fail) {
		t.Fatal(r.JSON())
	}
	if r := analyze(`package p;import "crypto/ed25519";func f(){ed25519.GenerateKey(nil)}`, standard()); !has(r, "ed25519_reader", Pass) {
		t.Fatal(r.JSON())
	}
}
func TestTLSRandVersionBoundary(t *testing.T) {
	src := `package p;import("math/rand";"crypto/tls");var c=tls.Config{MinVersion:tls.VersionTLS12,Rand:rand.New(rand.NewSource(7))}`
	if r := analyze(src, oldGo()); !has(r, "tls_entropy_reader", Fail) {
		t.Fatal(r.JSON())
	}
	if r := analyze(src, standard()); !has(r, "tls_entropy_reader", Fail) {
		t.Fatal(r.JSON())
	}
}
func TestReaderLocalSourceAliasAndMutation(t *testing.T) {
	src := `package p;import("math/rand";"crypto/ed25519");func f(){s:=rand.NewSource(1);r:=rand.New(s);ed25519.GenerateKey(r)}`
	if r := analyze(src, standard()); !has(r, "ed25519_reader", Fail) {
		t.Fatal(r.JSON())
	}
	for _, change := range []string{`r=unknown;`, `escape(&r);`, `s=unknown;`} {
		x := strings.Replace(src, "ed25519.GenerateKey(r)", change+"ed25519.GenerateKey(r)", 1)
		if r := analyze(x, standard()); r.FindingCount != 0 || r.Status != Open {
			t.Fatal(change, r.JSON())
		}
	}
}
func TestReadToAESExactObjectAndOrder(t *testing.T) {
	src := `package p;import("math/rand";"crypto/aes");func f(){key:=make([]byte,16);rand.Read(key);aes.NewCipher(key)}`
	if r := analyze(src, standard()); !has(r, "weak_bytes_to_aes_key", Fail) {
		t.Fatal(r.JSON())
	}
	reverse := strings.Replace(src, "rand.Read(key);aes.NewCipher(key)", "aes.NewCipher(key);rand.Read(key)", 1)
	if r := analyze(reverse, standard()); r.FindingCount != 0 || r.Status != Open {
		t.Fatal(r.JSON())
	}
}
func TestAESFlowInvalidation(t *testing.T) {
	for _, middle := range []string{`key=other;`, `key[0]=0;`, `wipe(key);`, `alias:=key;_ = alias;`, `if ok { wipe(key) };`, `go wipe(key);`} {
		src := `package p;import("math/rand";"crypto/aes");func f(){key:=make([]byte,16);rand.Read(key);` + middle + `aes.NewCipher(key)}`
		if r := analyze(src, standard()); r.FindingCount != 0 || r.Status != Open {
			t.Fatal(middle, r.JSON())
		}
	}
}
func TestAESFlowLexicalShadowAndControlFlow(t *testing.T) {
	for _, body := range []string{`rand.Read(key);{key:=other;aes.NewCipher(key)}`, `if ok {rand.Read(key)};aes.NewCipher(key)`, `rand.Read(key);return aes.NewCipher(key)`} {
		src := `package p;import("math/rand";"crypto/aes");func f(){key:=make([]byte,16);` + body + `}`
		if r := analyze(src, standard()); r.FindingCount != 0 || r.Status != Open {
			t.Fatal(body, r.JSON())
		}
	}
}
func TestCrossFileConstantsNeverMerged(t *testing.T) {
	r := Review([][]byte{[]byte(`package p;const bits=1024`), []byte(rsaSrc("bits"))}, standard(), DefaultLimits())
	if r.Status != Open || r.FindingCount != 0 || !has(r, "rsa_bits", Open) {
		t.Fatal(r.JSON())
	}
}
func TestPhysicalPositionsAndContentPrivacy(t *testing.T) {
	src := "package p\nimport \"crypto/tls\"\n//line /PRIVATE_PATH:999\nvar PRIVATE_NAME=tls.Config{InsecureSkipVerify:true,MinVersion:tls.VersionTLS12}\n// SECRET_TEXT\n"
	r := analyze(src, standard())
	for _, v := range r.Results {
		if v.Position.Line != 4 {
			t.Fatal(v)
		}
	}
	b := r.JSON()
	for _, marker := range []string{"PRIVATE_PATH", "PRIVATE_NAME", "SECRET_TEXT"} {
		if bytes.Contains(b, []byte(marker)) {
			t.Fatal(string(b))
		}
	}
}
func TestInvalidSourceAndDotImport(t *testing.T) {
	for _, src := range []string{`package p;var =`, `package p;import . "crypto/tls";var c=Config{InsecureSkipVerify:true}`, "package p\x00", "package p;var x=1١"} {
		if r := analyze(src, standard()); r.Status != Open {
			t.Fatal(r.JSON())
		}
	}
}
func TestInvalidUTF8AndInputBudgetDigest(t *testing.T) {
	r := Review([][]byte{{0xff}}, standard(), DefaultLimits())
	if !contains(r, "invalid_utf8") {
		t.Fatal(r.JSON())
	}
	l := DefaultLimits()
	l.FileBytes = 10
	r = Review([][]byte{bytes.Repeat([]byte("x"), 11)}, standard(), l)
	if r.Status != Open || len(r.Inputs) != 1 || r.Inputs[0].SHA256 != "" || r.Inputs[0].Status != Open {
		t.Fatal(r.JSON())
	}
}
func TestTokenDepthAndASTBudgets(t *testing.T) {
	for _, which := range []string{"tokens", "tokenbytes", "nesting", "astnodes", "evaluation"} {
		l := DefaultLimits()
		src := tlsSrc("InsecureSkipVerify:!false,MinVersion:tls.VersionTLS12")
		switch which {
		case "tokens":
			l.Tokens = 3
		case "tokenbytes":
			l.TokenBytes = 4
		case "nesting":
			l.Nesting = 1
		case "astnodes":
			l.ASTNodes = 4
		case "evaluation":
			l.EvalSteps = 1
		}
		if r := Review([][]byte{[]byte(src)}, standard(), l); r.Status != Open && !(which == "evaluation" && r.Status == Fail && len(r.Unknowns) > 0) {
			t.Fatal(which, r.JSON())
		}
	}
	if r := analyze(tlsSrc("InsecureSkipVerify:"+strings.Repeat("!", 200)+"false"), standard()); !contains(r, "syntax_nesting_budget") {
		t.Fatal(r.JSON())
	}
}
func TestFailAndOpenSurviveResultAndInputBudgets(t *testing.T) {
	l := DefaultLimits()
	l.Results = 1
	l.ReportBytes = 2048
	r := Review([][]byte{[]byte(tlsSrc("InsecureSkipVerify:true,MinVersion:unknown")), bytes.Repeat([]byte("x"), l.FileBytes+1)}, standard(), l)
	if r.Status != Fail || r.FindingCount != 1 || !contains(r, "result_budget") || !contains(r, "input_budget") {
		t.Fatal(r.JSON())
	}
	var report map[string]any
	if json.Unmarshal(r.JSON(), &report) != nil || report["status"] != Fail || len(r.JSON()) > 2049 {
		t.Fatal(r.JSON())
	}
}
func TestAPIDoesNotMutateInputs(t *testing.T) {
	b := []byte(tlsSrc("MinVersion:tls.VersionTLS12"))
	before := bytes.Clone(b)
	_ = Review([][]byte{b}, standard(), DefaultLimits())
	if !bytes.Equal(b, before) {
		t.Fatal("mutated")
	}
}
func TestInvalidOptionsNoRawEcho(t *testing.T) {
	for _, o := range []Options{{GoMinor: 27}, {TLSRole: "SECRET_PATH"}, {CryptoRandom: "SECRET_PATH"}, {TLSRole: "client", TLSDefaults: "server_legacy"}} {
		r := analyze(rsaSrc("2048"), o)
		if r.Status != Open || bytes.Contains(r.JSON(), []byte("SECRET_PATH")) {
			t.Fatal(r.JSON())
		}
	}
	l := DefaultLimits()
	l.ReportBytes = 1
	if r := Review([][]byte{[]byte(rsaSrc("2048"))}, standard(), l); r.Status != Open || len(r.Inputs) != 0 {
		t.Fatal(r.JSON())
	}
}
func TestPermanentOpenBoundaries(t *testing.T) {
	r := analyze(tlsSrc("MinVersion:tls.VersionTLS12,InsecureSkipVerify:false"), standard())
	if r.Status != Pass || r.ExitCode() != 0 || r.Compilation != Open || r.RuntimeSecurity != Open || r.SourceAuthenticity != Open || r.CrossFileResolution != Open || r.CVPEligibility != Open {
		t.Fatal(r.JSON())
	}
}
func TestBuildTagsAndCgoRemainOpen(t *testing.T) {
	for _, src := range []string{"//go:build linux\n\n" + tlsSrc("MinVersion:tls.VersionTLS12"), `package p;import("C";"crypto/tls");var c=tls.Config{MinVersion:tls.VersionTLS12}`} {
		if r := analyze(src, standard()); r.Status != Open || len(r.Unknowns) == 0 {
			t.Fatal(r.JSON())
		}
	}
}
func FuzzReviewBounded(f *testing.F) {
	for _, s := range []string{tlsSrc("MinVersion:tls.VersionTLS12"), rsaSrc("1<<10"), readerSrc("rsa", "rsa.GenerateKey(r,2048)"), "package p"} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		l := DefaultLimits()
		l.FileBytes = 32768
		l.Tokens = 4096
		l.ASTNodes = 8192
		r := Review([][]byte{b}, standard(), l)
		if r.Status != Pass && r.Status != Fail && r.Status != Open {
			t.Fatal(r.Status)
		}
		if !json.Valid(bytes.TrimSpace(r.JSON())) {
			t.Fatal("invalid report")
		}
	})
}
