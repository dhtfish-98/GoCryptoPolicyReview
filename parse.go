// SPDX-License-Identifier: Apache-2.0
package gocrypto

import (
	"crypto/sha256"
	"encoding/hex"
	"go/ast"
	"go/parser"
	"go/scanner"
	"go/token"
	"path"
	"strconv"
	"strings"
	"unicode/utf8"
)

type binding struct {
	expr    ast.Expr
	typ     ast.Expr
	isConst bool
	iota    int
}
type fileReview struct {
	r             *Report
	index         int
	fset          *token.FileSet
	file          *ast.File
	imports       map[string]string
	bindings      map[*ast.Object]binding
	writes        map[*ast.Object]bool
	escaped       map[*ast.Object]bool
	steps         int
	evalBudget    bool
	usedRandom    map[*ast.CallExpr]bool
	handledAES    map[*ast.CallExpr]bool
	constantTypes map[ast.Expr]constantType
	crossBuiltin  map[string]bool
}

func (f *fileReview) position(n ast.Node) Position {
	p := f.fset.PositionFor(n.Pos(), false)
	return Position{f.index, p.Line, p.Column}
}
func (f *fileReview) emit(n ast.Node, rule, status, reason string, v *int64, evidence []Position) {
	f.r.result(Result{f.position(n), rule, status, reason, v, evidence})
}

// Review analyzes each supplied byte slice separately; it never imports or reads other files.
func Review(sources [][]byte, o Options, l Limits) *Report {
	if !l.valid() || !o.valid() {
		return ErrorReport("invalid_options_or_limits")
	}
	r := newReport(o, l)
	if len(sources) == 0 {
		r.unresolved("no_sources")
		return r
	}
	if len(sources) > l.Files {
		r.unresolved("file_budget")
	}
	total := 0
	files := []*fileReview{}
	for i, b := range sources {
		if i >= l.Files {
			break
		}
		if len(b) > l.FileBytes || len(b) > l.TotalBytes-total {
			r.Inputs = append(r.Inputs, Digest{File: i + 1, Status: Open})
			r.unresolved("input_budget")
			continue
		}
		total += len(b)
		h := sha256.Sum256(b)
		r.Inputs = append(r.Inputs, Digest{i + 1, Pass, hex.EncodeToString(h[:])})
		fs := token.NewFileSet()
		if code := preflight(b, fs, l); code != "" {
			r.unresolved(code)
			continue
		}
		// The synthetic name and PositionFor(false) prevent //line directives from
		// replacing physical coordinates or leaking arbitrary source-supplied paths.
		a, err := parser.ParseFile(fs, "input.go", b, parser.ParseComments|parser.DeclarationErrors)
		if err != nil || a == nil {
			r.unresolved("invalid_go_syntax")
			continue
		}
		f := &fileReview{r: r, index: i + 1, fset: fs, file: a, imports: map[string]string{}, bindings: map[*ast.Object]binding{}, writes: map[*ast.Object]bool{}, escaped: map[*ast.Object]bool{}, usedRandom: map[*ast.CallExpr]bool{}, handledAES: map[*ast.CallExpr]bool{}, constantTypes: map[ast.Expr]constantType{}}
		if !f.admitAST() {
			continue
		}
		files = append(files, f)
	}
	for _, f := range files {
		f.crossBuiltin = map[string]bool{}
		names := []string{"true", "false", "iota", "nil", "new", "bool", "int", "uint", "int8", "uint8", "byte", "int16", "uint16", "int32", "uint32", "rune", "int64", "uint64"}
		for _, other := range files {
			if other != f && other.file.Name.Name == f.file.Name.Name {
				for _, name := range names {
					if other.file.Scope.Objects[name] != nil {
						f.crossBuiltin[name] = true
					}
				}
			}
		}
		f.collect()
		f.check()
	}
	if r.ResultCount == 0 {
		r.unresolved("no_selected_apis")
	}
	return r
}
func (f *fileReview) shadowedBuiltin(id *ast.Ident) bool {
	if id.Obj == nil && f.crossBuiltin[id.Name] {
		f.r.unresolved("cross_file_builtin_shadow_unresolved")
		return true
	}
	return false
}

// Token and recursive-grammar budgets are applied before calling the Go parser.
func preflight(b []byte, fs *token.FileSet, l Limits) string {
	if !utf8.Valid(b) {
		return "invalid_utf8"
	}
	var s scanner.Scanner
	bad := false
	s.Init(fs.AddFile("tokens.go", -1, len(b)), b, func(token.Position, string) { bad = true }, scanner.ScanComments)
	depth, operators, count := 0, 0, 0
	for {
		_, t, lit := s.Scan()
		if t == token.EOF {
			break
		}
		count++
		if count > l.Tokens {
			return "token_budget"
		}
		if len(lit) > l.TokenBytes {
			return "token_size_budget"
		}
		switch t {
		case token.LPAREN, token.LBRACK, token.LBRACE:
			depth++
			operators = 0
		case token.RPAREN, token.RBRACK, token.RBRACE:
			depth--
			operators = 0
		case token.SEMICOLON, token.COMMA:
			operators = 0
		default:
			if t.IsOperator() {
				operators++
			}
		}
		if depth > l.Nesting || operators > l.Nesting {
			return "syntax_nesting_budget"
		}
	}
	if bad {
		return "invalid_go_tokens"
	}
	return ""
}
func (f *fileReview) admitAST() bool {
	nodes, depth := 0, 0
	bad := false
	ast.Inspect(f.file, func(n ast.Node) bool {
		if n == nil {
			depth--
			return false
		}
		nodes++
		depth++
		if nodes > f.r.Limits.ASTNodes || depth > f.r.Limits.Nesting*2 {
			bad = true
			depth--
			return false
		}
		return true
	})
	if bad {
		f.r.unresolved("ast_budget")
		return false
	}
	return true
}
func (f *fileReview) collect() {
	for _, s := range f.file.Imports {
		p, e := strconv.Unquote(s.Path.Value)
		if e != nil {
			f.r.unresolved("invalid_import")
			continue
		}
		if p == "C" {
			f.r.unresolved("cgo_unresolved")
		}
		name := path.Base(p)
		if p == "math/rand/v2" {
			name = "rand"
		}
		if s.Name != nil {
			name = s.Name.Name
		}
		if name == "." {
			f.r.unresolved("dot_import_unresolved")
			continue
		}
		if name == "_" {
			continue
		}
		if _, found := f.imports[name]; found {
			f.r.unresolved("ambiguous_import_binding")
			f.imports[name] = ""
		} else {
			f.imports[name] = p
		}
	}
	for _, c := range f.file.Comments {
		for _, v := range c.List {
			if strings.HasPrefix(v.Text, "//go:build") || strings.HasPrefix(v.Text, "// +build") {
				f.r.unresolved("build_constraints_not_evaluated")
			}
			if strings.HasPrefix(v.Text, "//go:debug") {
				f.r.unresolved("target_debug_directive_not_evaluated")
			}
		}
	}
	ast.Inspect(f.file, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.GenDecl:
			var previous []ast.Expr
			var previousType ast.Expr
			for ix, sp := range x.Specs {
				v, ok := sp.(*ast.ValueSpec)
				if !ok {
					continue
				}
				values := v.Values
				typ := v.Type
				if x.Tok == token.CONST {
					if len(values) == 0 {
						values = previous
						typ = previousType
					} else {
						previous = values
						previousType = typ
					}
				}
				for j, id := range v.Names {
					if id.Obj == nil {
						continue
					}
					var e ast.Expr
					if len(values) == len(v.Names) {
						e = values[j]
					}
					f.bindings[id.Obj] = binding{e, typ, x.Tok == token.CONST, ix}
				}
			}
		case *ast.AssignStmt:
			for j, left := range x.Lhs {
				if id, ok := left.(*ast.Ident); ok && id.Obj != nil {
					if x.Tok == token.DEFINE && id.Obj.Decl == x && len(x.Lhs) == len(x.Rhs) {
						f.bindings[id.Obj] = binding{expr: x.Rhs[j]}
					} else {
						f.writes[id.Obj] = true
					}
				}
			}
		case *ast.IncDecStmt:
			if id, ok := x.X.(*ast.Ident); ok && id.Obj != nil {
				f.writes[id.Obj] = true
			}
		case *ast.UnaryExpr:
			if x.Op == token.AND {
				if id, ok := x.X.(*ast.Ident); ok && id.Obj != nil {
					f.escaped[id.Obj] = true
				}
			}
		case *ast.TypeSpec:
			if x.Name.Obj != nil {
				f.bindings[x.Name.Obj] = binding{typ: x.Type, isConst: x.Assign.IsValid()}
			}
		case *ast.Field:
			for _, id := range x.Names {
				if id.Obj != nil {
					f.bindings[id.Obj] = binding{typ: x.Type}
				}
			}
		}
		return true
	})
	// Function values and defined TLS types require semantics outside this model.
	direct := map[ast.Expr]bool{}
	ast.Inspect(f.file, func(n ast.Node) bool {
		if c, ok := n.(*ast.CallExpr); ok {
			direct[unparen(c.Fun)] = true
		}
		return true
	})
	ast.Inspect(f.file, func(n ast.Node) bool {
		if s, ok := n.(*ast.SelectorExpr); ok && !direct[s] {
			p, name, known := f.packageSelector(s)
			if known && ((p == "crypto/rsa" && (name == "GenerateKey" || name == "GenerateMultiPrimeKey")) || ((p == "crypto/ecdsa" || p == "crypto/ed25519") && name == "GenerateKey") || (p == "crypto/aes" && name == "NewCipher") || ((p == "math/rand" || p == "math/rand/v2") && randomCall(name, p))) {
				f.r.unresolved("selected_function_alias_unresolved")
			}
		}
		if t, ok := n.(*ast.TypeSpec); ok && !t.Assign.IsValid() && f.typeTLS(t.Type, 0) {
			f.r.unresolved("defined_tls_type_unresolved")
		}
		return true
	})
}
func unparen(e ast.Expr) ast.Expr {
	for {
		p, ok := e.(*ast.ParenExpr)
		if !ok {
			return e
		}
		e = p.X
	}
}
func (f *fileReview) packageSelector(e ast.Expr) (string, string, bool) {
	s, ok := unparen(e).(*ast.SelectorExpr)
	if !ok {
		return "", "", false
	}
	id, ok := unparen(s.X).(*ast.Ident)
	if !ok || id.Obj != nil {
		return "", "", false
	}
	p, ok := f.imports[id.Name]
	return p, s.Sel.Name, ok && p != ""
}
func (f *fileReview) call(e ast.Expr) (*ast.CallExpr, string, string, bool) {
	c, ok := unparen(e).(*ast.CallExpr)
	if !ok {
		return nil, "", "", false
	}
	p, n, ok := f.packageSelector(c.Fun)
	return c, p, n, ok
}

// typeTLS resolves only local syntactic aliases and variable declarations.
// Defined types, untyped parameters, interface assertions and function results are unknown.
func (f *fileReview) typeTLS(e ast.Expr, depth int) bool {
	if e == nil || depth > 32 {
		return false
	}
	e = unparen(e)
	if p, n, ok := f.packageSelector(e); ok {
		return p == "crypto/tls" && n == "Config"
	}
	switch x := e.(type) {
	case *ast.StarExpr:
		return f.typeTLS(x.X, depth+1)
	case *ast.UnaryExpr:
		if x.Op == token.AND {
			return f.typeTLS(x.X, depth+1)
		}
	case *ast.CompositeLit:
		return f.typeTLS(x.Type, depth+1)
	case *ast.Ident:
		if x.Obj == nil {
			return false
		}
		b, ok := f.bindings[x.Obj]
		if !ok {
			return false
		}
		if x.Obj.Kind == ast.Typ {
			return b.isConst && f.typeTLS(b.typ, depth+1)
		}
		if b.typ != nil {
			return f.typeTLS(b.typ, depth+1)
		}
		return f.typeTLS(b.expr, depth+1)
	case *ast.CallExpr:
		id, ok := x.Fun.(*ast.Ident)
		return ok && id.Obj == nil && id.Name == "new" && !f.shadowedBuiltin(id) && len(x.Args) == 1 && f.typeTLS(x.Args[0], depth+1)
	}
	return false
}
