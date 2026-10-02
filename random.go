// SPDX-License-Identifier: Apache-2.0
package gocrypto

import (
	"go/ast"
	"go/token"
)

func randomCall(name, p string) bool {
	switch name {
	case "Int", "Int31", "Int31n", "Int63", "Int63n", "Intn", "IntN", "Int32", "Int32N", "Int64", "Int64N", "Uint", "UintN", "N", "Uint32", "Uint32N", "Uint64", "Uint64N", "Float32", "Float64", "ExpFloat64", "NormFloat64", "Perm", "Shuffle", "Read", "Seed", "New", "NewSource", "NewPCG", "NewChaCha8", "NewZipf":
		return true
	}
	return false
}

type readerFlow struct {
	weak      bool
	secure    bool
	nilReader bool
	evidence  []*ast.CallExpr
}

func (f *fileReview) reader(e ast.Expr, depth int) readerFlow {
	if e == nil || depth > 32 {
		return readerFlow{}
	}
	e = unparen(e)
	if id, ok := e.(*ast.Ident); ok {
		if id.Obj == nil && f.shadowedBuiltin(id) {
			return readerFlow{}
		}
		if id.Obj == nil && id.Name == "nil" {
			return readerFlow{nilReader: true}
		}
		if id.Obj == nil || f.writes[id.Obj] || f.escaped[id.Obj] {
			return readerFlow{}
		}
		b, ok := f.bindings[id.Obj]
		if !ok {
			return readerFlow{}
		}
		return f.reader(b.expr, depth+1)
	}
	if p, n, ok := f.packageSelector(e); ok && p == "crypto/rand" && n == "Reader" {
		return readerFlow{secure: true}
	}
	c, p, n, ok := f.call(e)
	if !ok || p != "math/rand" || n != "New" || len(c.Args) != 1 || c.Ellipsis.IsValid() {
		return readerFlow{}
	}
	source := f.randomSource(c.Args[0], depth+1)
	if source == nil {
		return readerFlow{}
	}
	return readerFlow{weak: true, evidence: []*ast.CallExpr{source, c}}
}
func (f *fileReview) randomSource(e ast.Expr, depth int) *ast.CallExpr {
	if e == nil || depth > 32 {
		return nil
	}
	e = unparen(e)
	if id, ok := e.(*ast.Ident); ok {
		if id.Obj == nil || f.writes[id.Obj] || f.escaped[id.Obj] {
			return nil
		}
		b, ok := f.bindings[id.Obj]
		if !ok {
			return nil
		}
		return f.randomSource(b.expr, depth+1)
	}
	c, p, n, ok := f.call(e)
	if ok && p == "math/rand" && n == "NewSource" && len(c.Args) == 1 && !c.Ellipsis.IsValid() {
		return c
	}
	return nil
}
func (f *fileReview) readerSink(n ast.Node, e ast.Expr, rule string, changedIn26 bool) {
	v := f.reader(e, 0)
	evidence := []Position{}
	for _, c := range v.evidence {
		f.usedRandom[c] = true
		evidence = append(evidence, f.position(c))
	}
	o := f.r.Assertions
	if changedIn26 && o.GoMinor == 26 && o.CryptoRandom == "standard" {
		f.emit(n, rule, Pass, "asserted_go_1_26_reader_ignored", nil, evidence)
		return
	}
	if v.secure {
		f.emit(n, rule, Pass, "declared_crypto_rand_reader", nil, nil)
		return
	}
	if v.nilReader && rule == "ed25519_reader" {
		f.emit(n, rule, Pass, "declared_ed25519_default_reader", nil, nil)
		return
	}
	if v.nilReader && rule == "tls_entropy_reader" {
		f.emit(n, rule, Pass, "declared_tls_default_entropy_reader", nil, nil)
		return
	}
	if !v.weak {
		f.emit(n, rule, Open, "unresolved_security_random_reader", nil, nil)
		return
	}
	if o.GoMinor == 0 || (changedIn26 && o.GoMinor == 26 && o.CryptoRandom == "") {
		f.emit(n, rule, Open, "weak_reader_consumption_unresolved", nil, evidence)
		return
	}
	f.emit(n, rule, Fail, "declared_weak_reader_in_security_use", nil, evidence)
}

// byteBuffer tracks only same lexical objects in the same straight-line block.
// Aliases, unknown calls, control flow and mutation invalidate proof. No names
// or comments are used to infer security purpose.
type byteBuffer struct {
	sources []*ast.CallExpr
	known   bool
}

func (f *fileReview) bufferUses() {
	ast.Inspect(f.file, func(n ast.Node) bool {
		b, ok := n.(*ast.BlockStmt)
		if !ok {
			return true
		}
		f.bufferBlock(b)
		return true
	})
}
func (f *fileReview) bufferBlock(block *ast.BlockStmt) {
	state := map[*ast.Object]byteBuffer{}
	for _, stmt := range block.List {
		switch stmt.(type) {
		case *ast.IfStmt, *ast.ForStmt, *ast.RangeStmt, *ast.SwitchStmt, *ast.TypeSwitchStmt, *ast.SelectStmt, *ast.GoStmt, *ast.DeferStmt, *ast.BranchStmt, *ast.LabeledStmt, *ast.BlockStmt:
			state = map[*ast.Object]byteBuffer{}
			continue
		case *ast.ReturnStmt:
			state = map[*ast.Object]byteBuffer{}
			continue
		}
		calls := []*ast.CallExpr{}
		ast.Inspect(stmt, func(n ast.Node) bool {
			if _, ok := n.(*ast.FuncLit); ok {
				return false
			}
			if c, ok := n.(*ast.CallExpr); ok {
				calls = append(calls, c)
			}
			return true
		})
		// A call within another call has unspecified effects in this model.
		// For supported Read/NewCipher, each is the only call in its statement.
		if len(calls) == 1 {
			c := calls[0]
			p, name, ok := f.packageSelector(c.Fun)
			if ok && p == "math/rand" && name == "Read" && len(c.Args) == 1 && !c.Ellipsis.IsValid() {
				if id, ok := unparen(c.Args[0]).(*ast.Ident); ok && id.Obj != nil && !f.escaped[id.Obj] {
					state[id.Obj] = byteBuffer{[]*ast.CallExpr{c}, true}
					continue
				}
			}
			if ok && p == "crypto/aes" && name == "NewCipher" && len(c.Args) == 1 && !c.Ellipsis.IsValid() {
				f.handledAES[c] = true
				if id, ok := unparen(c.Args[0]).(*ast.Ident); ok && id.Obj != nil {
					if flow, ok := state[id.Obj]; ok && flow.known {
						evidence := []Position{}
						for _, source := range flow.sources {
							f.usedRandom[source] = true
							evidence = append(evidence, f.position(source))
						}
						f.emit(c, "weak_bytes_to_aes_key", Fail, "weak_random_bytes_used_as_aes_key", nil, evidence)
					} else {
						f.emit(c, "aes_key_source", Open, "aes_key_random_source_unresolved", nil, nil)
					}
				} else {
					f.emit(c, "aes_key_source", Open, "aes_key_random_source_unresolved", nil, nil)
				}
				continue
			}
		}
		// Any other call can mutate or alias buffers. Clearing is conservative.
		if len(calls) > 0 {
			state = map[*ast.Object]byteBuffer{}
		}
		ast.Inspect(stmt, func(n ast.Node) bool {
			if _, ok := n.(*ast.FuncLit); ok {
				return false
			}
			switch x := n.(type) {
			case *ast.AssignStmt:
				for _, e := range x.Rhs {
					ast.Inspect(e, func(n ast.Node) bool {
						if id, ok := n.(*ast.Ident); ok {
							delete(state, id.Obj)
						}
						return true
					})
				}
				for _, lhs := range x.Lhs {
					if id, ok := unparen(lhs).(*ast.Ident); ok {
						delete(state, id.Obj)
					} else {
						state = map[*ast.Object]byteBuffer{}
					}
				}
			case *ast.IncDecStmt:
				state = map[*ast.Object]byteBuffer{}
			case *ast.UnaryExpr:
				if x.Op == token.AND {
					state = map[*ast.Object]byteBuffer{}
				}
			case *ast.ValueSpec:
				for _, e := range x.Values {
					if id, ok := unparen(e).(*ast.Ident); ok {
						delete(state, id.Obj)
					}
				}
			}
			return true
		})
	}
}
