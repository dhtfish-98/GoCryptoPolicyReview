// SPDX-License-Identifier: Apache-2.0
package gocrypto

import (
	"go/ast"
	"go/token"
)

func (f *fileReview) check() {
	ast.Inspect(f.file, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.CompositeLit:
			if f.typeTLS(x.Type, 0) {
				f.tlsLiteral(x)
			}
		case *ast.ValueSpec:
			if len(x.Values) == 0 && f.typeTLS(x.Type, 0) {
				f.emit(x, "tls_verify", Pass, "declared_builtin_verification_enabled", nil, nil)
				f.tlsDefault(x)
			}
		case *ast.AssignStmt:
			for i, left := range x.Lhs {
				s, ok := unparen(left).(*ast.SelectorExpr)
				if !ok {
					continue
				}
				if s.Sel.Name != "InsecureSkipVerify" && s.Sel.Name != "MinVersion" && s.Sel.Name != "Rand" {
					continue
				}
				if !f.typeTLS(s.X, 0) {
					if f.hasImport("crypto/tls") {
						f.emit(s, "tls_receiver", Open, "unresolved_tls_receiver", nil, nil)
					}
					continue
				}
				if x.Tok != token.ASSIGN || len(x.Lhs) != len(x.Rhs) {
					f.emit(s, "tls_field", Open, "unsupported_tls_assignment", nil, nil)
					continue
				}
				f.tlsField(s, s.Sel.Name, x.Rhs[i], false)
			}
		case *ast.CallExpr:
			if id, ok := unparen(x.Fun).(*ast.Ident); ok && id.Obj == nil && id.Name == "new" && !f.shadowedBuiltin(id) && len(x.Args) == 1 && f.typeTLS(x.Args[0], 0) {
				f.emit(x, "tls_verify", Pass, "declared_builtin_verification_enabled", nil, nil)
				f.tlsDefault(x)
			}
			p, name, ok := f.packageSelector(x.Fun)
			if !ok {
				return true
			}
			if p == "crypto/rsa" && (name == "GenerateKey" || name == "GenerateMultiPrimeKey") {
				argc, bitsIndex := 2, 1
				if name == "GenerateMultiPrimeKey" {
					argc, bitsIndex = 3, 2
				}
				if len(x.Args) != argc || x.Ellipsis.IsValid() {
					f.emit(x, "rsa_bits", Open, "invalid_rsa_call_shape", nil, nil)
					return true
				}
				if bits, known := f.policyInteger(x.Args[bitsIndex], "int"); known && bits > 0 && bits <= 2147483647 {
					status, reason := Pass, "declared_rsa_bits_at_least_2048"
					if bits < 2048 {
						status, reason = Fail, "declared_rsa_bits_below_2048"
					}
					f.emit(x, "rsa_bits", status, reason, &bits, nil)
				} else {
					f.emit(x, "rsa_bits", Open, "unresolved_or_invalid_rsa_bits", nil, nil)
				}
				f.readerSink(x, x.Args[0], "rsa_reader", true)
			}
			if p == "crypto/ecdsa" && name == "GenerateKey" {
				if len(x.Args) != 2 || x.Ellipsis.IsValid() {
					f.emit(x, "random_security_use", Open, "invalid_security_call_shape", nil, nil)
				} else {
					f.readerSink(x, x.Args[1], "ecdsa_reader", true)
				}
			}
			if p == "crypto/ed25519" && name == "GenerateKey" {
				if len(x.Args) != 1 || x.Ellipsis.IsValid() {
					f.emit(x, "random_security_use", Open, "invalid_security_call_shape", nil, nil)
				} else {
					f.readerSink(x, x.Args[0], "ed25519_reader", false)
				}
			}
		}
		return true
	})
	f.bufferUses()
	// Ordinary random calls retain purpose uncertainty; names and comments are
	// never interpreted as evidence that a value is a password, token or key.
	ast.Inspect(f.file, func(n ast.Node) bool {
		c, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		p, name, ok := f.packageSelector(c.Fun)
		if ok && p == "crypto/aes" && name == "NewCipher" && !f.handledAES[c] {
			f.emit(c, "aes_key_source", Open, "aes_key_random_source_unresolved", nil, nil)
		}
		if ok && (p == "math/rand" || p == "math/rand/v2") && randomCall(name, p) && !f.usedRandom[c] {
			f.emit(c, "random_observation", Open, "random_security_purpose_unproven", nil, nil)
		}
		return true
	})
}
func (f *fileReview) hasImport(p string) bool {
	for _, v := range f.imports {
		if v == p {
			return true
		}
	}
	return false
}
func (f *fileReview) tlsLiteral(x *ast.CompositeLit) {
	fields := map[string]ast.Expr{}
	custom := false
	for _, e := range x.Elts {
		kv, ok := e.(*ast.KeyValueExpr)
		if !ok {
			f.emit(x, "tls_config", Open, "unkeyed_tls_literal", nil, nil)
			return
		}
		id, ok := kv.Key.(*ast.Ident)
		if !ok {
			f.emit(x, "tls_config", Open, "unsupported_tls_field", nil, nil)
			return
		}
		if _, dup := fields[id.Name]; dup {
			f.emit(x, "tls_config", Open, "duplicate_tls_field", nil, nil)
			return
		}
		fields[id.Name] = kv.Value
		if id.Name == "VerifyConnection" || id.Name == "VerifyPeerCertificate" {
			custom = true
		}
	}
	if v, ok := fields["InsecureSkipVerify"]; ok {
		f.tlsField(x, "InsecureSkipVerify", v, custom)
	} else {
		f.emit(x, "tls_verify", Pass, "declared_builtin_verification_enabled", nil, nil)
	}
	if v, ok := fields["MinVersion"]; ok {
		f.tlsField(x, "MinVersion", v, false)
	} else {
		f.tlsDefault(x)
	}
	if v, ok := fields["Rand"]; ok {
		f.tlsField(x, "Rand", v, false)
	}
	if v, ok := fields["MaxVersion"]; ok {
		max, known := f.policyInteger(v, "uint16")
		if !known || (max != 0 && (max < 769 || max > 772)) {
			f.emit(x, "tls_range", Open, "unresolved_or_invalid_tls_maximum", nil, nil)
		} else if max != 0 {
			min, km := f.policyInteger(fields["MinVersion"], "uint16")
			if !km || min == 0 {
				min, km = f.defaultMinimum()
			}
			if km && min > max {
				f.emit(x, "tls_range", Open, "invalid_tls_version_range", nil, nil)
			}
		}
	}
}
func (f *fileReview) tlsField(n ast.Node, name string, e ast.Expr, custom bool) {
	switch name {
	case "InsecureSkipVerify":
		b, known := f.boolean(e)
		if !known {
			f.emit(n, "tls_verify", Open, "unresolved_verification_boolean", nil, nil)
			return
		}
		if b {
			if f.r.Assertions.TLSRole == "server" {
				f.emit(n, "tls_verify", Open, "server_skip_verify_effect_unassessed", nil, nil)
				return
			}
			reason := "declared_builtin_verification_disabled"
			if custom {
				reason = "builtin_verification_disabled_custom_hook_unassessed"
			}
			f.emit(n, "tls_verify", Fail, reason, nil, nil)
		} else {
			f.emit(n, "tls_verify", Pass, "declared_builtin_verification_enabled", nil, nil)
		}
	case "MinVersion":
		v, known := f.policyInteger(e, "uint16")
		if !known {
			f.emit(n, "tls_minimum", Open, "unresolved_tls_minimum", nil, nil)
			return
		}
		if v == 0 {
			f.tlsDefault(n)
			return
		}
		if v >= 768 && v <= 770 {
			f.emit(n, "tls_minimum", Fail, "declared_tls_minimum_below_1_2", &v, nil)
		} else if v == 771 || v == 772 {
			f.emit(n, "tls_minimum", Pass, "declared_tls_minimum_at_least_1_2", &v, nil)
		} else {
			f.emit(n, "tls_minimum", Open, "invalid_or_unsupported_tls_minimum", nil, nil)
		}
	case "Rand":
		f.readerSink(n, e, "tls_entropy_reader", false)
	}
}
func (f *fileReview) defaultMinimum() (int64, bool) {
	o := f.r.Assertions
	if o.GoMinor < 22 || o.GoMinor > 26 || o.TLSRole == "" {
		return 0, false
	}
	if o.TLSRole == "client" {
		return 771, true
	}
	if o.TLSDefaults == "standard" {
		return 771, true
	}
	if o.TLSDefaults == "server_legacy" {
		return 769, true
	}
	return 0, false
}
func (f *fileReview) tlsDefault(n ast.Node) {
	v, known := f.defaultMinimum()
	if !known {
		f.emit(n, "tls_minimum", Open, "tls_default_assertions_missing", nil, nil)
		return
	}
	status, reason := Pass, "asserted_tls_default_1_2"
	if v < 771 {
		status, reason = Fail, "asserted_server_legacy_tls_default_1_0"
	}
	f.emit(n, "tls_minimum", status, reason, &v, nil)
}
