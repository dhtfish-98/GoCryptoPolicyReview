// SPDX-License-Identifier: Apache-2.0
package gocrypto

import (
	"go/ast"
	"go/constant"
	"go/token"
	"math/big"
)

// Unknown is distinct from zero. No mutable initializer is treated as a constant.
func (f *fileReview) eval(e ast.Expr, iotaValue, depth int) (v constant.Value) {
	v = constant.MakeUnknown()
	defer func() {
		if recover() != nil {
			v = constant.MakeUnknown()
		}
	}()
	f.steps++
	if f.steps > f.r.Limits.EvalSteps {
		f.evalBudget = true
		f.r.unresolved("constant_evaluation_budget")
		return v
	}
	if e == nil || depth > 64 {
		return v
	}
	e = unparen(e)
	switch x := e.(type) {
	case *ast.BasicLit:
		if x.Kind != token.INT && x.Kind != token.CHAR {
			return v
		}
		if len(x.Value) > 1024 {
			return v
		}
		v = constant.MakeFromLiteral(x.Value, x.Kind, 0)
	case *ast.Ident:
		if x.Obj == nil {
			if f.shadowedBuiltin(x) {
				return v
			}
			switch x.Name {
			case "true":
				return constant.MakeBool(true)
			case "false":
				return constant.MakeBool(false)
			case "iota":
				if iotaValue >= 0 {
					return constant.MakeInt64(int64(iotaValue))
				}
			}
			return v
		}
		b, ok := f.bindings[x.Obj]
		if !ok || !b.isConst || x.Obj.Kind != ast.Con {
			return v
		}
		v = f.eval(b.expr, b.iota, depth+1)
		if b.typ != nil {
			v = f.convert(b.typ, v)
		}
	case *ast.SelectorExpr:
		p, n, ok := f.packageSelector(x)
		if !ok || p != "crypto/tls" {
			return v
		}
		versions := map[string]int64{"VersionSSL30": 768, "VersionTLS10": 769, "VersionTLS11": 770, "VersionTLS12": 771, "VersionTLS13": 772}
		if n, ok := versions[n]; ok {
			return constant.MakeInt64(n)
		}
	case *ast.UnaryExpr:
		if x.Op != token.NOT && x.Op != token.ADD && x.Op != token.SUB && x.Op != token.XOR {
			return v
		}
		a := f.eval(x.X, iotaValue, depth+1)
		if a.Kind() == constant.Unknown {
			return v
		}
		prec := uint(0)
		if x.Op == token.XOR {
			t := f.expressionType(x.X, 0)
			switch t.name {
			case "uint8":
				prec = 8
			case "uint16":
				prec = 16
			case "uint32":
				prec = 32
			case "uint64":
				prec = 64
			case "uint":
				// Complement depends on the target's unstated 32/64-bit width.
				// A 32-bit result must not imply verification is enabled on 64-bit.
				return v
			}
		}
		v = constant.UnaryOp(x.Op, a, prec)
	case *ast.BinaryExpr:
		a := f.eval(x.X, iotaValue, depth+1)
		b := f.eval(x.Y, iotaValue, depth+1)
		if a.Kind() == constant.Unknown || b.Kind() == constant.Unknown {
			return v
		}
		ta, tb := f.expressionType(x.X, 0), f.expressionType(x.Y, 0)
		if !ta.valid || !tb.valid {
			return v
		}
		if x.Op != token.SHL && x.Op != token.SHR {
			if ta.name != "" && tb.name != "" && ta.name != tb.name {
				return v
			}
			if ta.name != "" && tb.name == "" {
				b = f.convertName(ta.name, b)
			}
			if tb.name != "" && ta.name == "" {
				a = f.convertName(tb.name, a)
			}
			if a.Kind() == constant.Unknown || b.Kind() == constant.Unknown {
				return v
			}
		}
		switch x.Op {
		case token.SHL, token.SHR:
			shift, ok := constant.Uint64Val(b)
			if !ok || shift > 4096 || a.Kind() != constant.Int {
				return v
			}
			v = constant.Shift(a, x.Op, uint(shift))
		case token.EQL, token.NEQ, token.LSS, token.LEQ, token.GTR, token.GEQ:
			v = constant.MakeBool(constant.Compare(a, x.Op, b))
		case token.ADD, token.SUB, token.MUL, token.QUO, token.REM, token.AND, token.OR, token.XOR, token.AND_NOT, token.LAND, token.LOR:
			if a.Kind() == constant.Int && b.Kind() == constant.Int && x.Op == token.QUO {
				v = constant.BinaryOp(a, token.QUO_ASSIGN, b)
			} else {
				v = constant.BinaryOp(a, x.Op, b)
			}
		default:
			return v
		}
	case *ast.CallExpr:
		if len(x.Args) == 1 {
			v = f.convert(x.Fun, f.eval(x.Args[0], iotaValue, depth+1))
		}
	}
	if v.Kind() == constant.Int {
		if n, ok := constant.Val(v).(*big.Int); ok && n.BitLen() > 4096 {
			return constant.MakeUnknown()
		}
	}
	t := f.expressionType(e, 0)
	if !t.valid {
		return constant.MakeUnknown()
	}
	if t.name != "" {
		v = f.convertName(t.name, v)
	}
	return v
}
func (f *fileReview) convert(typ ast.Expr, v constant.Value) constant.Value {
	id, ok := unparen(typ).(*ast.Ident)
	if !ok || id.Obj != nil || f.shadowedBuiltin(id) {
		return constant.MakeUnknown()
	}
	return f.convertName(id.Name, v)
}
func (f *fileReview) convertName(name string, v constant.Value) constant.Value {
	if name == "bool" && v.Kind() == constant.Bool {
		return v
	}
	if v.Kind() != constant.Int {
		return constant.MakeUnknown()
	}
	if name == "uint64" {
		if _, ok := constant.Uint64Val(v); ok {
			return v
		}
		return constant.MakeUnknown()
	}
	value, ok := constant.Int64Val(v)
	if !ok {
		return constant.MakeUnknown()
	}
	var min, max int64
	switch name {
	case "int8":
		min, max = -128, 127
	case "uint8", "byte":
		min, max = 0, 255
	case "int16":
		min, max = -32768, 32767
	case "uint16":
		min, max = 0, 65535
	case "int32", "rune", "int":
		min, max = -2147483648, 2147483647
	case "uint32", "uint":
		min, max = 0, 4294967295
	case "int64":
		return v
	default:
		return constant.MakeUnknown()
	}
	if value < min || value > max {
		return constant.MakeUnknown()
	}
	return v
}
func (f *fileReview) integer(e ast.Expr) (int64, bool) {
	v := f.eval(e, -1, 0)
	if v.Kind() != constant.Int {
		return 0, false
	}
	return constant.Int64Val(v)
}
func (f *fileReview) policyInteger(e ast.Expr, want string) (int64, bool) {
	v, known := f.integer(e)
	if !known {
		return 0, false
	}
	t := f.expressionType(e, 0)
	if !t.valid || (t.name != "" && t.name != want) {
		return 0, false
	}
	if want == "uint16" && (v < 0 || v > 65535) {
		return 0, false
	}
	if want == "int" && (v < -2147483648 || v > 2147483647) {
		return 0, false
	}
	return v, true
}
func (f *fileReview) boolean(e ast.Expr) (bool, bool) {
	v := f.eval(e, -1, 0)
	if v.Kind() != constant.Bool {
		return false, false
	}
	t := f.expressionType(e, 0)
	if !t.valid || (t.name != "" && t.name != "bool") {
		return false, false
	}
	return constant.BoolVal(v), true
}

type constantType struct {
	name  string
	valid bool
}

func builtinConstantType(e ast.Expr) constantType {
	id, ok := unparen(e).(*ast.Ident)
	if !ok || id.Obj != nil {
		return constantType{}
	}
	n := id.Name
	if n == "byte" {
		n = "uint8"
	}
	if n == "rune" {
		n = "int32"
	}
	switch n {
	case "bool", "int", "uint", "int8", "uint8", "int16", "uint16", "int32", "uint32", "int64", "uint64":
		return constantType{n, true}
	}
	return constantType{}
}

// Types are retained through constant operations so overflow and mixed typed
// operands cannot be mistaken for a valid constant policy value.
func (f *fileReview) expressionType(e ast.Expr, depth int) constantType {
	if e == nil || depth > 64 {
		return constantType{}
	}
	e = unparen(e)
	if v, ok := f.constantTypes[e]; ok {
		return v
	}
	f.steps++
	if f.steps > f.r.Limits.EvalSteps {
		f.r.unresolved("constant_evaluation_budget")
		return constantType{}
	}
	f.constantTypes[e] = constantType{} // recursion/cycle marker
	t := constantType{"", true}
	switch x := e.(type) {
	case *ast.BasicLit:
		if x.Kind != token.INT && x.Kind != token.CHAR {
			t.valid = false
		}
	case *ast.Ident:
		if x.Obj == nil {
			t.valid = !f.shadowedBuiltin(x) && (x.Name == "true" || x.Name == "false" || x.Name == "iota")
		} else {
			b, ok := f.bindings[x.Obj]
			if !ok || !b.isConst || x.Obj.Kind != ast.Con {
				t.valid = false
			} else if b.typ != nil {
				t = f.checkedBuiltinType(b.typ)
			} else {
				t = f.expressionType(b.expr, depth+1)
			}
		}
	case *ast.SelectorExpr:
		p, n, ok := f.packageSelector(x)
		t.valid = ok && p == "crypto/tls" && (n == "VersionSSL30" || n == "VersionTLS10" || n == "VersionTLS11" || n == "VersionTLS12" || n == "VersionTLS13")
	case *ast.UnaryExpr:
		t = f.expressionType(x.X, depth+1)
	case *ast.BinaryExpr:
		a, b := f.expressionType(x.X, depth+1), f.expressionType(x.Y, depth+1)
		if !a.valid || !b.valid {
			t.valid = false
			break
		}
		if x.Op == token.SHL || x.Op == token.SHR {
			t = a
			break
		}
		if a.name != "" && b.name != "" && a.name != b.name {
			t.valid = false
			break
		}
		if x.Op == token.EQL || x.Op == token.NEQ || x.Op == token.LSS || x.Op == token.LEQ || x.Op == token.GTR || x.Op == token.GEQ {
			break
		}
		t = a
		if t.name == "" {
			t = b
		}
	case *ast.CallExpr:
		if len(x.Args) != 1 {
			t.valid = false
		} else {
			t = f.checkedBuiltinType(x.Fun)
		}
	default:
		t.valid = false
	}
	f.constantTypes[e] = t
	return t
}
func (f *fileReview) checkedBuiltinType(e ast.Expr) constantType {
	if id, ok := unparen(e).(*ast.Ident); ok && f.shadowedBuiltin(id) {
		return constantType{}
	}
	return builtinConstantType(e)
}
