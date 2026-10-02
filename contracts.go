// SPDX-License-Identifier: Apache-2.0
package gocrypto

import (
	"encoding/json"
	"sort"
)

const (
	Pass = "PASS"
	Fail = "FAIL"
	Open = "OPEN"
)

// Limits may only lower the defaults. Zero values are invalid, not defaults.
type Limits struct {
	Files       int `json:"files"`
	FileBytes   int `json:"file_bytes"`
	TotalBytes  int `json:"total_bytes"`
	Tokens      int `json:"tokens_per_file"`
	TokenBytes  int `json:"token_bytes"`
	Nesting     int `json:"nesting"`
	ASTNodes    int `json:"ast_nodes_per_file"`
	EvalSteps   int `json:"evaluation_steps_per_file"`
	Results     int `json:"results"`
	ReportBytes int `json:"report_bytes"`
}

func DefaultLimits() Limits {
	return Limits{32, 262144, 2097152, 32768, 8192, 128, 50000, 50000, 2048, 1048576}
}

func (l Limits) valid() bool {
	d := DefaultLimits()
	a := []int{l.Files, l.FileBytes, l.TotalBytes, l.Tokens, l.TokenBytes, l.Nesting, l.ASTNodes, l.EvalSteps, l.Results, l.ReportBytes}
	b := []int{d.Files, d.FileBytes, d.TotalBytes, d.Tokens, d.TokenBytes, d.Nesting, d.ASTNodes, d.EvalSteps, d.Results, d.ReportBytes}
	for i, v := range a {
		if v < 1 || v > b[i] {
			return false
		}
	}
	return l.ReportBytes >= 2048
}

// Options are caller assertions, never inferred from the analyzer's Go runtime.
// The frozen default catalog only covers standard Go 1.22 through 1.26.
type Options struct {
	GoMinor      int    `json:"asserted_go_minor"`
	TLSRole      string `json:"asserted_tls_role"`
	TLSDefaults  string `json:"asserted_tls_defaults"`
	CryptoRandom string `json:"asserted_crypto_random_mode"`
}

func (o Options) valid() bool {
	return (o.GoMinor == 0 || (o.GoMinor >= 22 && o.GoMinor <= 26)) &&
		(o.TLSRole == "" || o.TLSRole == "client" || o.TLSRole == "server") &&
		(o.TLSDefaults == "" || o.TLSDefaults == "standard" || o.TLSDefaults == "server_legacy") &&
		(o.CryptoRandom == "" || o.CryptoRandom == "standard" || o.CryptoRandom == "custom") &&
		!(o.TLSRole == "client" && o.TLSDefaults == "server_legacy")
}

type Position struct {
	File   int `json:"file"`
	Line   int `json:"line"`
	Column int `json:"byte_column"`
}
type Result struct {
	Position Position   `json:"position"`
	Rule     string     `json:"rule"`
	Status   string     `json:"status"`
	Reason   string     `json:"reason"`
	Value    *int64     `json:"policy_value,omitempty"`
	Evidence []Position `json:"evidence,omitempty"`
}
type Digest struct {
	File   int    `json:"file"`
	Status string `json:"status"`
	SHA256 string `json:"sha256,omitempty"`
}
type Report struct {
	Schema              string   `json:"schema"`
	Status              string   `json:"status"`
	Results             []Result `json:"results"`
	ResultCount         int      `json:"result_count"`
	FindingCount        int      `json:"finding_count"`
	Unknowns            []string `json:"unknowns"`
	Inputs              []Digest `json:"inputs"`
	Limits              Limits   `json:"limits"`
	Assertions          Options  `json:"assertions"`
	Compilation         string   `json:"compilation"`
	RuntimeSecurity     string   `json:"runtime_security"`
	SourceAuthenticity  string   `json:"source_authenticity"`
	CrossFileResolution string   `json:"cross_file_resolution"`
	CVPEligibility      string   `json:"cvp_eligibility"`
	seen                map[string]bool
}

func newReport(o Options, l Limits) *Report {
	return &Report{
		Schema: "gocrypto-policy-review/v1", Status: Pass, Results: []Result{}, Unknowns: []string{}, Inputs: []Digest{}, Limits: l, Assertions: o,
		Compilation: Open, RuntimeSecurity: Open, SourceAuthenticity: Open, CrossFileResolution: Open, CVPEligibility: Open, seen: map[string]bool{},
	}
}
func (r *Report) unresolved(code string) {
	if !r.seen[code] {
		r.seen[code] = true
		r.Unknowns = append(r.Unknowns, code)
	}
	if r.Status != Fail {
		r.Status = Open
	}
}
func (r *Report) result(v Result) {
	r.ResultCount++
	if v.Status == Fail {
		r.FindingCount++
		r.Status = Fail
	}
	if v.Status == Open {
		r.unresolved(v.Reason)
	}
	if len(r.Results) < r.Limits.Results {
		r.Results = append(r.Results, v)
	} else {
		r.unresolved("result_budget")
	}
}

// JSON bounds the final report, retaining counts and FAIL even when detail is omitted.
func (r *Report) JSON() []byte {
	sort.Strings(r.Unknowns)
	for {
		b, _ := json.Marshal(r)
		if len(b)+1 <= r.Limits.ReportBytes {
			return append(b, '\n')
		}
		r.unresolved("report_budget")
		if len(r.Results) > 0 {
			r.Results = r.Results[:len(r.Results)/2]
			continue
		}
		if len(r.Inputs) > 0 {
			r.Inputs = r.Inputs[:len(r.Inputs)/2]
			continue
		}
		// Fixed metadata and the finite unknown vocabulary fit the 2048-byte minimum.
		fallback := map[string]any{"schema": r.Schema, "status": r.Status, "result_count": r.ResultCount, "finding_count": r.FindingCount, "unknowns": []string{"report_budget"}, "compilation": Open, "runtime_security": Open, "source_authenticity": Open, "cross_file_resolution": Open, "cvp_eligibility": Open}
		b, _ = json.Marshal(fallback)
		return append(b, '\n')
	}
}
func (r *Report) ExitCode() int {
	if r.Status == Fail {
		return 1
	}
	if r.Status == Open {
		return 2
	}
	return 0
}

// ErrorReport never incorporates argument values, paths, parser messages or source text.
func ErrorReport(code string) *Report {
	allowed := map[string]bool{"invalid_arguments": true, "invalid_file_inventory": true, "invalid_options_or_limits": true, "invalid_limits": true, "invalid_path": true, "parent_path": true, "path_budget": true, "local_read_unavailable": true, "nonfollowing_read_failed": true, "not_regular_file": true, "input_budget": true, "local_read_failed": true, "input_changed": true, "unsupported_platform": true}
	if !allowed[code] {
		code = "invalid_arguments"
	}
	r := newReport(Options{}, DefaultLimits())
	r.unresolved(code)
	return r
}
