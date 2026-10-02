// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestCLIReportsAndPrivacy(t *testing.T) {
	d, e := os.MkdirTemp(".", "cli-test-")
	if e != nil {
		t.Fatal(e)
	}
	defer os.RemoveAll(d)
	for _, tt := range []struct {
		name, src string
		exit      int
	}{{"pass", `package p;import "crypto/tls";var c=tls.Config{MinVersion:tls.VersionTLS12}`, 0}, {"fail", `package p;import "crypto/tls";var c=tls.Config{MinVersion:tls.VersionTLS12,InsecureSkipVerify:true}`, 1}, {"open", `package p;import "crypto/tls";var c=tls.Config{MinVersion:dynamic}`, 2}} {
		p := filepath.Join(d, tt.name+"_SECRET_PATH.go")
		if os.WriteFile(p, []byte(tt.src), 0600) != nil {
			t.Fatal("write")
		}
		var b bytes.Buffer
		exit := run([]string{p}, &b)
		if exit != tt.exit || !json.Valid(bytes.TrimSpace(b.Bytes())) || bytes.Contains(b.Bytes(), []byte("SECRET_PATH")) {
			t.Fatal(exit, b.String())
		}
	}
}
func TestCLIInvalidArgumentsFixedJSON(t *testing.T) {
	for _, args := range [][]string{nil, {"--SECRET_PATH"}, {"--go-minor", "SECRET_PATH"}, {"--tls-role", "SECRET_PATH", "missing.go"}, {"--max-file-bytes", "0", "missing.go"}, {"/SECRET_PATH/missing.go"}} {
		var b bytes.Buffer
		if code := run(args, &b); code != 2 || !json.Valid(bytes.TrimSpace(b.Bytes())) || bytes.Contains(b.Bytes(), []byte("SECRET_PATH")) {
			t.Fatal(args, code, b.String())
		}
	}
}
func TestCLIHelp(t *testing.T) {
	var b bytes.Buffer
	if run([]string{"--help"}, &b) != 0 || b.Len() == 0 {
		t.Fatal(b.String())
	}
}
