//go:build linux || darwin

// SPDX-License-Identifier: Apache-2.0
package gocrypto

import (
	"bytes"
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
	"testing"
)

func localTemp(t *testing.T) string {
	t.Helper()
	p, e := os.MkdirTemp(".", "input-test-")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = os.RemoveAll(p) })
	return p
}
func TestLocalReadAndBudgets(t *testing.T) {
	d := localTemp(t)
	p := filepath.Join(d, "input.go")
	data := []byte("package p\n")
	if os.WriteFile(p, data, 0600) != nil {
		t.Fatal("write")
	}
	b, e := ReadLocal(p, len(data))
	if e != nil || !bytes.Equal(b, data) {
		t.Fatal(e)
	}
	if _, e = ReadLocal(p, len(data)-1); e == nil || e.Error() != "input_budget" {
		t.Fatal(e)
	}
	after, _ := os.ReadFile(p)
	if !bytes.Equal(data, after) {
		t.Fatal("changed")
	}
}
func TestSymlinkAndParentPathRejection(t *testing.T) {
	d := localTemp(t)
	real := filepath.Join(d, "real")
	if os.Mkdir(real, 0700) != nil {
		t.Fatal("mkdir")
	}
	p := filepath.Join(real, "file.go")
	_ = os.WriteFile(p, []byte("package p"), 0600)
	link := filepath.Join(d, "link")
	_ = os.Symlink("real", link)
	filelink := filepath.Join(real, "link.go")
	_ = os.Symlink("file.go", filelink)
	for _, v := range []string{filepath.Join(link, "file.go"), filelink, d + "/link/../real/file.go", d + "/real/../real/file.go"} {
		if _, e := ReadLocal(v, 100); e == nil {
			t.Fatal(v)
		}
	}
}
func TestNonRegularFileNoBlocking(t *testing.T) {
	d := localTemp(t)
	fifo := filepath.Join(d, "fifo")
	if unix.Mkfifo(fifo, 0600) != nil {
		t.Fatal("fifo")
	}
	for _, p := range []string{d, fifo, "/dev/null"} {
		if _, e := ReadLocal(p, 100); e == nil {
			t.Fatal(p)
		}
	}
}
func TestInvalidPaths(t *testing.T) {
	for _, p := range []string{"", "bad\x00path", string(bytes.Repeat([]byte("x"), 4097))} {
		if _, e := ReadLocal(p, 100); e == nil {
			t.Fatal("accepted")
		}
	}
	if _, e := ReadLocal("missing.go", 0); e == nil {
		t.Fatal("bad limit")
	}
}
