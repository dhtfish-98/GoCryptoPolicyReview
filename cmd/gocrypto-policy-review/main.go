// SPDX-License-Identifier: Apache-2.0
package main

import (
	"errors"
	"flag"
	"fmt"
	gocrypto "github.com/dhtfish-98/GoCryptoPolicyReview"
	"io"
	"os"
)

func run(args []string, out io.Writer) int {
	fs := flag.NewFlagSet("gocrypto-policy-review", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	minor := fs.Int("go-minor", 0, "Assert target standard Go minor 22..26; zero leaves unknown")
	role := fs.String("tls-role", "", "Assert client or server for TLS defaults")
	defaults := fs.String("tls-defaults", "", "Assert standard or server_legacy GODEBUG semantics")
	crypto := fs.String("crypto-random", "", "Assert standard or custom (cryptocustomrand=1) semantics")
	maxbytes := fs.Int("max-file-bytes", gocrypto.DefaultLimits().FileBytes, "Lower the per-file byte budget")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprintln(out, "gocrypto-policy-review [--go-minor 22..26] [--tls-role client|server] [--tls-defaults standard|server_legacy] [--crypto-random standard|custom] [--max-file-bytes N] -- FILE.go [FILE.go ...]")
			return 0
		}
		r := gocrypto.ErrorReport("invalid_arguments")
		_, _ = out.Write(r.JSON())
		return 2
	}
	l := gocrypto.DefaultLimits()
	l.FileBytes = *maxbytes
	o := gocrypto.Options{GoMinor: *minor, TLSRole: *role, TLSDefaults: *defaults, CryptoRandom: *crypto}
	// Validate options before reading or hashing any caller file.
	probe := gocrypto.Review([][]byte{[]byte("package p")}, o, l)
	for _, code := range probe.Unknowns {
		if code == "invalid_options_or_limits" {
			_, _ = out.Write(probe.JSON())
			return 2
		}
	}
	if fs.NArg() == 0 || fs.NArg() > l.Files {
		r := gocrypto.ErrorReport("invalid_file_inventory")
		_, _ = out.Write(r.JSON())
		return 2
	}
	sources := [][]byte{}
	total := 0
	for _, p := range fs.Args() {
		remaining := l.TotalBytes - total
		if remaining <= 0 {
			r := gocrypto.ErrorReport("input_budget")
			_, _ = out.Write(r.JSON())
			return 2
		}
		readLimit := l.FileBytes
		if remaining < readLimit {
			readLimit = remaining
		}
		b, err := gocrypto.ReadLocal(p, readLimit)
		if err != nil {
			r := gocrypto.ErrorReport(err.Error())
			_, _ = out.Write(r.JSON())
			return 2
		}
		if len(b) > l.TotalBytes-total {
			r := gocrypto.ErrorReport("input_budget")
			_, _ = out.Write(r.JSON())
			return 2
		}
		total += len(b)
		sources = append(sources, b)
	}
	r := gocrypto.Review(sources, o, l)
	_, _ = out.Write(r.JSON())
	return r.ExitCode()
}
func main() { os.Exit(run(os.Args[1:], os.Stdout)) }
