//go:build darwin || linux

// SPDX-License-Identifier: Apache-2.0
package gocrypto

import (
	"errors"
	"golang.org/x/sys/unix"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// ReadLocal rejects symlinks at every component and does not walk directories.
// Error strings are fixed codes; the original path is never returned.
func ReadLocal(path string, limit int) ([]byte, error) {
	bad := func(code string) ([]byte, error) { return nil, errors.New(code) }
	if limit < 1 || limit > DefaultLimits().FileBytes {
		return bad("invalid_limits")
	}
	if path == "" || len(path) > 4096 || strings.IndexByte(path, 0) >= 0 {
		return bad("invalid_path")
	}
	for _, part := range strings.Split(path, "/") {
		if part == ".." {
			return bad("parent_path")
		}
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return bad("invalid_path")
	}
	parts := strings.Split(strings.TrimPrefix(abs, "/"), "/")
	if len(parts) > 128 {
		return bad("path_budget")
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return bad("local_read_unavailable")
	}
	defer func() {
		if fd >= 0 {
			_ = unix.Close(fd)
		}
	}()
	for i, part := range parts {
		if part == "" || part == "." {
			return bad("invalid_path")
		}
		flags := unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_CLOEXEC | unix.O_NONBLOCK
		if i < len(parts)-1 {
			flags |= unix.O_DIRECTORY
		}
		next, e := unix.Openat(fd, part, flags, 0)
		if e != nil {
			return bad("nonfollowing_read_failed")
		}
		_ = unix.Close(fd)
		fd = next
	}
	var before, after unix.Stat_t
	if unix.Fstat(fd, &before) != nil || before.Mode&unix.S_IFMT != unix.S_IFREG {
		return bad("not_regular_file")
	}
	if before.Size < 0 || before.Size > int64(limit) {
		return bad("input_budget")
	}
	f := os.NewFile(uintptr(fd), "")
	if f == nil {
		return bad("local_read_unavailable")
	}
	fd = -1
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, int64(limit)+1))
	if e != nil {
		return bad("local_read_failed")
	}
	if len(b) > limit {
		return bad("input_budget")
	}
	if unix.Fstat(int(f.Fd()), &after) != nil || before.Dev != after.Dev || before.Ino != after.Ino || before.Mode != after.Mode || before.Size != after.Size || before.Mtim != after.Mtim || before.Ctim != after.Ctim || int64(len(b)) != after.Size {
		return bad("input_changed")
	}
	return b, nil
}
