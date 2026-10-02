//go:build !darwin && !linux

// SPDX-License-Identifier: Apache-2.0
package gocrypto

import "errors"

func ReadLocal(path string, limit int) ([]byte, error) {
	return nil, errors.New("unsupported_platform")
}
