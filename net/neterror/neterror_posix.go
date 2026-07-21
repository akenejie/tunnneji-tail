// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9 && !js && !wasip1 && !wasm

package neterror

import (
	"errors"
	"io"
	"io/fs"
	"syscall"
)

// Reports whether err resulted from reading or writing to a closed or broken pipe.
func IsClosedPipeError(err error) bool {
	return errors.Is(err, syscall.EPIPE) ||
		errors.Is(err, syscall.ENOTCONN) ||
		errors.Is(err, fs.ErrClosed) ||
		errors.Is(err, io.ErrClosedPipe)
}
