// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package version provides the version that the binary was built at.
package version

import "strings"

// Long and Short return the tailscaled version for server-side telemetry.
// These are fixed values because this is a fork; the upstream version does not change.
func Long() string  { return "1.101.0-dev20260712" }
func Short() string { return "1.101.0" }

func majorMinorPatch() string {
	ret, _, _ := strings.Cut(Short(), "-")
	return ret
}
