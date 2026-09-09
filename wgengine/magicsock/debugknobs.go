// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ios && !js

package magicsock

import (
	"net/netip"
)

// pretendpoints returns TS_DEBUG_PRETENDPOINT as []AddrPort, if set.
func pretendpoints() []netip.AddrPort { return nil }
