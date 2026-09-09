// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package routecheck

import (
	"log"
)

// Logf calls [Client.Logf] to print to a logger.
// Arguments are handled in the manner of fmt.Printf.
func (c *Client) logf(format string, a ...any) {
	if c.Logf != nil {
		c.Logf(format, a...)
	} else {
		log.Printf(format, a...)
	}
}

// Vlogf calls [Client.Logf] to print to a logger, only when in debug mode,
// which is when verbose logging is enabled.
// Arguments are handled in the manner of fmt.Printf.
func (c *Client) vlogf(format string, a ...any) {
	if c.Verbose {
		c.logf(format, a...)
	}
}
