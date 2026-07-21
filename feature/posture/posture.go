// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package posture registers support for device posture checking,
// reporting machine-specific information to the control plane
// when enabled by the user and tailnet.
package posture

import (
	"encoding/json"
	"fmt"
	"net/http"

	"tailscale.com/health"
	"tailscale.com/ipn/ipnext"
	"tailscale.com/ipn/ipnlocal"
	"tailscale.com/posture"
	"tailscale.com/syncs"
	"tailscale.com/tailcfg"
	"tailscale.com/types/logger"
	"tailscale.com/util/syspolicy/pkey"
	"tailscale.com/util/syspolicy/ptype"
)

func init() {
	ipnext.RegisterExtension("posture", newExtension)
	ipnlocal.RegisterC2N("GET /posture/identity", handleC2NPostureIdentityGet)
}

var postureSerialWarnable = health.Register(&health.Warnable{
	Code:     "posture-checking-serial-collection-failed",
	Title:    "Device Posture: serial number collection failed",
	Severity: health.SeverityMedium,
	Text: func(args health.Args) string {
		return fmt.Sprintf("Could not collect device serial numbers for posture checking. (%v)", args[health.ArgError])
	},
})

func newExtension(logf logger.Logf, b ipnext.SafeBackend) (ipnext.Extension, error) {
	e := &extension{
		logf: logger.WithPrefix(logf, "posture: "),
	}
	return e, nil
}

type extension struct {
	logf logger.Logf

	// lastKnownHardwareAddrs is a list of the previous known hardware addrs.
	// Previously known hwaddrs are kept to work around an issue on Windows
	// where all addresses might disappear.
	// http://go/corp/25168
	lastKnownHardwareAddrs syncs.AtomicValue[[]string]
}

func (e *extension) Name() string             { return "posture" }
func (e *extension) Init(h ipnext.Host) error { return nil }
func (e *extension) Shutdown() error          { return nil }

func handleC2NPostureIdentityGet(b *ipnlocal.LocalBackend, w http.ResponseWriter, r *http.Request) {
	e, ok := ipnlocal.GetExt[*extension](b)
	if !ok {
		http.Error(w, "posture extension not available", http.StatusInternalServerError)
		return
	}
	e.logf("c2n: %s %s received", r.Method, r.URL.String())

	res := tailcfg.C2NPostureIdentityResponse{}

	// tunnneji-tail: posture data is never sent to prevent telemetry leakage.
	// Serial numbers, MAC addresses, and other device-specific information
	// are personal data that should not be shared with the control server.
	res.PostureDisabled = true

	e.logf("c2n: posture identity disabled=%v reported %d serials %d hwaddrs", res.PostureDisabled, len(res.SerialNumbers), len(res.IfaceHardwareAddrs))

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(res)
}

// getHardwareAddrs returns the hardware addresses for the machine. If the list
// of hardware addresses is empty, it will return the previously known hardware
// addresses. Both the current, and previously known hardware addresses might be
// empty.
func (e *extension) getHardwareAddrs() ([]string, error) {
	addrs, err := posture.GetHardwareAddrs()
	if err != nil {
		return nil, err
	}

	if len(addrs) == 0 {
		e.logf("getHardwareAddrs: got empty list of hwaddrs, returning previous list")
		return e.lastKnownHardwareAddrs.Load(), nil
	}

	e.lastKnownHardwareAddrs.Store(addrs)
	return addrs, nil
}
