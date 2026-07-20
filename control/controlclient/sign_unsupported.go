// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build (!windows && !(darwin && cgo)) || ios

package controlclient

import (
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/util/syspolicy/policyclient"
)

// signRegisterRequest on non-supported platforms always returns errNoCertStore.
// Device certificate signing is only supported on Windows and macOS with MDM
// configuration. On Linux, the control server does not accept signed requests.
func signRegisterRequest(polc policyclient.Client, req *tailcfg.RegisterRequest, serverURL string, serverPubKey, machinePubKey key.MachinePublic, deviceSigningKeyPEM, deviceCertChainPEM []byte) error {
	return errNoCertStore
}
