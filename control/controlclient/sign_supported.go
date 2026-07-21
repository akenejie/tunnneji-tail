// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build windows || (darwin && !ios && cgo)

package controlclient

import (
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/util/syspolicy/policyclient"
)

// signRegisterRequest on tunnneji-tail always returns errNoCertStore.
// Device certificate signing is an enterprise feature (MDM) that is not used
// in tunnneji-tail. All platforms send unsigned RegisterRequests for consistency.
func signRegisterRequest(polc policyclient.Client, req *tailcfg.RegisterRequest, serverURL string, serverPubKey, machinePubKey key.MachinePublic) error {
	return errNoCertStore
}
