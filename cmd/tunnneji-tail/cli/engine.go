// Copyright (C) 2026 アケネＪ / Akenejie
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package cli

import (
	"context"
	"net"
	"net/netip"

	"tailscale.com/health"
	"tailscale.com/ipn/store"
	"tailscale.com/net/netmon"
	"tailscale.com/net/tsdial"
	"tailscale.com/tsd"
	"tailscale.com/types/logger"
	"tailscale.com/wgengine"
	"tailscale.com/wgengine/netstack"
)

// createUserspaceEngine creates a WireGuard engine in userspace-networking mode
// and sets up netstack for VPN dialing.
// Returns netstack (nil if creation failed).
func createUserspaceEngine(logf logger.Logf, sys *tsd.System, stateFile string) (*netstack.Impl, error) {
	// Set up the dialer before anything that needs it
	dialer := &tsdial.Dialer{Logf: logf}
	dialer.SetBus(sys.Bus.Get())
	sys.Set(dialer)

	// Set up state store from file
	stateStore, err := store.NewFileStore(logf, stateFile)
	if err != nil {
		return nil, err
	}
	sys.Set(stateStore)

	// Create network monitor (required by engine for packet processing)
	netMon, err := netmon.New(sys.Bus.Get(), logf)
	if err != nil {
		return nil, err
	}
	sys.Set(netMon)

	// Create engine config
	conf := wgengine.Config{
		ListenPort:    0,
		NetMon:        netMon,
		Metrics:       sys.UserMetricsRegistry(),
		Dialer:        sys.Dialer.Get(),
		SetSubsystem:  sys.Set,
		ControlKnobs:  sys.ControlKnobs(),
		EventBus:      sys.Bus.Get(),
		HealthTracker: health.NewTracker(sys.Bus.Get()),
	}

	// Create userspace engine with netstack
	e, err := wgengine.NewUserspaceEngine(logf, conf)
	if err != nil {
		return nil, err
	}

	sys.Set(e)
	sys.NetstackRouter.Set(true)

	// Start the tun wrapper
	if w, ok := sys.Tun.GetOK(); ok {
		w.Start()
	}

	// Create netstack and set up dialer for VPN connections
	var ns *netstack.Impl
	tundev := sys.Tun.Get()
	if tundev != nil {
		ns, err = netstack.Create(logf, tundev, e, sys.MagicSock.Get(), dialer, sys.ProxyMapper())
		if err != nil {
			logf("netstack.Create: %v", err)
		} else {
			ns.ProcessLocalIPs = true
			ns.ProcessSubnets = true
			sys.Set(ns)

			dialer.UseNetstackForIP = func(ip netip.Addr) bool {
				// Use netstack for Tailscale IPs (100.64.0.0/10 and fd7a:115c:a1e0::/48)
				if ip.Is4() {
					b4 := ip.As4()
					return b4[0] == 100 && b4[1] >= 64 && b4[1] <= 127
				}
				if ip.Is6() {
					b := ip.As16()
					return b[0] == 0xfd && b[1] == 0x7a
				}
				return false
			}
			dialer.NetstackDialTCP = func(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
				return ns.DialContextTCP(ctx, dst)
			}
			dialer.NetstackDialUDP = func(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
				return ns.DialContextUDP(ctx, dst)
			}
			logf("netstack configured for VPN dialing")
		}
	} else {
		logf("warning: no tundev, VPN dialing via netstack unavailable")
	}

	return ns, nil
}
