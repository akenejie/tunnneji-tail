// Copyright (C) 2026 アケネＪ / Akenejie
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package cli

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnlocal"
	"tailscale.com/net/tsdial"
	"tailscale.com/tsd"
	"tailscale.com/types/logid"
	"tailscale.com/wgengine/netstack"
)

func runTunnelCLI(args []string) error {
	groups, err := parseTunnelArgs(args)
	if err != nil {
		return err
	}

	log.Printf("tunnneji-tail %s", version)
	for i, g := range groups {
		if len(groups) > 1 {
			log.Printf("  [%d] state: %s", i+1, g.StateFile)
		} else {
			log.Printf("  state: %s", g.StateFile)
		}
		for label, pe := range g.Ports {
			if label == "" {
				label = "-"
			}
			if pe.IsServer {
				log.Printf("    port %s: VPN %d -> %s:%d", label, pe.ListenPort, pe.TargetAddr, pe.TargetPort)
			} else {
				log.Printf("    port %s: local %d -> VPN %s:%d", label, pe.ListenPort, pe.TargetAddr, pe.TargetPort)
			}
		}
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	if len(groups) == 1 {
		errCh := make(chan error, 1)
		go func() {
			errCh <- runTunnel(groups[0])
		}()
		select {
		case err := <-errCh:
			return err
		case <-sigCh:
			log.Printf("Shutting down...")
			return nil
		}
	}

	var wg sync.WaitGroup
	errCh := make(chan error, len(groups))
	for _, g := range groups {
		wg.Add(1)
		g := g
		go func() {
			defer wg.Done()
			if err := runTunnel(g); err != nil {
				errCh <- fmt.Errorf("group error: %w", err)
			}
		}()
	}

	select {
	case err := <-errCh:
		log.Fatalf("Error: %v", err)
	case <-sigCh:
		log.Printf("Shutting down...")
	}

	return nil
}

func runTunnel(group TunnelGroup) error {
	sys := tsd.NewSystem()
	var logf func(string, ...any)
	if debug {
		logf = log.Printf
	} else {
		logf = func(string, ...any) {}
	}

	ns, err := createUserspaceEngine(logf, sys, group.StateFile)
	if err != nil {
		return fmt.Errorf("failed to create engine: %w", err)
	}

	lb, err := ipnlocal.NewLocalBackend(logf, logid.PublicID{}, sys, 0)
	if err != nil {
		return fmt.Errorf("failed to create local backend: %w", err)
	}

	// Configure netstack for server-side ports
	if ns != nil {
		for _, pe := range group.Ports {
			if !pe.IsServer {
				continue
			}
			if ns.AllowedIPsForPort == nil {
				ns.AllowedIPsForPort = make(map[uint16][]netip.Prefix)
			}
			if len(pe.Accept) > 0 {
				ns.AllowedIPsForPort[uint16(pe.ListenPort)] = pe.Accept
			}
			if ns.PasswordForPort == nil {
				ns.PasswordForPort = make(map[uint16]string)
			}
			if pe.Password != "" {
				ns.PasswordForPort[uint16(pe.ListenPort)] = pe.Password
			}
		}
		ns.DropICMP = group.DropICMP
		if err := ns.Start(lb); err != nil {
			log.Printf("netstack.Start: %v", err)
		}
	}

	prefs := ipn.NewPrefs()
	prefs.WantRunning = true
	if group.Hostname != "" {
		prefs.Hostname = group.Hostname
	} else {
		prefs.Hostname = "tailscaled"
	}

	if err := lb.Start(ipn.Options{
		AuthKey:     group.AuthKey,
		UpdatePrefs: prefs,
	}); err != nil {
		return fmt.Errorf("failed to start backend: %w", err)
	}

	if st := lb.State(); st == ipn.NeedsLogin {
		log.Printf("State is %v, starting login...", st)
		if err := lb.StartLoginInteractive(context.Background()); err != nil {
			return fmt.Errorf("failed to start login: %w", err)
		}
	}

	// Print VPN address once available
	go func() {
		for i := 0; i < 30; i++ {
			time.Sleep(1 * time.Second)
			if netMap := lb.NetMap(); netMap != nil && netMap.SelfNode.Valid() {
				for _, addr := range netMap.SelfNode.Addresses().All() {
					log.Printf("VPN address: %s", addr.Addr())
				}
				return
			}
		}
	}()

	// Set up all ports
	for sub, pe := range group.Ports {
		if pe.IsServer {
			// Server: VPN listens → dials local target
			// Use SetServeConfig to tell netstack to forward
			serveConfig := &ipn.ServeConfig{
				TCP: map[uint16]*ipn.TCPPortHandler{
					uint16(pe.ListenPort): {
						TCPForward: fmt.Sprintf("%s:%d", pe.TargetAddr, pe.TargetPort),
					},
				},
			}
			go func(sub string, pe *PortEntry) {
				for i := 0; i < 60; i++ {
					time.Sleep(2 * time.Second)
					if err := lb.SetServeConfig(serveConfig, ""); err != nil {
						if debug {
							log.Printf("SetServeConfig attempt %d failed: %v", i+1, err)
						}
						continue
					}
					log.Printf("Server port %s: VPN %d -> %s:%d", label(sub), pe.ListenPort, pe.TargetAddr, pe.TargetPort)
					return
				}
				log.Printf("Warning: failed to set serve config after 60 attempts")
			}(sub, pe)
		} else {
			// Client: local listens → dials VPN target
			dialer := lb.Dialer()
			listenAddr := fmt.Sprintf("127.0.0.1:%d", pe.ListenPort)
			listener, err := net.Listen("tcp", listenAddr)
			if err != nil {
				return fmt.Errorf("failed to listen on %s: %w", listenAddr, err)
			}
			log.Printf("Client port %s: local %d -> VPN %s:%d", label(sub), pe.ListenPort, pe.TargetAddr, pe.TargetPort)

			go func(pe *PortEntry, listener net.Listener) {
				for {
					conn, err := listener.Accept()
					if err != nil {
						log.Printf("Accept error on %s: %v", listenAddr, err)
						return
					}
					go handleConn(conn, pe, dialer)
				}
			}(pe, listener)
		}
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	<-sigCh

	log.Printf("Shutting down...")
	lb.Shutdown()
	return nil
}

func label(sub string) string {
	if sub == "" {
		return "-"
	}
	return sub
}

func handleConn(conn net.Conn, pe *PortEntry, dialer *tsdial.Dialer) {
	defer conn.Close()

	// IP filtering
	if len(pe.Accept) > 0 {
		remoteAddr, ok := conn.RemoteAddr().(*net.TCPAddr)
		if ok {
			srcIP := remoteAddr.AddrPort().Addr()
			found := false
			for _, pfx := range pe.Accept {
				if pfx.Contains(srcIP) {
					found = true
					break
				}
			}
			if !found {
				return
			}
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Resolve hostname at dial time (VPN-internal DNS may only be available after connect)
	host := resolveHost(pe.TargetAddr)
	target := fmt.Sprintf("%s:%d", host, pe.TargetPort)
	remoteConn, err := dialer.UserDial(ctx, "tcp", target)
	if err != nil {
		log.Printf("Failed to dial %s: %v", target, err)
		return
	}
	defer remoteConn.Close()

	var localReader io.Reader = conn
	var localWriter io.Writer = conn
	var remoteReader io.Reader = remoteConn
	var remoteWriter io.Writer = remoteConn

	if pe.Password != "" {
		key := netstack.DeriveKey(pe.Password)

		// local→remote: encrypt
		encWriter, err := netstack.NewChacha20Writer(remoteConn, key)
		if err != nil {
			log.Printf("Failed to create encrypt writer: %v", err)
			return
		}
		remoteWriter = encWriter

		// remote→local: decrypt
		decReader, err := netstack.NewChacha20Reader(remoteConn, key)
		if err != nil {
			log.Printf("Failed to create decrypt reader: %v", err)
			return
		}
		remoteReader = decReader
	}

	errc := make(chan error, 2)
	go func() {
		_, err := io.Copy(remoteWriter, localReader)
		errc <- err
	}()
	go func() {
		_, err := io.Copy(localWriter, remoteReader)
		errc <- err
	}()
	<-errc
}
