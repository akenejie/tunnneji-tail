// Copyright (C) 2026 アケネＪ / Akenejie
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package cli

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"

	tailscaleroot "tailscale.com"
)

var version = strings.TrimSpace(tailscaleroot.VersionDotTxt)
var debug bool

func Run(args []string) error {
	if len(args) == 0 {
		return printUsage()
	}

	switch args[0] {
	case "version":
		fmt.Printf("tunnneji-tail %s\n", version)
		return nil
	case "help", "-h", "--help":
		return printUsage()
	default:
		return runTunnelCLI(args)
	}
}

func printUsage() error {
	fmt.Println(`tunnneji-tail - Portable VPN tunnel using Tailscale

A single binary that combines Tailscale server+client functionality.
Uses API key authentication only (no browser/GUI required).
All networking runs in userspace (no system-wide VPN, no root needed).

Usage:
  tunnneji-tail -K <key> -S <mapping>     server mode (VPN port → local)
  tunnneji-tail -K <key> -C <mapping>     client mode (local port → VPN)
  tunnneji-tail -K <key> -S ... -C ...    both directions in one group

Options:
  -K[n]     <key>       API auth key for VPN group n (required for first run)
  -T[n]     <path>      State file path (default: tailscaled.state)
  -H[n]     <name>      Hostname for VPN group n (default: tailscaled)
  -S[n][s]  <mapping>   Server: listen on VPN port, forward to target
  -C[n][s]  <mapping>   Client: listen on local port, forward to VPN target
  -A[S|C][n][s] <ips>   Whitelist source IPs (S=server, C=client)
  -P[S|C][n][s] <pass>  ChaCha20 password for data encryption
  -D                  Debug mode (show tailscale internal logs)

Mapping format:
  port:addr:port    full form (listen:target-addr:target-port)
  port:addr         shorthand (target-port = listen port)

Authentication:
  -K with -T:       create new state file (error if file exists)
  -T only:          reconnect using existing state file (error if not found)
  -K only:          error (must provide -S or -C)
  -K without number: applies to group -1 (separate from group 0)

VPN groups:
  -K, -T, -S, -C without number = group -1 (default)
  -K0, -T0, -S0, -C0 = group 0
  -K1, -T1, -S1, -C1 = group 1
  Each numbered group requires its own -K or -T

Port groups (sub identifiers):
  Lowercase letters after direction = port group identifier
  -Sa 8080:... = server port group "a"
  -Ca 8081:... = client port group "a"
  -Sb 8082:... = server port group "b"

Password lookup priority (per port entry):
  direction+sub → direction → sub → global (no number)
  -PS1a > -PS1 > -Pa > -P

Password inheritance:
  -P (without number) = global, inherited by all VPN groups
  -P1 = group 1 only
  -P1a = group 1, port group "a" only

Accept (IP whitelist) rules:
  -A requires direction: -AS or -AC (error without S/C)
  -AS 127.0.0.1 = accept only 127.0.0.1 for server ports
  -AC 100.64.0.0/10 = accept only 100.64.0.0/10 for client ports
  Multiple IPs: underscore-separated (127.0.0.1_10.0.0.0/8)

ICMP behavior:
  All server ports password-protected → drop ICMP echo
  Any server port without password → respond to ICMP echo
  No server ports → drop ICMP echo

Examples:
  # Simple server: VPN port 8080 → local port 80
  tunnneji-tail -K <auth-key> -S 8080:127.0.0.1:80

  # Simple client: local port 8080 → VPN port 80
  tunnneji-tail -K <auth-key> -C 8080:100.64.0.1:80

  # Port shorthand (target port = listen port)
  tunnneji-tail -K <auth-key> -S 8080:127.0.0.1

  # With encryption
  tunnneji-tail -K <auth-key> -S 443:127.0.0.1:80 -P mypassword

  # Server + client with password
  tunnneji-tail -K <auth-key> -S 4096:127.0.0.1:4096 -C 4097:100.64.0.1:4096 -P secret

  # Multiple port groups
  tunnneji-tail -K <auth-key> -Sa 8080:127.0.0.1:80 -Sb 8081:127.0.0.1:81

  # Multiple VPN groups (different auth keys, different state files)
  tunnneji-tail -K1 <key1> -T1 a.state -S1 8080:127.0.0.1:80 \
                    -K2 <key2> -T2 b.state -C2 8081:100.64.0.1:80

  # Reconnect with existing state (no -K needed)
  tunnneji-tail -T a.state -S 8080:127.0.0.1:80 -P mypassword`)
	return nil
}

// PortEntry represents a port forwarding rule with direction
type PortEntry struct {
	IsServer   bool          // true: VPN→local (server), false: local→VPN (client)
	ListenPort int
	TargetAddr string
	TargetPort int
	Accept     []netip.Prefix
	Password   string
}

// TunnelGroup represents a single VPN tunnel with multiple port mappings
type TunnelGroup struct {
	AuthKey   string
	StateFile string
	Hostname  string // -H: hostname override for this VPN group
	Ports     map[string]*PortEntry // key: sub identifier ("", "A", "B", ...)
	DropICMP  bool                  // true if all server ports have passwords (untrusted VPN)
}

// parseFlag extracts flag components from a flag string.
// Returns: base flag, group number (-1 if none), sub identifier ("" if none),
// direction qualifier ("S"=server, "C"=client, ""=both)
//
// Convention:
//   - Uppercase S/C after -P/-A = direction qualifier (server/client)
//   - Lowercase letters = port group sub identifier
//   - Digits = VPN group number
//
// Examples:
//
//	-P        → both directions, no sub
//	-PS       → server direction, no sub
//	-Ps       → both directions, sub "s"
//	-PSs      → server direction, sub "s"
//	-P1s      → VPN group 1, sub "s", both directions
//	-PS1s     → VPN group 1, sub "s", server direction
func parseFlag(arg string) (base string, groupNum int, sub string, dir string) {
	if !strings.HasPrefix(arg, "-") || len(arg) < 2 {
		return arg, -1, "", ""
	}

	s := arg[1:]

	// -A and -P take a direction selector (uppercase S/C) after the base char
	if len(s) > 0 && (s[0] == 'A' || s[0] == 'P') {
		baseChar := string(s[0])
		rest := s[1:]
		if len(rest) == 0 {
			return baseChar, -1, "", ""
		}
		// Uppercase S/C = direction qualifier
		if rest[0] == 'S' || rest[0] == 'C' {
			dir = string(rest[0])
			rest = rest[1:]
		}
		groupNum, sub = parseNumAndSub(rest)
		return baseChar, groupNum, sub, dir
	}

	base = string(s[0])
	rest := s[1:]
	groupNum, sub = parseNumAndSub(rest)
	return base, groupNum, sub, ""
}

// parseNumAndSub extracts a group number and sub identifier.
// "1A" → (1, "A"), "12B" → (12, "B"), "3" → (3, ""), "" → (-1, "")
func parseNumAndSub(s string) (int, string) {
	if s == "" {
		return -1, ""
	}
	i := 0
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		i++
	}
	if i == 0 {
		return -1, s
	}
	num, err := strconv.Atoi(s[:i])
	if err != nil || num < 0 {
		return -1, s
	}
	return num, s[i:]
}

// parsePortMapping parses "port:addr:port"
func parsePortMapping(s string) (listenPort int, addr string, targetPort int, err error) {
	first := -1
	last := -1
	for i, c := range s {
		if c == ':' {
			if first == -1 {
				first = i
			}
			last = i
		}
	}
	if first == -1 {
		return 0, "", 0, fmt.Errorf("invalid mapping: %s (expected: port:addr or port:addr:port)", s)
	}
	p1, err := strconv.Atoi(s[:first])
	if err != nil {
		return 0, "", 0, fmt.Errorf("invalid port: %s", s[:first])
	}
	if last == len(s)-1 {
		return 0, "", 0, fmt.Errorf("invalid mapping: %s (missing address)", s)
	}
	if last == first {
		// Single colon: port:addr → targetPort = listenPort
		return p1, s[first+1:], p1, nil
	}
	p2, err := strconv.Atoi(s[last+1:])
	if err != nil {
		return 0, "", 0, fmt.Errorf("invalid port: %s", s[last+1:])
	}
	return p1, s[first+1 : last], p2, nil
}

// resolveHost resolves a hostname to an IP address.
// If the input is already an IP, it returns it unchanged.
// If resolution fails, the original string is returned (may be a VPN-internal name).
func resolveHost(host string) string {
	if net.ParseIP(host) != nil {
		return host
	}
	ips, err := net.LookupHost(host)
	if err != nil || len(ips) == 0 {
		return host
	}
	return ips[0]
}

// parseIPList parses underscore-separated IP/CIDR list
func parseIPList(s string) ([]netip.Prefix, error) {
	var prefixes []netip.Prefix
	for _, part := range strings.Split(s, "_") {
		if part == "" {
			continue
		}
		if pfx, err := netip.ParsePrefix(part); err == nil {
			prefixes = append(prefixes, pfx)
			continue
		}
		addr, err := netip.ParseAddr(part)
		if err != nil {
			return nil, fmt.Errorf("invalid IP/CIDR: %s", part)
		}
		bits := 32
		if addr.Is6() {
			bits = 128
		}
		prefixes = append(prefixes, netip.PrefixFrom(addr, bits))
	}
	return prefixes, nil
}

func parseTunnelArgs(args []string) ([]TunnelGroup, error) {
	type rawEntry struct {
		direction string // "S" or "C"
		mapping   string
	}
	type rawGroup struct {
		authKey       string
		authKeySet    bool
		stateFile     string
		stateFileSet  bool
		hostname      string
		hostnameSet   bool
		entries       map[string]rawEntry   // sub → port mapping
		accepts       map[string]string     // dir+sub → IP list ("S", "SA", "C", "CA")
		passwords     map[string]string     // dir+sub → password ("", "S", "SA", "C", "CA")
	}

	raw := make(map[int]*rawGroup)

	getGroup := func(n int) *rawGroup {
		if raw[n] == nil {
			raw[n] = &rawGroup{
				entries:   make(map[string]rawEntry),
				accepts:   make(map[string]string),
				passwords: make(map[string]string),
			}
		}
		return raw[n]
	}

	lastAuthKey := ""
	lastStateFile := ""
	lastHostname := ""
	inheritedPasswords := make(map[string]string) // group -1 passwords: key → password
	inheritedAccepts := make(map[string]string)   // group -1 accepts: key → ip list

	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "-D" {
			debug = true
			continue
		}
		if !strings.HasPrefix(arg, "-") {
			return nil, fmt.Errorf("unexpected argument: %s", arg)
		}

		flagName, groupNum, sub, dir := parseFlag(arg)

		switch flagName {
		case "K", "S", "C", "T", "A", "P", "H":
		default:
			return nil, fmt.Errorf("unknown flag: %s", arg)
		}

		if flagName == "K" {
			i++
			if i >= len(args) {
				return nil, fmt.Errorf("-K requires a value")
			}
			g := getGroup(groupNum)
			if g.authKey != "" {
				return nil, fmt.Errorf("duplicate -K for group %d", groupNum)
			}
			g.authKey = args[i]
			g.authKeySet = true
			lastAuthKey = args[i]
			continue
		}

		if flagName == "T" {
			i++
			if i >= len(args) {
				return nil, fmt.Errorf("-T requires a value")
			}
			g := getGroup(groupNum)
			if g.stateFile != "" {
				return nil, fmt.Errorf("duplicate -T for group %d", groupNum)
			}
			if lastStateFile != "" && args[i] == lastStateFile {
				return nil, fmt.Errorf("duplicate -T value (same file already set)")
			}
			g.stateFile = args[i]
			g.stateFileSet = true
			lastStateFile = args[i]
			continue
		}

		if flagName == "H" {
			i++
			if i >= len(args) {
				return nil, fmt.Errorf("-H requires a value")
			}
			g := getGroup(groupNum)
			if g.hostnameSet {
				return nil, fmt.Errorf("duplicate -H for group %d", groupNum)
			}
			g.hostname = args[i]
			g.hostnameSet = true
			if groupNum == -1 {
				lastHostname = args[i]
			}
			continue
		}

		if flagName == "S" || flagName == "C" {
			i++
			if i >= len(args) {
				return nil, fmt.Errorf("-%s requires a value", flagName)
			}
			g := getGroup(groupNum)
			key := flagName + sub // "Sa", "Ca", "S", "C", etc.
			if _, exists := g.entries[key]; exists {
				return nil, fmt.Errorf("duplicate -%s%s for group %d", flagName, sub, groupNum)
			}
			g.entries[key] = rawEntry{direction: flagName, mapping: args[i]}
			continue
		}

		if flagName == "A" {
			if dir == "" {
				return nil, fmt.Errorf("-A requires direction: use -AS or -AC")
			}
			i++
			if i >= len(args) {
				return nil, fmt.Errorf("-A requires a value")
			}
			key := dir + sub
			g := getGroup(groupNum)
			if _, exists := g.accepts[key]; exists {
				return nil, fmt.Errorf("duplicate -A%s%s for group %d", dir, sub, groupNum)
			}
			g.accepts[key] = args[i]
			if groupNum == -1 {
				inheritedAccepts[key] = args[i]
			}
			continue
		}

		if flagName == "P" {
			i++
			if i >= len(args) {
				return nil, fmt.Errorf("-P requires a value")
			}
			key := dir + sub
			g := getGroup(groupNum)
			if _, exists := g.passwords[key]; exists {
				return nil, fmt.Errorf("duplicate -P%s%s for group %d", dir, sub, groupNum)
			}
			g.passwords[key] = args[i]
			if groupNum == -1 {
				inheritedPasswords[key] = args[i]
			}
			continue
		}
	}

	if len(raw) == 0 {
		return nil, fmt.Errorf("no arguments provided")
	}

	nums := make([]int, 0, len(raw))
	for n := range raw {
		nums = append(nums, n)
	}
	sort.Ints(nums)

	groupHasAuth := make(map[int]bool)
	groupHasState := make(map[int]bool)
	for _, n := range nums {
		rg := raw[n]
		if rg.authKeySet {
			groupHasAuth[n] = true
		}
		if rg.stateFileSet {
			groupHasState[n] = true
		}
	}

	for _, n := range nums {
		rg := raw[n]
		// -K/-T without number only applies to group 0 (default)
		if n == 0 {
			if rg.authKey == "" {
				rg.authKey = lastAuthKey
			}
			if rg.stateFile == "" {
				rg.stateFile = lastStateFile
			}
		}
	}

	// Inherit -P from group -1 (applies to all groups)
	for key, pass := range inheritedPasswords {
		for _, n := range nums {
			if n == -1 {
				continue
			}
			rg := raw[n]
			if _, has := rg.passwords[key]; !has {
				rg.passwords[key] = pass
			}
		}
	}

	// Inherit -A from group -1 (applies to all groups)
	for key, ips := range inheritedAccepts {
		for _, n := range nums {
			if n == -1 {
				continue
			}
			rg := raw[n]
			if _, has := rg.accepts[key]; !has {
				rg.accepts[key] = ips
			}
		}
	}

	// Inherit -H from group -1 (applies to all groups)
	if lastHostname != "" {
		for _, n := range nums {
			if n == -1 {
				continue
			}
			rg := raw[n]
			if !rg.hostnameSet {
				rg.hostname = lastHostname
			}
		}
	}

	// Check coexistence limit
	hasNoNumberGroup := false
	hasNumberedGroup := false
	if rg, ok := raw[-1]; ok {
		// Group -1 is considered "active" if it has any mappings or explicit auth/state.
		if len(rg.entries) > 0 || rg.authKeySet || rg.stateFileSet {
			hasNoNumberGroup = true
		}
	}
	for _, n := range nums {
		if n >= 0 {
			rg := raw[n]
			if len(rg.entries) > 0 || rg.authKeySet || rg.stateFileSet {
				hasNumberedGroup = true
			}
		}
	}
	if hasNoNumberGroup && hasNumberedGroup {
		return nil, fmt.Errorf("numbered groups and no-number groups (except global -A/-P) cannot coexist")
	}

	// Validate
	for _, n := range nums {
		rg := raw[n]

		if n == -1 && len(rg.entries) == 0 {
			continue
		}

		groupExists := false
		if n > 0 {
			groupExists = groupHasAuth[n] || groupHasState[n] || rg.authKey != "" || rg.stateFile != ""
		} else {
			groupExists = groupHasAuth[n] || groupHasState[n] || len(rg.entries) > 0
		}
		if !groupExists {
			return nil, fmt.Errorf("group %d: no -K%d or -T%d", n, n, n)
		}

		if groupHasAuth[n] && groupHasState[n] {
			if _, err := os.Stat(rg.stateFile); err == nil {
				return nil, fmt.Errorf("group %d: state file %s already exists, -K%d is not needed", n, rg.stateFile, n)
			}
		}

		if rg.stateFile == "" {
			rg.stateFile = "tailscaled.state"
		}

		if len(rg.entries) == 0 {
			if n == -1 {
				return nil, fmt.Errorf("no-number group: missing -S or -C")
			}
			return nil, fmt.Errorf("group %d: missing -S or -C", n)
		}

		if rg.authKey == "" && !rg.stateFileSet {
			// No -K and no -T → check if default state file exists
			if _, err := os.Stat(rg.stateFile); err != nil {
				if n == -1 {
					return nil, fmt.Errorf("no-number group: state file %s not found, requires -K", rg.stateFile)
				}
				return nil, fmt.Errorf("group %d: state file %s not found, requires -K%d", n, rg.stateFile, n)
			}
		}
		if rg.authKey == "" && rg.stateFileSet {
			// -T only (no -K) → check state file exists
			if _, err := os.Stat(rg.stateFile); err != nil {
				if n == -1 {
					return nil, fmt.Errorf("no-number group: state file %s not found, requires -K", rg.stateFile)
				}
				return nil, fmt.Errorf("group %d: state file %s not found, requires -K%d", n, rg.stateFile, n)
			}
		}
	}

	// Build TunnelGroups
	var groups []TunnelGroup
	for _, n := range nums {
		rg := raw[n]

		if len(rg.entries) == 0 {
			continue
		}

		g := TunnelGroup{
			AuthKey:   rg.authKey,
			StateFile: rg.stateFile,
			Hostname:  rg.hostname,
			Ports:     make(map[string]*PortEntry),
		}

		type portInfo struct {
			direction string
			sub       string
		}
		usedPorts := make(map[string]portInfo) // key: direction + port number

		for key, entry := range rg.entries {
			// key is direction+sub (e.g., "Sa", "Ca", "S", "C")
			sub := key[1:] // extract sub part after direction char

			listenPort, addr, targetPort, err := parsePortMapping(entry.mapping)
			if err != nil {
				return nil, fmt.Errorf("group %d -%s%s: %v", n, entry.direction, sub, err)
			}

			portKey := fmt.Sprintf("%s%d", entry.direction, listenPort)
			if first, ok := usedPorts[portKey]; ok {
				return nil, fmt.Errorf("group %d: port %d used by both -%s%s and -%s%s", n, listenPort, first.direction, first.sub, entry.direction, sub)
			}
			usedPorts[portKey] = portInfo{direction: entry.direction, sub: sub}

			// Resolve hostname to IP for NAT processing
			addr = resolveHost(addr)

			pe := &PortEntry{
				IsServer:   entry.direction == "S",
				ListenPort: listenPort,
				TargetAddr: addr,
				TargetPort: targetPort,
			}

			// Accept lookup: direction+sub → direction → sub → global
			// -A always has direction, so keys are "SA", "S", "CA", "C"
			dirChar := entry.direction // "S" or "C"
			acceptKeys := []string{dirChar + sub, dirChar}
			for _, key := range acceptKeys {
				if ipStr, ok := rg.accepts[key]; ok {
					prefixes, err := parseIPList(ipStr)
					if err != nil {
						return nil, fmt.Errorf("group %d -A%s: %v", n, key, err)
					}
					pe.Accept = prefixes
					break
				}
			}

			// Password lookup: dir+sub → dir → sub → global
			// Keys: "SA"/"S"/"CA"/"C" for direction-specific, "A"/"sub" for sub-only, "" for global
			passKeys := []string{dirChar + sub, dirChar, sub, ""}
			for _, key := range passKeys {
				if pass, ok := rg.passwords[key]; ok {
					pe.Password = pass
					break
				}
			}

			g.Ports[entry.direction+sub] = pe
		}

		// Determine if VPN is untrusted (drop ICMP)
		// - No server ports at all → no one can connect → drop ICMP
		// - All server ports have passwords → untrusted → drop ICMP
		// - Any server port without password → partially trusted → respond to ICMP
		hasServerPorts := false
		allServerPassworded := true
		for _, pe := range g.Ports {
			if pe.IsServer {
				hasServerPorts = true
				if pe.Password == "" {
					allServerPassworded = false
					break
				}
			}
		}
		g.DropICMP = !hasServerPorts || allServerPassworded

		groups = append(groups, g)
	}

	if len(groups) == 0 {
		return nil, fmt.Errorf("no -S or -C provided")
	}

	return groups, nil
}
