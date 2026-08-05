// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package ipnlocal

import (
	"context"
	"errors"
	"net"
	"testing"
)

func TestServeTargetIPLiteral(t *testing.T) {
	st := newServeTarget("127.0.0.1:8080")
	st.lookup = func(string) ([]string, error) {
		t.Fatal("lookup must not be called for an IP literal")
		return nil, nil
	}
	st.probe = func(string) bool {
		t.Fatal("probe must not be called for an IP literal")
		return false
	}
	if got := st.addr(); got != "127.0.0.1:8080" {
		t.Fatalf("addr() = %q, want 127.0.0.1:8080", got)
	}
}

func TestServeTargetPinsFirstNonEmpty(t *testing.T) {
	var probed []string
	st := newServeTarget("localhost:8080")
	st.lookup = func(string) ([]string, error) { return []string{"127.0.0.1", "::1"}, nil }
	st.probe = func(addr string) bool {
		probed = append(probed, addr)
		// Only the first candidate accepts connections.
		return addr == "127.0.0.1:8080"
	}
	if got := st.addr(); got != "127.0.0.1:8080" {
		t.Fatalf("addr() = %q, want 127.0.0.1:8080", got)
	}
	if len(probed) != 1 {
		t.Fatalf("probed %v, want resolution order to stop at the first open target", probed)
	}
}

func TestServeTargetHoldsFirstIPWhenAllEmpty(t *testing.T) {
	var probeCalls int
	st := newServeTarget("localhost:8080")
	st.lookup = func(string) ([]string, error) { return []string{"10.0.0.9", "10.0.0.10"}, nil }
	st.probe = func(string) bool {
		probeCalls++
		return false // everything is empty
	}
	// The first resolved IP is held even though nothing accepts connections.
	if got := st.addr(); got != "10.0.0.9:8080" {
		t.Fatalf("addr() = %q, want 10.0.0.9:8080 (first resolved IP held)", got)
	}
	firstCallProbes := probeCalls
	if firstCallProbes != 2 {
		t.Fatalf("first call probed %d candidates, want 2", firstCallProbes)
	}
	// Subsequent calls reuse the held IP without re-resolving or re-probing.
	if got := st.addr(); got != "10.0.0.9:8080" {
		t.Fatalf("second addr() = %q, want cached 10.0.0.9:8080", got)
	}
	if probeCalls != firstCallProbes {
		t.Fatalf("probe count grew from %d to %d, want no per-connection re-probing", firstCallProbes, probeCalls)
	}
}

func TestServeTargetFailsOverOnDialError(t *testing.T) {
	live := "127.0.0.1:8080"
	st := newServeTarget("localhost:8080")
	st.lookup = func(string) ([]string, error) { return []string{"127.0.0.1", "::1"}, nil }
	st.probe = func(addr string) bool { return addr == live }

	var attempts []string
	systemDial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		attempts = append(attempts, addr)
		if addr != live {
			return nil, errors.New("connection refused")
		}
		_, c2 := net.Pipe()
		return c2, nil
	}

	// First connection: pins and connects to the currently open 127.0.0.1.
	conn, target, err := st.dial(context.Background(), systemDial)
	if err != nil {
		t.Fatalf("initial dial: %v", err)
	}
	if target != "127.0.0.1:8080" {
		t.Fatalf("initial target = %q, want 127.0.0.1:8080", target)
	}
	conn.Close()

	// 127.0.0.1 dies; connection-time failure triggers re-resolution and
	// failover to the now-open ::1 (bracketed, as JoinHostPort emits it).
	live = "[::1]:8080"
	st.cur = "127.0.0.1:8080" // stale pinned address before the failure
	attempts = nil
	conn, target, err = st.dial(context.Background(), systemDial)
	if err != nil {
		t.Fatalf("failover dial: %v", err)
	}
	defer conn.Close()
	if target != "[::1]:8080" {
		t.Fatalf("failover target = %q, want [::1]:8080", target)
	}
	want := []string{"127.0.0.1:8080", "[::1]:8080"}
	if len(attempts) != len(want) || attempts[0] != want[0] || attempts[1] != want[1] {
		t.Fatalf("dial attempts = %v, want %v, "+
			"(initial pin then re-resolved failover address, no per-connection DNS)", attempts, want)
	}
}