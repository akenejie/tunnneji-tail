// Copyright (C) 2026 アケネＪ / Akenejie
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package cli

import "testing"

func TestParsePortMapping(t *testing.T) {
	tests := []struct {
		in         string
		port       int
		addr       string
		targetPort int
		wantErr    bool
	}{
		// IPv4 / hostname, no explicit target port (target == listen)
		{"8080:127.0.0.1", 8080, "127.0.0.1", 8080, false},
		{"8080:localhost", 8080, "localhost", 8080, false},
		{"10000:localhost:8080", 10000, "localhost", 8080, false},
		{"8080:127.0.0.1:80", 8080, "127.0.0.1", 80, false},
		{"10000:10.0.0.5:22", 10000, "10.0.0.5", 22, false},
		// IPv6 bracketed
		{"10000:[::1]:8080", 10000, "::1", 8080, false},
		{"10000:[::1]", 10000, "::1", 10000, false},
		{"8090:[fe80::1]:443", 8090, "fe80::1", 443, false},
		// Unbracketed IPv6 must be rejected (require brackets)
		{"8080:::1", 0, "", 0, true},
		{"10000:::1:8080", 0, "", 0, true},
		{"7000:2001:db8::1:80", 0, "", 0, true},
		// Errors
		{"", 0, "", 0, true},
		{"abc:def", 0, "", 0, true},
		{"8080:", 0, "", 0, true},
		{"8080", 0, "", 0, true},
		{"8080:127.0.0.1:xyz", 0, "", 0, true},
		{"8080:foo:bar:baz", 0, "", 0, true},
	}
	for _, tt := range tests {
		port, addr, targetPort, err := parsePortMapping(tt.in)
		if tt.wantErr {
			if err == nil {
				t.Errorf("parsePortMapping(%q): expected error, got port=%d addr=%q tport=%d", tt.in, port, addr, targetPort)
			}
			continue
		}
		if err != nil {
			t.Errorf("parsePortMapping(%q): unexpected error: %v", tt.in, err)
			continue
		}
		if port != tt.port || addr != tt.addr || targetPort != tt.targetPort {
			t.Errorf("parsePortMapping(%q) = (%d, %q, %d), want (%d, %q, %d)",
				tt.in, port, addr, targetPort, tt.port, tt.addr, tt.targetPort)
		}
	}
}

func TestFormatIP(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"127.0.0.1", "127.0.0.1"},
		{"::1", "[::1]"},
		{"fe80::1", "[fe80::1]"},
		{"[::1]", "[::1]"},
	}
	for _, tt := range tests {
		if got := resolveHost(tt.in); got != tt.want {
			t.Errorf("resolveHost(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}