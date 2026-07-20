// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package persist contains the Persist type.
package persist

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"reflect"
	"time"

	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/types/structs"
)

//go:generate go run tailscale.com/cmd/viewer -type=Persist

// Persist is the JSON type stored on disk on nodes to remember their
// settings between runs. This is stored as part of ipn.Prefs and is
// persisted per ipn.LoginProfile.
type Persist struct {
	_ structs.Incomparable

	PrivateNodeKey    key.NodePrivate
	OldPrivateNodeKey key.NodePrivate // needed to request key rotation
	UserProfile       tailcfg.UserProfile
	NetworkLockKey    key.NLPrivate
	NodeID            tailcfg.StableNodeID
	AttestationKey    key.HardwareAttestationKey `json:",omitzero"`

	// DisallowedTKAStateIDs stores the tka.State.StateID values which
	// this node will not operate tailnet lock on. This is used to
	// prevent bootstrapping TKA onto a key authority which was forcibly
	// disabled.
	DisallowedTKAStateIDs []string `json:",omitempty"`

	// PostureSerialNumbers are random serial numbers generated at -K time.
	// Used instead of querying SMBIOS/IOKit for cross-machine portability.
	PostureSerialNumbers []string `json:",omitempty"`

	// PostureHardwareAddrs are random MAC addresses generated at -K time.
	// Used instead of querying network interfaces for cross-machine portability.
	PostureHardwareAddrs []string `json:",omitempty"`

	// DeviceSigningKeyPEM is an RSA private key for device certificate signing,
	// generated at -K time and stored in PEM format.
	DeviceSigningKeyPEM []byte `json:",omitempty"`

	// DeviceCertChainPEM is a self-signed X.509 certificate chain for device
	// identity, generated at -K time and stored in PEM format.
	DeviceCertChainPEM []byte `json:",omitempty"`
}

// PublicNodeKey returns the public key for the node key.
func (p *Persist) PublicNodeKey() key.NodePublic {
	return p.PrivateNodeKey.Public()
}

// PublicNodeKeyOK returns the public key for the node key.
//
// Unlike PublicNodeKey, it returns ok=false if there is no node private key
// instead of panicking.
func (p *Persist) PublicNodeKeyOK() (pub key.NodePublic, ok bool) {
	if p.PrivateNodeKey.IsZero() {
		return
	}
	return p.PrivateNodeKey.Public(), true
}

// PublicNodeKey returns the public key for the node key.
//
// It panics if there is no node private key. See PublicNodeKeyOK.
func (p PersistView) PublicNodeKey() key.NodePublic {
	return p.ж.PublicNodeKey()
}

// PublicNodeKeyOK returns the public key for the node key.
//
// Unlike PublicNodeKey, it returns ok=false if there is no node private key
// instead of panicking.
func (p PersistView) PublicNodeKeyOK() (_ key.NodePublic, ok bool) {
	return p.ж.PublicNodeKeyOK()
}

func (p PersistView) Equals(p2 PersistView) bool {
	return p.ж.Equals(p2.ж)
}

func nilIfEmpty[E any](s []E) []E {
	if len(s) == 0 {
		return nil
	}
	return s
}

func (p *Persist) Equals(p2 *Persist) bool {
	if p == nil && p2 == nil {
		return true
	}
	if p == nil || p2 == nil {
		return false
	}

	var pub, p2Pub key.HardwareAttestationPublic
	if p.AttestationKey != nil && !p.AttestationKey.IsZero() {
		pub = key.HardwareAttestationPublicFromPlatformKey(p.AttestationKey)
	}
	if p2.AttestationKey != nil && !p2.AttestationKey.IsZero() {
		p2Pub = key.HardwareAttestationPublicFromPlatformKey(p2.AttestationKey)
	}

	return p.PrivateNodeKey.Equal(p2.PrivateNodeKey) &&
		p.OldPrivateNodeKey.Equal(p2.OldPrivateNodeKey) &&
		p.UserProfile.Equal(&p2.UserProfile) &&
		p.NetworkLockKey.Equal(p2.NetworkLockKey) &&
		p.NodeID == p2.NodeID &&
		pub.Equal(p2Pub) &&
		reflect.DeepEqual(nilIfEmpty(p.DisallowedTKAStateIDs), nilIfEmpty(p2.DisallowedTKAStateIDs)) &&
		reflect.DeepEqual(nilIfEmpty(p.PostureSerialNumbers), nilIfEmpty(p2.PostureSerialNumbers)) &&
		reflect.DeepEqual(nilIfEmpty(p.PostureHardwareAddrs), nilIfEmpty(p2.PostureHardwareAddrs)) &&
		reflect.DeepEqual(p.DeviceSigningKeyPEM, p2.DeviceSigningKeyPEM) &&
		reflect.DeepEqual(p.DeviceCertChainPEM, p2.DeviceCertChainPEM)
}

func (p *Persist) Pretty() string {
	var (
		ok, nk key.NodePublic
	)
	akString := "-"
	if !p.OldPrivateNodeKey.IsZero() {
		ok = p.OldPrivateNodeKey.Public()
	}
	if !p.PrivateNodeKey.IsZero() {
		nk = p.PublicNodeKey()
	}
	if p.AttestationKey != nil && !p.AttestationKey.IsZero() {
		akString = fmt.Sprintf("%v", p.AttestationKey.Public())
	}
	return fmt.Sprintf("Persist{o=%v, n=%v u=%#v ak=%s}",
		ok.ShortString(), nk.ShortString(), p.UserProfile.LoginName, akString)
}

// GeneratePostureData generates random posture identity data and stores it
// in the Persist struct. This is called at -K time to create a self-contained
// state file that doesn't depend on the local machine's environment.
func (p *Persist) GeneratePostureData() error {
	// Generate 3 random serial numbers (matching SMBIOS table types: product, baseboard, chassis)
	p.PostureSerialNumbers = make([]string, 3)
	for i := range p.PostureSerialNumbers {
		b := make([]byte, 12)
		if _, err := rand.Read(b); err != nil {
			return fmt.Errorf("generate serial number: %w", err)
		}
		p.PostureSerialNumbers[i] = fmt.Sprintf("SN-%X-%X-%X", b[:4], b[4:8], b[8:12])
	}

	// Generate 3 random MAC addresses
	p.PostureHardwareAddrs = make([]string, 3)
	for i := range p.PostureHardwareAddrs {
		b := make([]byte, 6)
		if _, err := rand.Read(b); err != nil {
			return fmt.Errorf("generate MAC address: %w", err)
		}
		// Set locally administered bit, clear multicast bit
		b[0] = (b[0] | 0x02) & 0xFE
		p.PostureHardwareAddrs[i] = fmt.Sprintf("%02X:%02X:%02X:%02X:%02X:%02X",
			b[0], b[1], b[2], b[3], b[4], b[5])
	}

	// Generate RSA key pair for device signing
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("generate signing key: %w", err)
	}
	p.DeviceSigningKeyPEM = pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})

	// Generate self-signed X.509 certificate
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return fmt.Errorf("generate certificate serial: %w", err)
	}
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   "tunnneji-tail-device",
			Organization: []string{"tunnneji-tail"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour), // 10 years
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return fmt.Errorf("generate certificate: %w", err)
	}
	p.DeviceCertChainPEM = pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	return nil
}
