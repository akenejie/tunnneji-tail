package netstack

import (
	"crypto/sha256"
	"crypto/rand"
	"errors"
	"io"
	"net"

	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"golang.org/x/crypto/chacha20"
)

const Chacha20NonceLen = chacha20.NonceSize // 12 bytes

func DeriveKey(password string) [32]byte {
	return sha256.Sum256([]byte(password))
}

// encryptedTCPConn wraps a gonet.TCPConn with ChaCha20 encryption/decryption
type encryptedTCPConn struct {
	*gonet.TCPConn
	encWriter io.Writer
	decReader io.Reader
}

func newEncryptedTCPConn(conn *gonet.TCPConn, password string) (*encryptedTCPConn, error) {
	key := DeriveKey(password)

	// Receive encrypted from VPN client, decrypt
	decReader, err := NewChacha20Reader(conn, key)
	if err != nil {
		return nil, err
	}

	// Send to VPN client, encrypt
	encWriter, err := NewChacha20Writer(conn, key)
	if err != nil {
		return nil, err
	}

	return &encryptedTCPConn{
		TCPConn:   conn,
		encWriter: encWriter,
		decReader: decReader,
	}, nil
}

func (c *encryptedTCPConn) Read(p []byte) (int, error) {
	return c.decReader.Read(p)
}

func (c *encryptedTCPConn) Write(p []byte) (int, error) {
	return c.encWriter.Write(p)
}

type Chacha20Reader struct {
	r      io.Reader
	cipher *chacha20.Cipher
}

func NewChacha20Reader(r io.Reader, key [32]byte) (*Chacha20Reader, error) {
	nonce := make([]byte, Chacha20NonceLen)
	if _, err := io.ReadFull(r, nonce); err != nil {
		return nil, err
	}
	cipher, err := chacha20.NewUnauthenticatedCipher(key[:], nonce)
	if err != nil {
		return nil, err
	}
	return &Chacha20Reader{r: r, cipher: cipher}, nil
}

func (r *Chacha20Reader) Read(p []byte) (int, error) {
	n, err := r.r.Read(p)
	if n > 0 {
		r.cipher.XORKeyStream(p[:n], p[:n])
	}
	return n, err
}

type Chacha20Writer struct {
	w      io.Writer
	cipher *chacha20.Cipher
}

func NewChacha20Writer(w io.Writer, key [32]byte) (*Chacha20Writer, error) {
	nonce := make([]byte, Chacha20NonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	if _, err := w.Write(nonce); err != nil {
		return nil, err
	}
	cipher, err := chacha20.NewUnauthenticatedCipher(key[:], nonce)
	if err != nil {
		return nil, err
	}
	return &Chacha20Writer{w: w, cipher: cipher}, nil
}

func (w *Chacha20Writer) Write(p []byte) (int, error) {
	encrypted := make([]byte, len(p))
	w.cipher.XORKeyStream(encrypted, p)
	return w.w.Write(encrypted)
}

var errUDPPacketTooShort = errors.New("encrypted UDP packet too short")

// EncryptUDPPacket encrypts a complete UDP datagram with a fresh random
// nonce. The output format is [12-byte nonce][ciphertext].
func EncryptUDPPacket(plaintext []byte, key [32]byte) ([]byte, error) {
	nonce := make([]byte, Chacha20NonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	cipher, err := chacha20.NewUnauthenticatedCipher(key[:], nonce)
	if err != nil {
		return nil, err
	}
	out := make([]byte, Chacha20NonceLen+len(plaintext))
	copy(out, nonce)
	cipher.XORKeyStream(out[Chacha20NonceLen:], plaintext)
	return out, nil
}

// DecryptUDPPacket decrypts a datagram previously produced by
// EncryptUDPPacket, returning the plaintext.
func DecryptUDPPacket(packet []byte, key [32]byte) ([]byte, error) {
	if len(packet) < Chacha20NonceLen {
		return nil, errUDPPacketTooShort
	}
	cipher, err := chacha20.NewUnauthenticatedCipher(key[:], packet[:Chacha20NonceLen])
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(packet)-Chacha20NonceLen)
	cipher.XORKeyStream(out, packet[Chacha20NonceLen:])
	return out, nil
}

// encryptedUDPPacketConn wraps a net.PacketConn with per-datagram ChaCha20
// encryption. Every datagram read/written carries its own nonce prefix, so the
// stream-less nature of UDP is preserved while still applying the port
// password to the traffic.
type encryptedUDPPacketConn struct {
	net.PacketConn
	key [32]byte
}

func newEncryptedUDPPacketConn(conn net.PacketConn, password string) *encryptedUDPPacketConn {
	return &encryptedUDPPacketConn{PacketConn: conn, key: DeriveKey(password)}
}

func (c *encryptedUDPPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	n, addr, err := c.PacketConn.ReadFrom(b)
	if err != nil {
		return 0, addr, err
	}
	dec, err := DecryptUDPPacket(b[:n], c.key)
	if err != nil {
		return 0, addr, err
	}
	return copy(b, dec), addr, nil
}

func (c *encryptedUDPPacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	enc, err := EncryptUDPPacket(b, c.key)
	if err != nil {
		return 0, err
	}
	return c.PacketConn.WriteTo(enc, addr)
}

