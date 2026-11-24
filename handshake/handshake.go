// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: Apache-2.0

// Package handshake runs the session handshake between a feed client and a
// feed server, one message each way. Version 1 is
// Noise_IX_25519_AESGCM_SHA256:
//
//	-> e, s                  client: Hello (plaintext, bound into the hash)
//	<- e, ee, se, s, es      server: Welcome (encrypted)
//
// The version travels outside the Noise messages, as the v parameter of
// their media type ("application/vnd.bomcensus.feed-noise; v=1"), and both
// sides use "bomcensus-feed/<v>" as the prologue: a changed version makes
// the handshake fail instead of silently selecting another protocol.
//
// Both sides then derive the same Keys: a session ID and one MAC key per
// direction. Neither is sent.
package handshake

import (
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"sort"
	"strconv"

	"github.com/flynn/noise"

	"github.com/bomcensus/feed-protocol/instancekey"
)

// Version is the protocol version clients use.
const Version = 1

// MediaTypeBase is the media type of handshake messages, without the
// version parameter.
const MediaTypeBase = "application/vnd.bomcensus.feed-noise"

// ErrUnsupportedVersion: the media type names no version, or one this
// implementation does not have.
var ErrUnsupportedVersion = errors.New("handshake: unsupported protocol version")

// suites are the handshake of each version.
var suites = map[int]struct {
	pattern noise.HandshakePattern
	cipher  noise.CipherSuite
}{
	1: {noise.HandshakeIX, noise.NewCipherSuite(noise.DH25519, noise.CipherAESGCM, noise.HashSHA256)},
}

// Supported returns the versions this implementation speaks, ascending.
func Supported() []int {
	out := make([]int, 0, len(suites))
	for v := range suites {
		out = append(out, v)
	}
	sort.Ints(out)
	return out
}

// MediaType returns the media type of version v's handshake messages.
func MediaType(v int) string { return MediaTypeBase + "; v=" + strconv.Itoa(v) }

// ParseMediaType returns the version named by a Content-Type value. The
// error is ErrUnsupportedVersion (wrapped) for another media type, a
// missing or malformed v, or a version that is not supported.
func ParseMediaType(s string) (int, error) {
	mt, params, err := mime.ParseMediaType(s)
	if err != nil || mt != MediaTypeBase {
		return 0, fmt.Errorf("%w: content type %q, want %q", ErrUnsupportedVersion, s, MediaType(Version))
	}
	v, err := strconv.Atoi(params["v"])
	if err != nil {
		return 0, fmt.Errorf("%w: missing or malformed v parameter in %q", ErrUnsupportedVersion, s)
	}
	if _, ok := suites[v]; !ok {
		return 0, fmt.Errorf("%w: version %d", ErrUnsupportedVersion, v)
	}
	return v, nil
}

// Prologue returns the prologue of version v.
func Prologue(v int) string { return "bomcensus-feed/" + strconv.Itoa(v) }

// Info strings of the key derivation.
const (
	infoMAC       = "bomcensus-feed/1 mac"
	infoSessionID = "bomcensus-feed/1 session id"
)

// Hello is the client's handshake payload. It travels in plaintext: it is
// bound into the handshake hash, so a change makes the handshake fail, but
// it is visible on the wire.
type Hello struct {
	Client  string `json:"client"`  // software name, e.g. "bomcensus"
	Version string `json:"version"` // software version
	Time    int64  `json:"time"`    // unix seconds, for the server's clock check
	// Telemetry allows the server to count the client's queries in its
	// anonymous statistics.
	Telemetry bool `json:"telemetry"`
}

// Welcome is the server's handshake payload (encrypted).
type Welcome struct {
	SessionExpires int64  `json:"session_expires"` // unix seconds; the session cannot be extended
	Heartbeat      int    `json:"heartbeat"`       // seconds between heartbeats
	IdleTimeout    int    `json:"idle_timeout"`    // seconds without a request before the session ends
	Grade          string `json:"grade"`           // the server's grade of the instance
	ServerTime     int64  `json:"server_time"`     // unix seconds
}

// Keys are what both sides derive from a completed handshake.
type Keys struct {
	// SessionID names the session in request headers. It is not secret.
	SessionID string
	// ClientToServer signs requests, ServerToClient signs responses.
	ClientToServer [32]byte
	ServerToClient [32]byte
}

func newState(version int, prologue string, key *instancekey.PrivateKey, initiator bool, random io.Reader) (*noise.HandshakeState, error) {
	s, ok := suites[version]
	if !ok {
		return nil, fmt.Errorf("%w: version %d", ErrUnsupportedVersion, version)
	}
	pub := key.Public()
	return noise.NewHandshakeState(noise.Config{
		CipherSuite:   s.cipher,
		Random:        random,
		Pattern:       s.pattern,
		Initiator:     initiator,
		Prologue:      []byte(prologue),
		StaticKeypair: noise.DHKey{Private: key.Bytes(), Public: pub[:]},
	})
}

// derive computes the session keys from the split cipher states and the
// handshake hash h.
//
//	mac_c2s || mac_s2c = HKDF-SHA256(ikm = k1 || k2, salt = h, info = "bomcensus-feed/1 mac", 64)
//	session_id         = base64url(HKDF-SHA256(ikm = h, salt = "", info = "bomcensus-feed/1 session id", 16))
func derive(h []byte, c1, c2 *noise.CipherState) (Keys, error) {
	if c1 == nil || c2 == nil {
		return Keys{}, errors.New("handshake: not complete")
	}
	k1, k2 := c1.UnsafeKey(), c2.UnsafeKey()
	mac, err := hkdf.Key(sha256.New, append(k1[:], k2[:]...), h, infoMAC, 64)
	if err != nil {
		return Keys{}, err
	}
	sid, err := hkdf.Key(sha256.New, h, nil, infoSessionID, 16)
	if err != nil {
		return Keys{}, err
	}
	var k Keys
	k.SessionID = base64.RawURLEncoding.EncodeToString(sid)
	copy(k.ClientToServer[:], mac[:32])
	copy(k.ServerToClient[:], mac[32:])
	return k, nil
}

// Initiator is the client side of a handshake in progress.
type Initiator struct {
	hs      *noise.HandshakeState
	version int
}

// Version returns the protocol version of the handshake.
func (i *Initiator) Version() int { return i.version }

// Start begins a handshake of the given version and returns the first
// message, to be sent with Content-Type MediaType(version). random supplies
// the ephemeral key (crypto/rand when nil).
func Start(version int, key *instancekey.PrivateKey, hello Hello, random io.Reader) (*Initiator, []byte, error) {
	hs, err := newState(version, Prologue(version), key, true, random)
	if err != nil {
		return nil, nil, err
	}
	payload, err := json.Marshal(hello)
	if err != nil {
		return nil, nil, err
	}
	msg, _, _, err := hs.WriteMessage(nil, payload)
	if err != nil {
		return nil, nil, fmt.Errorf("handshake: %w", err)
	}
	return &Initiator{hs: hs, version: version}, msg, nil
}

// Finish reads the server's message. It returns the keys, the Welcome and
// the server's static public key, which the caller must check against the
// key it trusts for that server.
func (i *Initiator) Finish(msg []byte) (Keys, Welcome, instancekey.PublicKey, error) {
	payload, c1, c2, err := i.hs.ReadMessage(nil, msg)
	if err != nil {
		return Keys{}, Welcome{}, instancekey.PublicKey{}, fmt.Errorf("handshake: %w", err)
	}
	server, err := instancekey.PublicKeyFromBytes(i.hs.PeerStatic())
	if err != nil {
		return Keys{}, Welcome{}, instancekey.PublicKey{}, err
	}
	keys, err := derive(i.hs.ChannelBinding(), c1, c2)
	if err != nil {
		return Keys{}, Welcome{}, instancekey.PublicKey{}, err
	}
	var w Welcome
	if err := json.Unmarshal(payload, &w); err != nil {
		return Keys{}, Welcome{}, instancekey.PublicKey{}, fmt.Errorf("handshake: welcome: %w", err)
	}
	return keys, w, server, nil
}

// Responder is the server side of a handshake in progress.
type Responder struct {
	hs      *noise.HandshakeState
	version int
	hello   Hello
	client  instancekey.PublicKey
}

// Read reads the client's first message, of the version its Content-Type
// named (see ParseMediaType). The server decides from Hello and Client
// whether to Accept, and answers with Content-Type MediaType(version).
func Read(version int, key *instancekey.PrivateKey, msg []byte, random io.Reader) (*Responder, error) {
	return read(version, Prologue(version), key, msg, random)
}

func read(version int, prologue string, key *instancekey.PrivateKey, msg []byte, random io.Reader) (*Responder, error) {
	hs, err := newState(version, prologue, key, false, random)
	if err != nil {
		return nil, err
	}
	payload, _, _, err := hs.ReadMessage(nil, msg)
	if err != nil {
		return nil, fmt.Errorf("handshake: %w", err)
	}
	client, err := instancekey.PublicKeyFromBytes(hs.PeerStatic())
	if err != nil {
		return nil, err
	}
	var h Hello
	if err := json.Unmarshal(payload, &h); err != nil {
		return nil, fmt.Errorf("handshake: hello: %w", err)
	}
	return &Responder{hs: hs, version: version, hello: h, client: client}, nil
}

// Version returns the protocol version of the handshake.
func (r *Responder) Version() int { return r.version }

// Hello returns the client's payload.
func (r *Responder) Hello() Hello { return r.hello }

// Client returns the client's static public key (its instance ID).
func (r *Responder) Client() instancekey.PublicKey { return r.client }

// Accept completes the handshake and returns the second message and the
// keys.
func (r *Responder) Accept(w Welcome) ([]byte, Keys, error) {
	payload, err := json.Marshal(w)
	if err != nil {
		return nil, Keys{}, err
	}
	msg, c1, c2, err := r.hs.WriteMessage(nil, payload)
	if err != nil {
		return nil, Keys{}, fmt.Errorf("handshake: %w", err)
	}
	keys, err := derive(r.hs.ChannelBinding(), c1, c2)
	if err != nil {
		return nil, Keys{}, err
	}
	return msg, keys, nil
}
