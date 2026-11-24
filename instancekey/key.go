// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: Apache-2.0

// Package instancekey handles the X25519 static keys of feed clients and
// servers, and their text forms.
//
// A public key is written like an SSH public key without the comment:
//
//	x25519 <base64 of the 32-byte key>
//
// The client's public key in this form is its instance ID. A private key is
// stored as PEM, type "X25519 PRIVATE KEY", holding the 32-byte scalar.
package instancekey

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"strings"
)

// KeyType is the type name in the text form of a public key.
const KeyType = "x25519"

// PEMType is the PEM block type of a private key.
const PEMType = "X25519 PRIVATE KEY"

// Size is the length of keys in bytes.
const Size = 32

// PublicKey is an X25519 public key.
type PublicKey [Size]byte

// PrivateKey is an X25519 private key.
type PrivateKey struct {
	priv [Size]byte
	pub  PublicKey
}

// Generate creates a private key from rand (crypto/rand when nil).
func Generate(r io.Reader) (*PrivateKey, error) {
	if r == nil {
		r = rand.Reader
	}
	var b [Size]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return nil, fmt.Errorf("instancekey: %w", err)
	}
	return FromBytes(b[:])
}

// FromBytes returns the private key with the given 32-byte scalar.
func FromBytes(b []byte) (*PrivateKey, error) {
	k, err := ecdh.X25519().NewPrivateKey(b)
	if err != nil {
		return nil, fmt.Errorf("instancekey: %w", err)
	}
	p := &PrivateKey{}
	copy(p.priv[:], b)
	copy(p.pub[:], k.PublicKey().Bytes())
	return p, nil
}

// Bytes returns the 32-byte scalar.
func (k *PrivateKey) Bytes() []byte { return append([]byte(nil), k.priv[:]...) }

// Public returns the public key.
func (k *PrivateKey) Public() PublicKey { return k.pub }

// MarshalPEM encodes the private key as PEM.
func (k *PrivateKey) MarshalPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: PEMType, Bytes: k.priv[:]})
}

// ParsePEM decodes a private key written by MarshalPEM.
func ParsePEM(data []byte) (*PrivateKey, error) {
	b, _ := pem.Decode(data)
	if b == nil {
		return nil, errors.New("instancekey: no PEM block")
	}
	if b.Type != PEMType {
		return nil, fmt.Errorf("instancekey: PEM type %q, want %q", b.Type, PEMType)
	}
	if len(b.Bytes) != Size {
		return nil, fmt.Errorf("instancekey: key is %d bytes, want %d", len(b.Bytes), Size)
	}
	return FromBytes(b.Bytes)
}

// String returns the text form, "x25519 <base64>".
func (p PublicKey) String() string {
	return KeyType + " " + base64.StdEncoding.EncodeToString(p[:])
}

// ParsePublicKey parses the text form. Text after the key (a comment, as in
// SSH public key lines) is ignored.
func ParsePublicKey(s string) (PublicKey, error) {
	f := strings.Fields(s)
	if len(f) < 2 || f[0] != KeyType {
		return PublicKey{}, fmt.Errorf("instancekey: want %q followed by base64", KeyType)
	}
	b, err := base64.StdEncoding.DecodeString(f[1])
	if err != nil || len(b) != Size {
		return PublicKey{}, errors.New("instancekey: bad public key encoding")
	}
	var p PublicKey
	copy(p[:], b)
	if p == (PublicKey{}) {
		return PublicKey{}, errors.New("instancekey: zero public key")
	}
	return p, nil
}

// PublicKeyFromBytes returns the public key with the given 32 bytes.
func PublicKeyFromBytes(b []byte) (PublicKey, error) {
	if len(b) != Size {
		return PublicKey{}, fmt.Errorf("instancekey: key is %d bytes, want %d", len(b), Size)
	}
	var p PublicKey
	copy(p[:], b)
	return p, nil
}
