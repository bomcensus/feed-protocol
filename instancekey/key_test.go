// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: Apache-2.0

package instancekey

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
)

// RFC 7748 section 6.1: Alice's private and public key.
const (
	alicePriv = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"
	alicePub  = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
)

func TestKnownKey(t *testing.T) {
	b, _ := hex.DecodeString(alicePriv)
	k, err := FromBytes(b)
	if err != nil {
		t.Fatal(err)
	}
	pub := k.Public()
	if hex.EncodeToString(pub[:]) != alicePub {
		t.Fatalf("public %x", pub)
	}
	if got := pub.String(); got != "x25519 hSDwCYkwp1R0i33ctD73Wg2/Og0mOBr066SpjqqbTmo=" {
		t.Fatalf("id %q", got)
	}
}

func TestRoundTrip(t *testing.T) {
	k, err := Generate(nil)
	if err != nil {
		t.Fatal(err)
	}
	k2, err := ParsePEM(k.MarshalPEM())
	if err != nil || !bytes.Equal(k2.Bytes(), k.Bytes()) || k2.Public() != k.Public() {
		t.Fatalf("pem: %v", err)
	}
	if !strings.Contains(string(k.MarshalPEM()), "-----BEGIN X25519 PRIVATE KEY-----") {
		t.Errorf("pem: %s", k.MarshalPEM())
	}
	p, err := ParsePublicKey(k.Public().String() + " comment@host")
	if err != nil || p != k.Public() {
		t.Fatalf("public: %v", err)
	}
}

func TestParseErrors(t *testing.T) {
	for _, s := range []string{"", "x25519", "ssh-ed25519 AAAA", "x25519 !!!", "x25519 AAAA",
		"x25519 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="} {
		if _, err := ParsePublicKey(s); err == nil {
			t.Errorf("accepted %q", s)
		}
	}
	if _, err := ParsePEM([]byte("-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n")); err == nil {
		t.Error("accepted another PEM type")
	}
	if _, err := FromBytes(make([]byte, 31)); err == nil {
		t.Error("accepted a short key")
	}
}
