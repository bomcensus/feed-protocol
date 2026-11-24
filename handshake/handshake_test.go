// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: Apache-2.0

package handshake

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/bomcensus/feed-protocol/instancekey"
)

func key(t *testing.T, b byte) *instancekey.PrivateKey {
	t.Helper()
	k, err := instancekey.FromBytes(bytes.Repeat([]byte{b}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func run(t *testing.T, client, server *instancekey.PrivateKey, cr, sr byte) (Keys, Keys, Welcome, *Responder, instancekey.PublicKey) {
	t.Helper()
	hello := Hello{Client: "bomcensus", Version: "1.0.0", Time: 1795000000, Telemetry: true}
	ini, msg1, err := Start(Version, client, hello, bytes.NewReader(bytes.Repeat([]byte{cr}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := Read(Version, server, msg1, bytes.NewReader(bytes.Repeat([]byte{sr}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	if resp.Client() != client.Public() || resp.Hello() != hello {
		t.Fatalf("responder saw %v %+v", resp.Client(), resp.Hello())
	}
	welcome := Welcome{SessionExpires: 1795086400, Heartbeat: 300, IdleTimeout: 900, Grade: "anonymous", ServerTime: 1795000001}
	msg2, sk, err := resp.Accept(welcome)
	if err != nil {
		t.Fatal(err)
	}
	ck, w, serverPub, err := ini.Finish(msg2)
	if err != nil {
		t.Fatal(err)
	}
	return ck, sk, w, resp, serverPub
}

func TestRoundTrip(t *testing.T) {
	client, server := key(t, 1), key(t, 2)
	ck, sk, w, _, serverPub := run(t, client, server, 3, 4)
	if ck != sk {
		t.Fatalf("keys differ:\n%+v\n%+v", ck, sk)
	}
	if serverPub != server.Public() {
		t.Errorf("server key %v", serverPub)
	}
	if w.Grade != "anonymous" || w.Heartbeat != 300 || w.SessionExpires != 1795086400 {
		t.Errorf("welcome %+v", w)
	}
	if ck.ClientToServer == ck.ServerToClient || len(ck.SessionID) != 22 {
		t.Errorf("keys %+v", ck)
	}
	// Fresh ephemeral keys give a fresh session.
	ck2, _, _, _, _ := run(t, client, server, 5, 6)
	if ck2.SessionID == ck.SessionID || ck2.ClientToServer == ck.ClientToServer {
		t.Error("two handshakes derived the same keys")
	}
}

// The derivation is fixed by the specification; these values change only
// with it.
func TestVector(t *testing.T) {
	ck, _, _, _, _ := run(t, key(t, 1), key(t, 2), 3, 4)
	got := []string{ck.SessionID, hex.EncodeToString(ck.ClientToServer[:]), hex.EncodeToString(ck.ServerToClient[:])}
	want := []string{vectorSessionID, vectorC2S, vectorS2C}
	for i := range got {
		if got[i] != want[i] {
			t.Errorf("vector %d: %s, want %s", i, got[i], want[i])
		}
	}
}

func TestTampered(t *testing.T) {
	client, server := key(t, 1), key(t, 2)
	ini, msg1, err := Start(Version, client, Hello{Client: "c"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	// A changed Hello is accepted by the server but breaks the handshake hash.
	bad := bytes.Clone(msg1)
	bad[len(bad)-2] ^= 1
	resp, err := Read(Version, server, bad, nil)
	if err == nil {
		msg2, _, err := resp.Accept(Welcome{})
		if err != nil {
			t.Fatal(err)
		}
		if _, _, _, err := ini.Finish(msg2); err == nil {
			t.Error("client accepted a reply to a changed hello")
		}
	}
	// A changed reply fails on the client.
	ini, msg1, _ = Start(Version, client, Hello{Client: "c"}, nil)
	resp, err = Read(Version, server, msg1, nil)
	if err != nil {
		t.Fatal(err)
	}
	msg2, _, _ := resp.Accept(Welcome{})
	msg2[len(msg2)-1] ^= 1
	if _, _, _, err := ini.Finish(msg2); err == nil {
		t.Error("client accepted a changed reply")
	}
	if _, err := Read(Version, server, []byte("short"), nil); err == nil {
		t.Error("server accepted garbage")
	}
}

// A server that reads the first message under another version's prologue
// (a changed v parameter) reads it fine, but the client rejects the reply.
func TestPrologueMismatch(t *testing.T) {
	client, server := key(t, 1), key(t, 2)
	ini, msg1, err := Start(Version, client, Hello{Client: "c"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := read(Version, "bomcensus-feed/2", server, msg1, nil)
	if err != nil {
		t.Fatal(err)
	}
	msg2, _, err := resp.Accept(Welcome{})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := ini.Finish(msg2); err == nil {
		t.Fatal("client accepted a reply made under another prologue")
	}
}

func TestMediaType(t *testing.T) {
	if got := MediaType(1); got != "application/vnd.bomcensus.feed-noise; v=1" {
		t.Errorf("media type %q", got)
	}
	for in, want := range map[string]int{
		"application/vnd.bomcensus.feed-noise; v=1":     1,
		"Application/VND.Bomcensus.Feed-Noise;V=1":      1,
		"application/vnd.bomcensus.feed-noise; v=\"1\"": 1,
	} {
		if v, err := ParseMediaType(in); err != nil || v != want {
			t.Errorf("%q: %d %v", in, v, err)
		}
	}
	for _, in := range []string{"", "application/vnd.bomcensus.feed-noise", "application/vnd.bomcensus.feed-noise; v=2",
		"application/vnd.bomcensus.feed-noise; v=x", "application/json; v=1", "application/vnd.bomcensus.feed-noise; version=1"} {
		if _, err := ParseMediaType(in); !errors.Is(err, ErrUnsupportedVersion) {
			t.Errorf("%q: %v", in, err)
		}
	}
	if _, _, err := Start(2, key(t, 1), Hello{}, nil); !errors.Is(err, ErrUnsupportedVersion) {
		t.Errorf("start v2: %v", err)
	}
	if got := Supported(); len(got) != 1 || got[0] != 1 {
		t.Errorf("supported %v", got)
	}
}
