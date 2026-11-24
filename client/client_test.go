// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	feedprotocol "github.com/bomcensus/feed-protocol"
	"github.com/bomcensus/feed-protocol/handshake"
	"github.com/bomcensus/feed-protocol/instancekey"
	"github.com/bomcensus/feed-protocol/server"
)

// testServer implements the session endpoints and one protected path.
type testServer struct {
	key        *instancekey.PrivateKey
	mu         sync.Mutex
	sessions   map[string]*server.Session
	active     map[string]bool
	handshakes int
	tamper     bool
	ttl        time.Duration // session lifetime handed out
	replyType  string        // Content-Type of the handshake reply, if set
}

func (ts *testServer) Session(_ context.Context, id string) (server.Session, error) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	s, ok := ts.sessions[id]
	if !ok {
		return server.Session{}, server.ErrUnknownSession
	}
	return *s, nil
}

func (ts *testServer) handler(t *testing.T) http.Handler {
	v := &server.Verifier{Sessions: ts, Verified: func(r *http.Request, s server.Session) error {
		ts.mu.Lock()
		ts.active[s.ID] = true
		ts.mu.Unlock()
		return nil
	}}
	mux := http.NewServeMux()
	mux.HandleFunc("POST "+feedprotocol.SessionPath, func(w http.ResponseWriter, r *http.Request) {
		v, err := handshake.ParseMediaType(r.Header.Get("Content-Type"))
		if err != nil {
			server.WriteError(w, http.StatusUnsupportedMediaType, feedprotocol.CodeUnsupportedProtocol, err.Error())
			return
		}
		msg, _ := io.ReadAll(r.Body)
		resp, err := handshake.Read(v, ts.key, msg, nil)
		if err != nil {
			server.WriteError(w, 400, feedprotocol.CodeBadHandshake, err.Error())
			return
		}
		if resp.Hello().Client != "test" {
			t.Errorf("hello %+v", resp.Hello())
		}
		ttl := ts.ttl
		if ttl == 0 {
			ttl = 24 * time.Hour
		}
		msg2, keys, err := resp.Accept(handshake.Welcome{SessionExpires: time.Now().Add(ttl).Unix(), Heartbeat: 1, Grade: "anonymous"})
		if err != nil {
			t.Fatal(err)
		}
		ts.mu.Lock()
		ts.handshakes++
		ts.sessions[keys.SessionID] = &server.Session{ID: keys.SessionID, InstanceID: resp.Client().String(),
			ClientToServer: keys.ClientToServer, ServerToClient: keys.ServerToClient}
		ts.mu.Unlock()
		w.Header().Set("Content-Type", handshake.MediaType(resp.Version()))
		if ts.replyType != "" {
			w.Header().Set("Content-Type", ts.replyType)
		}
		w.Write(msg2)
	})
	protected := http.NewServeMux()
	protected.HandleFunc("POST "+feedprotocol.HeartbeatPath, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(feedprotocol.Heartbeat{SessionExpires: time.Now().Add(time.Hour).Unix(), Grade: "anonymous"})
	})
	protected.HandleFunc("DELETE "+feedprotocol.SessionPath, func(w http.ResponseWriter, r *http.Request) {
		s, _ := server.FromContext(r.Context())
		ts.mu.Lock()
		delete(ts.sessions, s.ID)
		ts.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	})
	protected.HandleFunc("POST /v1/echo", func(w http.ResponseWriter, r *http.Request) {
		s, _ := server.FromContext(r.Context())
		b, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte(s.InstanceID + " " + string(b)))
	})
	mux.Handle("/", v.Middleware(protected))
	h := http.Handler(mux)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !ts.tamper || r.URL.Path != "/v1/echo" {
			h.ServeHTTP(w, r)
			return
		}
		// A proxy that changes the body after the server signed it.
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		for k, v := range rec.Header() {
			w.Header()[k] = v
		}
		w.Header().Del("Content-Length")
		w.WriteHeader(rec.Code)
		w.Write([]byte(strings.ToUpper(rec.Body.String())))
	})
}

func setup(t *testing.T) (*testServer, *httptest.Server, *Transport) {
	t.Helper()
	sk, _ := instancekey.Generate(nil)
	ck, _ := instancekey.Generate(nil)
	ts := &testServer{key: sk, sessions: map[string]*server.Session{}, active: map[string]bool{}}
	srv := httptest.NewServer(ts.handler(t))
	t.Cleanup(srv.Close)
	tr := &Transport{BaseURL: srv.URL, Key: ck, Trust: &MemoryTrust{}, Hello: handshake.Hello{Client: "test", Version: "1"}}
	return ts, srv, tr
}

func echo(t *testing.T, tr *Transport, url, body string) (string, error) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, url+"/v1/echo", strings.NewReader(body))
	req.Header.Set("Content-Type", "text/plain")
	resp, err := (&http.Client{Transport: tr}).Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return string(b), nil
}

func TestSessionRoundTrip(t *testing.T) {
	ts, srv, tr := setup(t)
	got, err := echo(t, tr, srv.URL, "hello")
	if err != nil {
		t.Fatal(err)
	}
	if got != tr.Key.Public().String()+" hello" {
		t.Fatalf("echo %q", got)
	}
	info, ok := tr.Session()
	if !ok || info.Grade != "anonymous" || !ts.active[info.ID] {
		t.Fatalf("session %+v %v, active %v", info, ok, ts.active)
	}
	trusted, ok, _ := tr.Trust.ServerKey(context.Background(), srv.URL)
	if !ok || trusted != ts.key.Public() {
		t.Errorf("trust %v %v", trusted, ok)
	}
	// The session is reused.
	if _, err := echo(t, tr, srv.URL, "again"); err != nil || ts.handshakes != 1 {
		t.Fatalf("second request: %v, %d handshakes", err, ts.handshakes)
	}
	if err := tr.Heartbeat(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := tr.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(ts.sessions) != 0 {
		t.Errorf("session not deleted: %v", ts.sessions)
	}
}

func TestForgottenSessionIsReplaced(t *testing.T) {
	ts, srv, tr := setup(t)
	if _, err := echo(t, tr, srv.URL, "a"); err != nil {
		t.Fatal(err)
	}
	ts.mu.Lock()
	ts.sessions = map[string]*server.Session{}
	ts.mu.Unlock()
	if got, err := echo(t, tr, srv.URL, "b"); err != nil || !strings.HasSuffix(got, " b") || ts.handshakes != 2 {
		t.Fatalf("%q %v, %d handshakes", got, err, ts.handshakes)
	}
}

func TestRenewBeforeExpiry(t *testing.T) {
	ts, srv, tr := setup(t)
	// Sessions that end within the renewal margin (10 minutes) are replaced.
	ts.ttl = 5 * time.Minute
	if _, err := echo(t, tr, srv.URL, "a"); err != nil {
		t.Fatal(err)
	}
	if _, err := echo(t, tr, srv.URL, "b"); err != nil || ts.handshakes != 2 {
		t.Fatalf("%v, %d handshakes", err, ts.handshakes)
	}
}

func TestServerKeyChanged(t *testing.T) {
	ts, srv, tr := setup(t)
	if _, err := echo(t, tr, srv.URL, "a"); err != nil {
		t.Fatal(err)
	}
	tr.Close(context.Background())
	ts.key, _ = instancekey.Generate(nil)
	_, err := echo(t, tr, srv.URL, "b")
	var kc *KeyChangedError
	if !errors.Is(err, ErrServerKeyChanged) || !errors.As(err, &kc) || kc.Presented == kc.Trusted {
		t.Fatalf("err %v", err)
	}
}

func TestTamperedResponse(t *testing.T) {
	ts, srv, tr := setup(t)
	ts.tamper = true
	if _, err := echo(t, tr, srv.URL, "a"); err == nil || !strings.Contains(err.Error(), "body does not match") {
		t.Fatalf("err %v", err)
	}
}

func TestUnsignedRequestRejected(t *testing.T) {
	_, srv, _ := setup(t)
	resp, err := http.Post(srv.URL+"/v1/echo", "text/plain", strings.NewReader("x"))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var e feedprotocol.Error
	json.NewDecoder(resp.Body).Decode(&e)
	if resp.StatusCode != 401 || e.Code != feedprotocol.CodeMissingSignature {
		t.Fatalf("%d %+v", resp.StatusCode, e)
	}
}

func TestReplyVersionChecked(t *testing.T) {
	ts, srv, tr := setup(t)
	ts.replyType = handshake.MediaTypeBase
	if _, err := echo(t, tr, srv.URL, "a"); err == nil || !strings.Contains(err.Error(), "not version 1") {
		t.Fatalf("err %v", err)
	}
	// A request without the version parameter is refused by the server.
	resp, err := http.Post(srv.URL+feedprotocol.SessionPath, handshake.MediaTypeBase, strings.NewReader("x"))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnsupportedMediaType {
		t.Errorf("status %d", resp.StatusCode)
	}
}
