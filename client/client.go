// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: Apache-2.0

// Package client is an http.RoundTripper that talks to a feed server
// through a session: it runs the handshake, trusts the server key it meets
// first (TOFU), signs requests, verifies responses, keeps the session alive
// and replaces it before it expires.
package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	feedprotocol "github.com/bomcensus/feed-protocol"
	"github.com/bomcensus/feed-protocol/handshake"
	"github.com/bomcensus/feed-protocol/instancekey"
	"github.com/bomcensus/feed-protocol/sign"
)

// TrustStore keeps the server keys a client has accepted.
type TrustStore interface {
	// ServerKey returns the key accepted for server; ok is false before the
	// first contact.
	ServerKey(ctx context.Context, server string) (key instancekey.PublicKey, ok bool, err error)
	// TrustServerKey records the key met at the first contact.
	TrustServerKey(ctx context.Context, server string, key instancekey.PublicKey) error
}

// ErrServerKeyChanged means the server presented another key than the one
// trusted for it. The client does not use the session; an operator must
// decide (remove the server's entry from the TrustStore to accept the new
// key). The error is a *KeyChangedError.
var ErrServerKeyChanged = errors.New("client: server key changed")

// KeyChangedError carries both keys of an ErrServerKeyChanged.
type KeyChangedError struct {
	Trusted   instancekey.PublicKey
	Presented instancekey.PublicKey
}

func (e *KeyChangedError) Error() string {
	return fmt.Sprintf("%s: trusted %s, got %s", ErrServerKeyChanged, e.Trusted, e.Presented)
}

// Is makes errors.Is(err, ErrServerKeyChanged) true.
func (e *KeyChangedError) Is(target error) bool { return target == ErrServerKeyChanged }

// Error is an error response from the server.
type Error struct {
	Status  int
	Code    string
	Message string
}

func (e *Error) Error() string {
	return fmt.Sprintf("feed server: HTTP %d %s: %s", e.Status, e.Code, e.Message)
}

// MemoryTrust is a TrustStore in memory.
type MemoryTrust struct {
	mu   sync.Mutex
	keys map[string]instancekey.PublicKey
}

// ServerKey implements TrustStore.
func (m *MemoryTrust) ServerKey(_ context.Context, server string) (instancekey.PublicKey, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	k, ok := m.keys[server]
	return k, ok, nil
}

// TrustServerKey implements TrustStore.
func (m *MemoryTrust) TrustServerKey(_ context.Context, server string, key instancekey.PublicKey) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.keys == nil {
		m.keys = map[string]instancekey.PublicKey{}
	}
	m.keys[server] = key
	return nil
}

// Transport sends requests to one feed server. Requests must go to
// BaseURL's host.
type Transport struct {
	// BaseURL of the server, e.g. "https://feed.example.com"; it is also the
	// name under which the server key is trusted.
	BaseURL string
	Key     *instancekey.PrivateKey
	Trust   TrustStore
	// Hello is sent in the handshake; Time and Protocol are filled in.
	Hello handshake.Hello
	// Base sends the HTTP requests (http.DefaultTransport when nil).
	Base http.RoundTripper
	// Now defaults to time.Now; Skew to sign.DefaultSkew.
	Now  func() time.Time
	Skew time.Duration
	// Renew is how long before expiry a session is replaced (default 10m).
	Renew time.Duration

	mu   sync.Mutex
	sess *session
}

type session struct {
	keys     handshake.Keys
	welcome  handshake.Welcome
	expires  time.Time
	lastUsed atomic.Int64 // unix nanoseconds of the last verified response
}

func (t *Transport) now() time.Time {
	if t.Now != nil {
		return t.Now()
	}
	return time.Now()
}

func (t *Transport) base() http.RoundTripper {
	if t.Base != nil {
		return t.Base
	}
	return http.DefaultTransport
}

func (t *Transport) skew() time.Duration {
	if t.Skew != 0 {
		return t.Skew
	}
	return sign.DefaultSkew
}

func (t *Transport) renew() time.Duration {
	if t.Renew != 0 {
		return t.Renew
	}
	return 10 * time.Minute
}

// Info describes the current session.
type Info struct {
	ID      string
	Grade   string
	Expires time.Time
	// Heartbeat is the interval the server asks for.
	Heartbeat time.Duration
}

// Session returns the current session, if there is one.
func (t *Transport) Session() (Info, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.sess == nil {
		return Info{}, false
	}
	return Info{ID: t.sess.keys.SessionID, Grade: t.sess.welcome.Grade, Expires: t.sess.expires,
		Heartbeat: time.Duration(t.sess.welcome.Heartbeat) * time.Second}, true
}

// Start runs a handshake now unless a usable session exists.
func (t *Transport) Start(ctx context.Context) error {
	_, err := t.current(ctx)
	return err
}

func (t *Transport) current(ctx context.Context) (*session, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if s := t.sess; s != nil && t.now().Before(s.expires.Add(-t.renew())) {
		return s, nil
	}
	s, err := t.handshake(ctx)
	if err != nil {
		return nil, err
	}
	t.sess = s
	return s, nil
}

func (t *Transport) drop(s *session) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.sess == s {
		t.sess = nil
	}
}

// handshake runs with t.mu held.
func (t *Transport) handshake(ctx context.Context) (*session, error) {
	if t.Key == nil || t.Trust == nil {
		return nil, errors.New("client: Key and Trust are required")
	}
	hello := t.Hello
	hello.Time = t.now().Unix()
	ini, msg1, err := handshake.Start(handshake.Version, t.Key, hello, nil)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.url(feedprotocol.SessionPath), bytes.NewReader(msg1))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", handshake.MediaType(ini.Version()))
	resp, err := t.base().RoundTrip(req)
	if err != nil {
		return nil, err
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	resp.Body.Close()
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, errorOf(resp.StatusCode, body)
	}
	// The server answers in the version it was asked for; another one is
	// never accepted (no fallback).
	if v, err := handshake.ParseMediaType(resp.Header.Get("Content-Type")); err != nil || v != ini.Version() {
		return nil, fmt.Errorf("client: handshake reply is not version %d: %q", ini.Version(), resp.Header.Get("Content-Type"))
	}
	keys, welcome, serverKey, err := ini.Finish(body)
	if err != nil {
		return nil, err
	}
	trusted, ok, err := t.Trust.ServerKey(ctx, t.BaseURL)
	if err != nil {
		return nil, err
	}
	if ok && trusted != serverKey {
		return nil, &KeyChangedError{Trusted: trusted, Presented: serverKey}
	}
	if !ok {
		if err := t.Trust.TrustServerKey(ctx, t.BaseURL, serverKey); err != nil {
			return nil, err
		}
	}
	s := &session{keys: keys, welcome: welcome, expires: time.Unix(welcome.SessionExpires, 0)}
	// The server keeps a new session pending until a signed request shows
	// that the client holds the keys.
	if _, err := t.heartbeat(ctx, s); err != nil {
		return nil, fmt.Errorf("client: confirming the session: %w", err)
	}
	return s, nil
}

func (t *Transport) url(path string) string {
	return strings.TrimSuffix(t.BaseURL, "/") + path
}

func errorOf(status int, body []byte) error {
	var b feedprotocol.Error
	if json.Unmarshal(body, &b) != nil || b.Code == "" {
		b.Code, b.Message = "http_error", strings.TrimSpace(string(body))
	}
	return &Error{Status: status, Code: b.Code, Message: b.Message}
}

// send signs and sends one request in session s and verifies the response.
func (t *Transport) send(req *http.Request, body []byte, s *session) (*http.Response, []byte, error) {
	r := req.Clone(req.Context())
	r.Body = io.NopCloser(bytes.NewReader(body))
	r.ContentLength = int64(len(body))
	r.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(body)), nil }
	sig, err := sign.SignRequest(r, body, s.keys.SessionID, s.keys.ClientToServer, t.now())
	if err != nil {
		return nil, nil, err
	}
	resp, err := t.base().RoundTrip(r)
	if err != nil {
		return nil, nil, err
	}
	rbody, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return nil, nil, err
	}
	resp.Body = io.NopCloser(bytes.NewReader(rbody))
	if resp.Header.Get(sign.HeaderSignature) == "" && resp.StatusCode >= 400 {
		// Errors before the session is known (401, 413, 429) are not signed.
		return resp, rbody, errorOf(resp.StatusCode, rbody)
	}
	if err := sign.VerifyResponse(resp, rbody, sig, s.keys.ServerToClient, t.now(), t.skew()); err != nil {
		return nil, nil, fmt.Errorf("client: response from %s: %w", r.URL.Host, err)
	}
	s.lastUsed.Store(t.now().UnixNano())
	return resp, rbody, nil
}

// RoundTrip implements http.RoundTripper. A request whose session the
// server no longer knows is repeated once in a new session.
func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	var body []byte
	if req.Body != nil {
		b, err := io.ReadAll(req.Body)
		req.Body.Close()
		if err != nil {
			return nil, err
		}
		body = b
	}
	for attempt := 0; ; attempt++ {
		s, err := t.current(req.Context())
		if err != nil {
			return nil, err
		}
		resp, _, err := t.send(req, body, s)
		var e *Error
		if errors.As(err, &e) && (e.Code == feedprotocol.CodeSessionUnknown || e.Code == feedprotocol.CodeSessionExpired) {
			t.drop(s)
			if attempt == 0 {
				continue
			}
		}
		if resp != nil && err != nil && errors.As(err, &e) {
			// An unsigned error response is still returned to the caller.
			return resp, nil
		}
		return resp, err
	}
}

// Heartbeat keeps the current session alive (starting one if needed).
func (t *Transport) Heartbeat(ctx context.Context) error {
	s, err := t.current(ctx)
	if err != nil {
		return err
	}
	if _, err := t.heartbeat(ctx, s); err != nil {
		var e *Error
		if errors.As(err, &e) && (e.Code == feedprotocol.CodeSessionUnknown || e.Code == feedprotocol.CodeSessionExpired) {
			t.drop(s)
		}
		return err
	}
	return nil
}

func (t *Transport) heartbeat(ctx context.Context, s *session) (feedprotocol.Heartbeat, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.url(feedprotocol.HeartbeatPath), nil)
	if err != nil {
		return feedprotocol.Heartbeat{}, err
	}
	resp, body, err := t.send(req, nil, s)
	if err != nil {
		return feedprotocol.Heartbeat{}, err
	}
	if resp.StatusCode != http.StatusOK {
		return feedprotocol.Heartbeat{}, errorOf(resp.StatusCode, body)
	}
	var hb feedprotocol.Heartbeat
	if err := json.Unmarshal(body, &hb); err != nil {
		return hb, fmt.Errorf("client: heartbeat: %w", err)
	}
	return hb, nil
}

// KeepAlive sends heartbeats at the interval the server asked for until ctx
// ends, replacing the session before it expires. A tick is skipped when a
// request went through within the interval, since any request keeps the
// session alive. Errors are passed to onError (may be nil) and retried at
// the next tick.
func (t *Transport) KeepAlive(ctx context.Context, onError func(error)) {
	for {
		wait := time.Minute
		if info, ok := t.Session(); ok && info.Heartbeat > 0 {
			wait = info.Heartbeat
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		if t.recentlyUsed(wait) {
			continue
		}
		if err := t.Heartbeat(ctx); err != nil && onError != nil && ctx.Err() == nil {
			onError(err)
		}
	}
}

// recentlyUsed reports whether the current session answered within d and
// does not need replacing yet.
func (t *Transport) recentlyUsed(d time.Duration) bool {
	t.mu.Lock()
	s := t.sess
	t.mu.Unlock()
	if s == nil {
		return false
	}
	now := t.now()
	if !now.Before(s.expires.Add(-t.renew())) {
		return false
	}
	return now.Sub(time.Unix(0, s.lastUsed.Load())) < d
}

// Close ends the current session on the server.
func (t *Transport) Close(ctx context.Context) error {
	t.mu.Lock()
	s := t.sess
	t.sess = nil
	t.mu.Unlock()
	if s == nil {
		return nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, t.url(feedprotocol.SessionPath), nil)
	if err != nil {
		return err
	}
	resp, body, err := t.send(req, nil, s)
	if err != nil {
		return err
	}
	if resp.StatusCode/100 != 2 {
		return errorOf(resp.StatusCode, body)
	}
	return nil
}
