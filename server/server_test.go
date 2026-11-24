// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	feedprotocol "github.com/bomcensus/feed-protocol"
	"github.com/bomcensus/feed-protocol/sign"
)

type lookup map[string]Session

func (l lookup) Session(_ context.Context, id string) (Session, error) {
	if id == "expired" {
		return Session{}, ErrExpiredSession
	}
	s, ok := l[id]
	if !ok {
		return Session{}, ErrUnknownSession
	}
	return s, nil
}

var sess = Session{ID: "sid", InstanceID: "x25519 abc", ClientToServer: [32]byte{1}, ServerToClient: [32]byte{2}}

func do(t *testing.T, v *Verifier, id string, body []byte, at time.Time) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/v1/match", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if _, err := sign.SignRequest(req, body, id, sess.ClientToServer, at); err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	v.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s, ok := FromContext(r.Context())
		if !ok || s.ID != "sid" {
			t.Errorf("context session %+v", s)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(`{"ok":true}`))
	})).ServeHTTP(rec, req)
	return rec
}

func code(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var e feedprotocol.Error
	json.Unmarshal(rec.Body.Bytes(), &e)
	return e.Code
}

func TestMiddleware(t *testing.T) {
	now := time.Unix(1795000000, 0)
	v := &Verifier{Sessions: lookup{"sid": sess}, Now: func() time.Time { return now }, MaxBodyBytes: 64}
	rec := do(t, v, "sid", []byte(`{}`), now)
	if rec.Code != http.StatusCreated {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	resp := &http.Response{StatusCode: rec.Code, Header: rec.Header()}
	reqSig := ""
	{
		req := httptest.NewRequest(http.MethodPost, "/v1/match", nil)
		req.Header.Set("Content-Type", "application/json")
		reqSig, _ = sign.SignRequest(req, []byte(`{}`), "sid", sess.ClientToServer, now)
	}
	if err := sign.VerifyResponse(resp, rec.Body.Bytes(), reqSig, sess.ServerToClient, now, sign.DefaultSkew); err != nil {
		t.Errorf("response signature: %v", err)
	}
	for name, tc := range map[string]struct {
		id     string
		body   []byte
		at     time.Time
		status int
		code   string
	}{
		"unknown":  {"nope", []byte(`{}`), now, 401, feedprotocol.CodeSessionUnknown},
		"expired":  {"expired", []byte(`{}`), now, 401, feedprotocol.CodeSessionExpired},
		"skew":     {"sid", []byte(`{}`), now.Add(-time.Hour), 401, feedprotocol.CodeClockSkew},
		"too long": {"sid", bytes.Repeat([]byte("x"), 65), now, 413, "too_large"},
	} {
		rec := do(t, v, tc.id, tc.body, tc.at)
		if rec.Code != tc.status || code(t, rec) != tc.code {
			t.Errorf("%s: %d %s", name, rec.Code, rec.Body)
		}
		if name == "skew" && rec.Header().Get(feedprotocol.HeaderServerTime) != "1795000000" {
			t.Errorf("server time %q", rec.Header().Get(feedprotocol.HeaderServerTime))
		}
	}
	// A hook refuses (rate limit).
	v.Verified = func(*http.Request, Session) error {
		return &Reject{Status: 429, Code: feedprotocol.CodeRateLimited, Message: "slow down", RetryAfter: 1500 * time.Millisecond}
	}
	rec = do(t, v, "sid", []byte(`{}`), now)
	if rec.Code != 429 || code(t, rec) != feedprotocol.CodeRateLimited || rec.Header().Get("Retry-After") != "2" {
		t.Errorf("reject: %d %s %v", rec.Code, rec.Body, rec.Header())
	}
}
