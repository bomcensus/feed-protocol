// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: Apache-2.0

package sign

import (
	"bytes"
	"errors"
	"net/http"
	"testing"
	"time"
)

var (
	key   = [32]byte{1, 2, 3}
	other = [32]byte{9}
	now   = time.Unix(1795000000, 0)
)

func newRequest(t *testing.T, body []byte) *http.Request {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, "https://feed.example/v1/match?b=2&a=1&a=0", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Encoding", "gzip")
	return req
}

func TestVector(t *testing.T) {
	s, err := RequestString(1795000000, "sid", "post", "/v1/match", "b=2&a=1&a=0", " application/json ", "GZIP", BodyHash([]byte("{}")))
	if err != nil {
		t.Fatal(err)
	}
	want := "FEED1-HMAC-SHA256\n1795000000\nsid\nPOST\n/v1/match\na=0&a=1&b=2\napplication/json\ngzip\n" +
		"44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"
	if s != want {
		t.Fatalf("string to sign:\n%q\nwant\n%q", s, want)
	}
	if got := mac(key, s); got != vectorRequestSignature {
		t.Errorf("signature %s, want %s", got, vectorRequestSignature)
	}
}

func TestRequest(t *testing.T) {
	body := []byte(`{"targets":[]}`)
	req := newRequest(t, body)
	sig, err := SignRequest(req, body, "sid", key, now)
	if err != nil {
		t.Fatal(err)
	}
	if req.Header.Get(HeaderSignature) != sig || req.Header.Get(HeaderSession) != "sid" {
		t.Fatalf("headers %v", req.Header)
	}
	if err := VerifyRequest(req, body, key, now.Add(time.Minute), DefaultSkew); err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		mutate func(*http.Request) []byte
		want   error
	}{
		"other key":       {func(r *http.Request) []byte { return body }, ErrBadSignature},
		"body":            {func(r *http.Request) []byte { return []byte(`{"targets":[1]}`) }, ErrBodyHash},
		"body and hash":   {func(r *http.Request) []byte { r.Header.Del(HeaderContentSHA256); return []byte("x") }, ErrBadSignature},
		"path":            {func(r *http.Request) []byte { r.URL.Path = "/v1/status"; return body }, ErrBadSignature},
		"query":           {func(r *http.Request) []byte { r.URL.RawQuery = "a=1"; return body }, ErrBadSignature},
		"method":          {func(r *http.Request) []byte { r.Method = http.MethodPut; return body }, ErrBadSignature},
		"content type":    {func(r *http.Request) []byte { r.Header.Set("Content-Type", "text/plain"); return body }, ErrBadSignature},
		"encoding":        {func(r *http.Request) []byte { r.Header.Del("Content-Encoding"); return body }, ErrBadSignature},
		"session":         {func(r *http.Request) []byte { r.Header.Set(HeaderSession, "other"); return body }, ErrBadSignature},
		"timestamp":       {func(r *http.Request) []byte { r.Header.Set(HeaderTimestamp, "1795000001"); return body }, ErrBadSignature},
		"old timestamp":   {func(r *http.Request) []byte { r.Header.Set(HeaderTimestamp, "1794990000"); return body }, ErrClockSkew},
		"missing headers": {func(r *http.Request) []byte { r.Header.Del(HeaderSignature); return body }, ErrMissing},
	} {
		r := newRequest(t, body)
		if _, err := SignRequest(r, body, "sid", key, now); err != nil {
			t.Fatal(err)
		}
		b := tc.mutate(r)
		k := key
		if name == "other key" {
			k = other
		}
		if err := VerifyRequest(r, b, k, now, DefaultSkew); !errors.Is(err, tc.want) {
			t.Errorf("%s: %v, want %v", name, err, tc.want)
		}
	}
}

func TestResponse(t *testing.T) {
	body := []byte(`{"ok":true}`)
	resp := &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"application/json"}}}
	SignResponse(resp.Header, 200, "reqsig", body, key, now)
	if err := VerifyResponse(resp, body, "reqsig", key, now, DefaultSkew); err != nil {
		t.Fatal(err)
	}
	// Bound to the request: another request's signature does not verify.
	if err := VerifyResponse(resp, body, "othersig", key, now, DefaultSkew); !errors.Is(err, ErrBadSignature) {
		t.Errorf("other request: %v", err)
	}
	resp.StatusCode = 500
	if err := VerifyResponse(resp, body, "reqsig", key, now, DefaultSkew); !errors.Is(err, ErrBadSignature) {
		t.Errorf("status: %v", err)
	}
	resp.StatusCode = 200
	if err := VerifyResponse(resp, []byte(`{"ok":false}`), "reqsig", key, now, DefaultSkew); !errors.Is(err, ErrBodyHash) {
		t.Errorf("body: %v", err)
	}
	if err := VerifyResponse(resp, body, "reqsig", other, now, DefaultSkew); !errors.Is(err, ErrBadSignature) {
		t.Errorf("key: %v", err)
	}
}
