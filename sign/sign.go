// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: Apache-2.0

// Package sign signs and verifies HTTP requests and responses of a feed
// session with HMAC-SHA256. Messages are not encrypted (TLS is expected
// underneath); the signature proves they come from the session's holder and
// were not changed.
//
// Request string to sign (lines joined with "\n"):
//
//	FEED1-HMAC-SHA256
//	<Feed-Timestamp: unix seconds>
//	<Feed-Session>
//	<method>
//	<escaped path>
//	<query, keys and values sorted, form-encoded>
//	<Content-Type, trimmed>
//	<Content-Encoding, trimmed, lowercase>
//	<hex SHA-256 of the body as sent>
//
// Response string to sign:
//
//	FEED1-HMAC-SHA256-RESPONSE
//	<Feed-Timestamp>
//	<Feed-Signature of the request>
//	<status code>
//	<Content-Type>
//	<Content-Encoding>
//	<hex SHA-256 of the body as sent>
//
// Feed-Signature is the standard base64 of the HMAC; Feed-Content-SHA256
// repeats the body hash so that a mismatch is reported as such.
package sign

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Header names.
const (
	HeaderSession       = "Feed-Session"
	HeaderTimestamp     = "Feed-Timestamp"
	HeaderContentSHA256 = "Feed-Content-SHA256"
	HeaderSignature     = "Feed-Signature"
)

// Algorithm names, the first line of the strings to sign.
const (
	Algorithm         = "FEED1-HMAC-SHA256"
	ResponseAlgorithm = "FEED1-HMAC-SHA256-RESPONSE"
)

// DefaultSkew is the accepted clock difference.
const DefaultSkew = 5 * time.Minute

// Verification errors.
var (
	ErrMissing      = errors.New("sign: signature headers missing")
	ErrClockSkew    = errors.New("sign: timestamp outside the accepted window")
	ErrBodyHash     = errors.New("sign: body does not match Feed-Content-SHA256")
	ErrBadSignature = errors.New("sign: bad signature")
)

// BodyHash returns the hex SHA-256 of b.
func BodyHash(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// CanonicalQuery sorts a raw query by key and value and form-encodes it.
func CanonicalQuery(raw string) (string, error) {
	if raw == "" {
		return "", nil
	}
	v, err := url.ParseQuery(raw)
	if err != nil {
		return "", fmt.Errorf("sign: query: %w", err)
	}
	keys := make([]string, 0, len(v))
	for k := range v {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		vals := append([]string(nil), v[k]...)
		sort.Strings(vals)
		for _, x := range vals {
			if b.Len() > 0 {
				b.WriteByte('&')
			}
			b.WriteString(url.QueryEscape(k))
			b.WriteByte('=')
			b.WriteString(url.QueryEscape(x))
		}
	}
	return b.String(), nil
}

// RequestString returns the request string to sign.
func RequestString(ts int64, session, method, escapedPath, rawQuery, contentType, contentEncoding, bodyHash string) (string, error) {
	q, err := CanonicalQuery(rawQuery)
	if err != nil {
		return "", err
	}
	return strings.Join([]string{
		Algorithm, strconv.FormatInt(ts, 10), session, strings.ToUpper(method), escapedPath, q,
		strings.TrimSpace(contentType), strings.ToLower(strings.TrimSpace(contentEncoding)), bodyHash,
	}, "\n"), nil
}

// ResponseString returns the response string to sign.
func ResponseString(ts int64, requestSignature string, status int, contentType, contentEncoding, bodyHash string) string {
	return strings.Join([]string{
		ResponseAlgorithm, strconv.FormatInt(ts, 10), requestSignature, strconv.Itoa(status),
		strings.TrimSpace(contentType), strings.ToLower(strings.TrimSpace(contentEncoding)), bodyHash,
	}, "\n")
}

func mac(key [32]byte, s string) string {
	m := hmac.New(sha256.New, key[:])
	m.Write([]byte(s))
	return base64.StdEncoding.EncodeToString(m.Sum(nil))
}

func path(u *url.URL) string {
	p := u.EscapedPath()
	if p == "" {
		return "/"
	}
	return p
}

// SignRequest sets the signature headers of req for the body that will be
// sent and returns the signature.
func SignRequest(req *http.Request, body []byte, session string, key [32]byte, now time.Time) (string, error) {
	ts := now.Unix()
	hash := BodyHash(body)
	s, err := RequestString(ts, session, req.Method, path(req.URL), req.URL.RawQuery,
		req.Header.Get("Content-Type"), req.Header.Get("Content-Encoding"), hash)
	if err != nil {
		return "", err
	}
	sig := mac(key, s)
	req.Header.Set(HeaderSession, session)
	req.Header.Set(HeaderTimestamp, strconv.FormatInt(ts, 10))
	req.Header.Set(HeaderContentSHA256, hash)
	req.Header.Set(HeaderSignature, sig)
	return sig, nil
}

func checkTime(h http.Header, now time.Time, skew time.Duration) (int64, error) {
	ts, err := strconv.ParseInt(h.Get(HeaderTimestamp), 10, 64)
	if err != nil {
		return 0, ErrMissing
	}
	if d := now.Sub(time.Unix(ts, 0)); d > skew || d < -skew {
		return 0, ErrClockSkew
	}
	return ts, nil
}

// VerifyRequest checks the signature of req, whose body (as received,
// before any decoding) is body, with the session's client-to-server key.
// The caller looks the key up by the Feed-Session header.
func VerifyRequest(req *http.Request, body []byte, key [32]byte, now time.Time, skew time.Duration) error {
	sig := req.Header.Get(HeaderSignature)
	session := req.Header.Get(HeaderSession)
	if sig == "" || session == "" {
		return ErrMissing
	}
	ts, err := checkTime(req.Header, now, skew)
	if err != nil {
		return err
	}
	hash := BodyHash(body)
	if h := req.Header.Get(HeaderContentSHA256); h != "" && !strings.EqualFold(h, hash) {
		return ErrBodyHash
	}
	s, err := RequestString(ts, session, req.Method, path(req.URL), req.URL.RawQuery,
		req.Header.Get("Content-Type"), req.Header.Get("Content-Encoding"), hash)
	if err != nil {
		return err
	}
	if !hmac.Equal([]byte(mac(key, s)), []byte(sig)) {
		return ErrBadSignature
	}
	return nil
}

// SignResponse sets the signature headers of a response to the request
// signed with requestSignature.
func SignResponse(h http.Header, status int, requestSignature string, body []byte, key [32]byte, now time.Time) {
	ts := now.Unix()
	hash := BodyHash(body)
	h.Set(HeaderTimestamp, strconv.FormatInt(ts, 10))
	h.Set(HeaderContentSHA256, hash)
	h.Set(HeaderSignature, mac(key, ResponseString(ts, requestSignature, status,
		h.Get("Content-Type"), h.Get("Content-Encoding"), hash)))
}

// VerifyResponse checks a response to the request signed with
// requestSignature. body is the response body as received.
func VerifyResponse(resp *http.Response, body []byte, requestSignature string, key [32]byte, now time.Time, skew time.Duration) error {
	sig := resp.Header.Get(HeaderSignature)
	if sig == "" {
		return ErrMissing
	}
	ts, err := checkTime(resp.Header, now, skew)
	if err != nil {
		return err
	}
	hash := BodyHash(body)
	if h := resp.Header.Get(HeaderContentSHA256); h != "" && !strings.EqualFold(h, hash) {
		return ErrBodyHash
	}
	s := ResponseString(ts, requestSignature, resp.StatusCode, resp.Header.Get("Content-Type"),
		resp.Header.Get("Content-Encoding"), hash)
	if !hmac.Equal([]byte(mac(key, s)), []byte(sig)) {
		return ErrBadSignature
	}
	return nil
}
