// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: Apache-2.0

// Package server verifies signed requests of feed sessions and signs the
// responses, as net/http middleware.
package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"time"

	feedprotocol "github.com/bomcensus/feed-protocol"
	"github.com/bomcensus/feed-protocol/sign"
)

// Session is what the middleware needs to know about a session.
type Session struct {
	ID             string
	InstanceID     string
	Grade          string
	Telemetry      bool
	ClientToServer [32]byte
	ServerToClient [32]byte
}

// Errors a Lookup returns for sessions that cannot be used.
var (
	ErrUnknownSession = errors.New("server: unknown session")
	ErrExpiredSession = errors.New("server: session expired")
)

// Lookup finds sessions by ID.
type Lookup interface {
	// Session returns the session or ErrUnknownSession / ErrExpiredSession.
	Session(ctx context.Context, id string) (Session, error)
}

// Verifier is the middleware configuration.
type Verifier struct {
	Sessions Lookup
	// Now defaults to time.Now; Skew to sign.DefaultSkew.
	Now  func() time.Time
	Skew time.Duration
	// MaxBodyBytes bounds the request body read for verification (0: no
	// limit). A larger body gets 413.
	MaxBodyBytes int64
	// Verified is called after a request verified; an error ends the request
	// with the status and code it carries (see Reject).
	Verified func(r *http.Request, s Session) error
}

// Reject is an error a Verified hook returns to refuse a request.
type Reject struct {
	Status     int
	Code       string
	Message    string
	RetryAfter time.Duration
}

func (e *Reject) Error() string { return e.Code + ": " + e.Message }

type ctxKey struct{}

// FromContext returns the session of a verified request.
func FromContext(ctx context.Context) (Session, bool) {
	s, ok := ctx.Value(ctxKey{}).(Session)
	return s, ok
}

// WriteError writes an unsigned error response.
func WriteError(w http.ResponseWriter, status int, code, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(feedprotocol.Error{Code: code, Message: msg}) //nolint:errcheck // client gone
}

func (v *Verifier) now() time.Time {
	if v.Now != nil {
		return v.Now()
	}
	return time.Now()
}

// Middleware verifies the request, passes it on with the body restored and
// the session in its context, and signs the response. The response is
// buffered to be hashed.
func (v *Verifier) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get(sign.HeaderSession)
		if id == "" || r.Header.Get(sign.HeaderSignature) == "" {
			WriteError(w, http.StatusUnauthorized, feedprotocol.CodeMissingSignature, "the request is not signed for a session")
			return
		}
		var src io.Reader = r.Body
		if r.Body == nil {
			src = http.NoBody
		}
		if v.MaxBodyBytes > 0 {
			src = http.MaxBytesReader(w, r.Body, v.MaxBodyBytes)
		}
		body, err := io.ReadAll(src)
		if err != nil {
			var mbe *http.MaxBytesError
			if errors.As(err, &mbe) {
				WriteError(w, http.StatusRequestEntityTooLarge, "too_large", "request body too large")
				return
			}
			WriteError(w, http.StatusBadRequest, "bad_request", "reading the body failed")
			return
		}
		sess, err := v.Sessions.Session(r.Context(), id)
		switch {
		case errors.Is(err, ErrUnknownSession):
			WriteError(w, http.StatusUnauthorized, feedprotocol.CodeSessionUnknown, "unknown session")
			return
		case errors.Is(err, ErrExpiredSession):
			WriteError(w, http.StatusUnauthorized, feedprotocol.CodeSessionExpired, "session expired")
			return
		case err != nil:
			WriteError(w, http.StatusInternalServerError, "internal", "internal error")
			return
		}
		skew := v.Skew
		if skew == 0 {
			skew = sign.DefaultSkew
		}
		now := v.now()
		switch err := sign.VerifyRequest(r, body, sess.ClientToServer, now, skew); {
		case errors.Is(err, sign.ErrClockSkew):
			w.Header().Set(feedprotocol.HeaderServerTime, strconv.FormatInt(now.Unix(), 10))
			WriteError(w, http.StatusUnauthorized, feedprotocol.CodeClockSkew, "timestamp outside the accepted window")
			return
		case errors.Is(err, sign.ErrMissing):
			WriteError(w, http.StatusUnauthorized, feedprotocol.CodeMissingSignature, err.Error())
			return
		case err != nil:
			WriteError(w, http.StatusUnauthorized, feedprotocol.CodeBadSignature, "bad signature")
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		r.ContentLength = int64(len(body))
		r = r.WithContext(context.WithValue(r.Context(), ctxKey{}, sess))
		if v.Verified != nil {
			if err := v.Verified(r, sess); err != nil {
				var rej *Reject
				if !errors.As(err, &rej) {
					WriteError(w, http.StatusInternalServerError, "internal", "internal error")
					return
				}
				if rej.RetryAfter > 0 {
					w.Header().Set("Retry-After", strconv.Itoa(int((rej.RetryAfter+time.Second-1)/time.Second)))
				}
				WriteError(w, rej.Status, rej.Code, rej.Message)
				return
			}
		}
		bw := &bufferedWriter{header: http.Header{}}
		next.ServeHTTP(bw, r)
		if bw.status == 0 {
			bw.status = http.StatusOK
		}
		h := w.Header()
		for k, vs := range bw.header {
			h[k] = vs
		}
		sign.SignResponse(h, bw.status, r.Header.Get(sign.HeaderSignature), bw.body.Bytes(), sess.ServerToClient, v.now())
		h.Set("Content-Length", strconv.Itoa(bw.body.Len()))
		w.WriteHeader(bw.status)
		w.Write(bw.body.Bytes()) //nolint:errcheck // client gone
	})
}

// bufferedWriter collects a response so that it can be signed.
type bufferedWriter struct {
	header http.Header
	status int
	body   bytes.Buffer
}

func (b *bufferedWriter) Header() http.Header { return b.header }

func (b *bufferedWriter) WriteHeader(status int) {
	if b.status == 0 {
		b.status = status
	}
}

func (b *bufferedWriter) Write(p []byte) (int, error) {
	if b.status == 0 {
		b.status = http.StatusOK
	}
	return b.body.Write(p)
}
