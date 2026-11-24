// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: Apache-2.0

// Package feedprotocol holds what feed clients and servers share over HTTP:
// endpoint paths, error codes and message bodies. The handshake is in
// package handshake, signatures in package sign, and ready-made client and
// server pieces in packages client and server. docs/PROTOCOL.md is the
// specification.
package feedprotocol

// Endpoint paths.
const (
	// SessionPath: POST starts a session (handshake message 1 in, message 2
	// out, Content-Type handshake.MediaType(version)). DELETE, signed, ends
	// it.
	SessionPath = "/v1/session"
	// HeartbeatPath: POST, signed, keeps the session alive.
	HeartbeatPath = "/v1/session/heartbeat"
)

// Error codes in Error.Code.
const (
	CodeMissingSignature = "missing_signature"
	CodeBadSignature     = "bad_signature"
	CodeClockSkew        = "clock_skew"
	CodeSessionUnknown   = "session_unknown"
	CodeSessionExpired   = "session_expired"
	CodeBadHandshake     = "bad_handshake"
	// CodeUnsupportedProtocol (415): the handshake's media type names no
	// version or one the server does not speak; Accept-Post lists the
	// supported media types.
	CodeUnsupportedProtocol = "unsupported_protocol"
	CodeBlocked             = "blocked"
	CodeRateLimited         = "rate_limited"
)

// HeaderServerTime carries the server's clock (unix seconds) in clock_skew
// errors.
const HeaderServerTime = "Feed-Server-Time"

// Error is the JSON body of an error response.
type Error struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// Heartbeat is the JSON body of a heartbeat response.
type Heartbeat struct {
	SessionExpires int64  `json:"session_expires"` // unix seconds
	IdleTimeout    int    `json:"idle_timeout"`    // seconds
	Grade          string `json:"grade"`
}
