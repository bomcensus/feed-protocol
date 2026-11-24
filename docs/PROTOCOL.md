# bomcensus feed protocol, version 1

This document specifies how a feed client (a bomcensus server) and a feed
server establish a session and exchange signed HTTP messages. The Go packages
in this repository implement it.

## Keys and identities

Both sides have a static X25519 key pair. A private key is any 32 random
bytes (X25519 clamps it). The text form of a public key is

```
x25519 <standard base64 of the 32-byte public key>
```

like an SSH public key line without the comment. The client's public key in
this form is its **instance ID**. A private key is stored as PEM of type
`X25519 PRIVATE KEY` holding the 32 bytes.

The client generates its key once, when it is installed. The server's key is
trusted on first use: the client records the key the server presents at the
first handshake and refuses a different one afterwards, until an operator
removes the record.

## Session handshake

One HTTP exchange. The protocol version is the `v` parameter of the media
type of both messages:

```
POST /v1/session
Content-Type: application/vnd.bomcensus.feed-noise; v=1
<message 1: -> e, s, payload Hello>

200 OK
Content-Type: application/vnd.bomcensus.feed-noise; v=1
<message 2: <- e, ee, se, s, es, payload Welcome>
```

Version 1 is `Noise_IX_25519_AESGCM_SHA256`.

### Versions

The version selects the Noise protocol (pattern, DH, cipher, hash) and
everything that follows from it (key derivation, signatures). It is sent
outside the Noise messages because the server needs it to read message 1.

- The prologue is `bomcensus-feed/<v>` (ASCII, no terminator), where `<v>` is
  the version in decimal. Both sides take it from the media type, so a
  version changed on the way gives the two sides different prologues and the
  handshake fails: a downgrade is detected, not negotiated.
- The media type and its parameter name are case-insensitive; the value is a
  decimal integer, optionally quoted.
- A server that does not speak the requested version (or gets no `v`)
  answers 415 `unsupported_protocol` with `Accept-Post` listing the media
  types it accepts, e.g. `application/vnd.bomcensus.feed-noise; v=1`.
- The server answers in the requested version. A client rejects a reply in
  another one, and never retries with an older version on its own.

Payloads are JSON.

`Hello` (message 1) is not encrypted: in IX the first message has no key yet.
It is mixed into the handshake hash, so a change makes message 2 fail on the
client, but it can be read on the wire, and so can the client's static key.
Run the protocol over TLS.

```json
{"client": "bomcensus", "version": "1.2.3", "time": 1795000000, "telemetry": true}
```

- `client`, `version`: the client software.

- `time`: client clock, unix seconds. The server refuses a Hello more than 5
  minutes away from its clock.
- `telemetry`: whether the server may count the client's queries in
  anonymous statistics.

`Welcome` (message 2, encrypted):

```json
{"session_expires": 1795086400, "heartbeat": 300, "idle_timeout": 900, "grade": "anonymous", "server_time": 1795000001}
```

- `session_expires`: the session ends then, at most 24 hours after it
  started; it cannot be extended.
- `heartbeat`: seconds between heartbeats; `idle_timeout`: seconds without a
  request after which the session ends.
- `grade`: the server's classification of the instance.

The client checks the server's static key (trust on first use) before using
the session.

### Session keys

After message 2 both sides hold the split cipher states with keys `k1`
(initiator to responder) and `k2`, and the handshake hash `h`. With
HKDF-SHA256 (RFC 5869):

```
mac_c2s || mac_s2c = HKDF(ikm = k1 || k2, salt = h, info = "bomcensus-feed/1 mac", L = 64)
session_id         = base64url_nopad(HKDF(ikm = h, salt = "", info = "bomcensus-feed/1 session id", L = 16))
```

The session ID is not secret and is never sent by the server; both sides
compute it. The cipher states are not used further: messages are signed, not
encrypted.

A new session is pending until the server receives a request signed with it;
a pending session that is not confirmed within a minute is dropped. The
client confirms with a heartbeat right after the handshake.

## Signed messages

Every request in a session carries:

| Header | Value |
|---|---|
| `Feed-Session` | session ID |
| `Feed-Timestamp` | unix seconds |
| `Feed-Content-SHA256` | lowercase hex SHA-256 of the body as sent (compressed bytes if `Content-Encoding` is set) |
| `Feed-Signature` | standard base64 of `HMAC-SHA256(mac_c2s, string to sign)` |

String to sign, lines joined with `\n`:

```
FEED1-HMAC-SHA256
<Feed-Timestamp>
<Feed-Session>
<method, uppercase>
<path, escaped as sent>
<query: pairs sorted by key, then value; each form-encoded as key=value; joined with &>
<Content-Type, trimmed>
<Content-Encoding, trimmed, lowercase>
<hex SHA-256 of the body>
```

The server signs every response to a verified request with `mac_s2c`:

```
FEED1-HMAC-SHA256-RESPONSE
<Feed-Timestamp of the response>
<Feed-Signature of the request>
<status code>
<Content-Type>
<Content-Encoding>
<hex SHA-256 of the response body>
```

and sends `Feed-Timestamp`, `Feed-Content-SHA256` and `Feed-Signature`.
Including the request signature binds the response to its request.

Timestamps more than 5 minutes from the receiver's clock are refused. There
is no nonce: a captured request can be replayed within that window, which
the protocol accepts for its idempotent queries.

Proxies between client and server must not change the path, query, body or
the headers above.

### Errors

Errors are JSON `{"code": "...", "message": "..."}`. Errors produced before a
session is established or verified are not signed.

| Status | Code | Meaning |
|---|---|---|
| 401 | `missing_signature` | no session headers |
| 401 | `bad_signature` | signature or body hash does not match |
| 401 | `clock_skew` | timestamp outside the window; `Feed-Server-Time` carries the server clock |
| 401 | `session_unknown` | no such session (never existed, dropped, or ended) |
| 401 | `session_expired` | the session passed its expiry or idle timeout |
| 400 | `bad_handshake` | message 1 could not be read, or its Hello was refused |
| 415 | `unsupported_protocol` | the handshake media type names no version or an unsupported one; `Accept-Post` lists the supported ones |
| 403 | `blocked` | the instance is blocked |
| 429 | `rate_limited` | too many requests; `Retry-After` in seconds |

On `session_unknown` or `session_expired` the client runs a new handshake and
repeats the request once.

## Session lifetime

- `POST /v1/session/heartbeat` (signed, empty body) keeps the session alive
  and returns `{"session_expires": <unix>, "idle_timeout": <seconds>, "grade": "..."}`.
  Any signed request also counts as activity.
- `DELETE /v1/session` (signed) ends the session.
- The client replaces a session some minutes before `session_expires`.

## Test vectors

Handshake, version 1: client static private key 32 × `0x01`, server static
32 × `0x02`, client ephemeral 32 × `0x03`, server ephemeral 32 × `0x04`,
Hello `{"client":"bomcensus","version":"1.0.0","time":1795000000,"telemetry":true}`,
Welcome
`{"session_expires":1795086400,"heartbeat":300,"idle_timeout":900,"grade":"anonymous","server_time":1795000001}`:

```
session_id = wBs08tjslkX4ukHVEX86ew
mac_c2s    = 94b186270c9f755d37a7be04740eef40a6137e651a4d091a798698a743fb211f
mac_s2c    = ed1a56b4c8e9c0aa9f00ea8f4ec8c0e08aea65968877c9f3a009137b4f18e5d7
```

Request signature with key `01 02 03` followed by 29 zero bytes, timestamp
1795000000, session `sid`, `POST /v1/match?b=2&a=1&a=0`, `Content-Type:
application/json`, `Content-Encoding: gzip`, body `{}`:

```
FEED1-HMAC-SHA256
1795000000
sid
POST
/v1/match
a=0&a=1&b=2
application/json
gzip
44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a

Feed-Signature: U0Y4kbSu/cQOKyPX0EqOfAKFRPFKkRHU2TXNGY187G8=
```
