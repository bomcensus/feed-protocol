# feed-protocol

Session protocol between [bomcensus](https://github.com/bomcensus/bomcensus) and its vulnerability feed server: a Noise IX handshake over X25519 keys, then HMAC-signed HTTP requests and responses. See [docs/PROTOCOL.md](docs/PROTOCOL.md).

```
instancekey/   X25519 keys, the "x25519 <base64>" public key form (instance ID), PEM private keys
handshake/     versioned Noise handshake (v1: Noise_IX_25519_AESGCM_SHA256), session key derivation
sign/          request and response signatures
client/        http.RoundTripper: handshake, trust on first use, signing, heartbeats, renewal
server/        net/http middleware: verification against a session store, response signing
```

## Client

```go
key, _ := instancekey.Generate(nil) // once; store key.MarshalPEM()
tr := &client.Transport{
	BaseURL: "https://feed.example.com",
	Key:     key,
	Trust:   trustStore, // client.TrustStore: remembers the server key met first
	Hello:   handshake.Hello{Client: "bomcensus", Version: version, Telemetry: true},
}
go tr.KeepAlive(ctx, logError)
httpClient := &http.Client{Transport: tr}
```

## Server

```go
v := &server.Verifier{Sessions: store} // server.Lookup
mux.Handle("/v1/", v.Middleware(api))
// POST /v1/session: handshake.ParseMediaType(Content-Type), handshake.Read, check Hello,
// Accept, store the session, reply with Content-Type handshake.MediaType(version).
```

## Development

```sh
make check   # vet, tests, license headers
make license # insert missing license headers
```

## License

Apache License 2.0. See [LICENSE](LICENSE).
