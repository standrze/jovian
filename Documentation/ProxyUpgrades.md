# Proxy correctness, streaming, ranges, and dynamic TLS

## Via and loop detection

Every proxy instance adds `1.1 jovian-UNIQUE-ID` to the request's Via chain. Existing
hops and duplicate Via fields are preserved in one combined field. A request
containing this instance's identity receives 400 before DNS or origin contact.
This applies to HTTP, intercepted HTTPS, and CONNECT requests. CONNECT to a
next-hop proxy carries the Via chain as well; a next-hop rejection is reported
as 502 by the initiating proxy.

Via history is transport-owned. Modifiers and interceptors can inspect it, but
Jovian restores it before forwarding, so deleting it cannot disable loop detection.
Different Jovian instances have different identities even when chained together.
This follows Martian's per-instance loop-detection approach; it is not a new
registered canonical JSON type.

## Special header fields

Header replacement, append, blacklist, copy, filters, and verifiers understand
Martian's special `Host`, `Content-Length`, and `Transfer-Encoding` fields:

- Request Host defaults from the URL when absent. Changing it affects the HTTP
  virtual host, while URL/port modifiers control the actual network destination.
  Appending to a nonempty Host throws. A deleted/empty request Host falls back to
  URL authority when serialized. Response Host reads as absent, and setting
  or deleting it has no effect.
- Content-Length setters accept signed 64-bit integers; a negative value represents
  unknown length. Copy reads zero as `"0"`, but presence matching and verification
  treat zero and negative lengths as absent, matching Martian's `Get`/`All` distinction.
  Appending when the current length is positive throws. Deleting makes it unknown.
- Transfer-Encoding exposes its ordered coding list; copy uses the first coding,
  append extends it, and blacklist removes it.

These semantics apply at the modifier position. Jovian owns serialization: it
normalizes outgoing framing to the buffered body or original streaming source.
A header rule cannot make Jovian send 99 bytes when it only has an empty body.
Input with duplicate Content-Length, invalid lengths, conflicting length/encoding,
or transfer codings other than a single `chunked` is rejected. Large HTTP chunks
are split into bounded chunks; their extensions may be dropped while payload and
validated trailers are retained. HTTP/2 colon pseudo-headers are unsupported.

## Aggregated modifier errors

```json
{
  "fifo.Group": {
    "aggregateErrors": true,
    "modifiers": [
      {"header.Append": {"scope": ["request"], "name": "Host", "value": "duplicate.test"}},
      {"failure.Verifier": {"message": "still reached after the append error"}}
    ]
  }
}
```

All children run in declaration order for each direction. Errors are returned
after the last child, preserving execution order and nested group errors.
Without `aggregateErrors`, the first error stops the group. Child scopes and
filter branches still apply. Aggregation does not roll back successful mutations
or suppress errors: Jovian's existing proxy policy returns 502 for a modifier error.
Verification failures continue to be reported separately through `/verify`.
Swift callers use `ModifierGroup(children, aggregateErrors: true)` and can inspect
`ModifierErrors.errors`. Native Jovian group JSON retains its existing schema.

## Streaming logger bodies

`log.Logger` captures streaming uploads, fixed-length responses, chunked responses,
and streamed static files without eagerly reading the entire body. It freezes
headers at its modifier position and emits the body snapshot after transfer.
Deferred snapshots observe payload bytes passed through forwarding, including a
later replacement; they do not reconstruct an abandoned original body.

Reached logger nodes in one message share one bounded payload tee. The default
capture limit is 64 KiB, configurable in the library through `BodyCapturePolicy`.
Chunk framing is excluded. Truncation and interrupted transfers have explicit
markers, and each reached logger emits once. Headers-only logs remain immediate.
JSON/form field redaction and bounded diagnostic decompression still apply;
incomplete structured bodies are replaced by a redaction marker. A truncated or
oversized compressed body can produce a decode-unavailable marker. Logging does
not change forwarded bytes. Opaque tunnels and upgraded protocols have no HTTP
body snapshot.

## Replacement ranges and streamed files

`body.Modifier` and `static.Modifier` share byte-range handling: single, open-ended,
suffix, and multipart ranges. Satisfiable ranges produce 206; malformed or wholly
unsatisfiable ranges produce 416 with `Content-Range: bytes */SIZE`. A list can
contain at most 16 ranges. Out-of-bounds ends are clamped, and unsatisfiable entries
in an otherwise satisfiable list are omitted. Multipart parts include their MIME
type and Content-Range; the overall Content-Length includes multipart framing.
HEAD returns the corresponding metadata and no payload.

Replacement content remains limited to 1 MiB in configuration. Replacements can
replace streaming originals; unread uploads close the downstream connection and
unread origin responses retire their upstream connection. Static files larger
than 4 MiB stream in reads of at most 32 KiB from the validated file descriptor.
HEAD avoids reading file content. Existing traversal, symlink, and regular-file
checks remain. If the file becomes unreadable or shrinks during streaming, Jovian
closes the response rather than inserting another HTTP response into its body.
There is no directory listing or conditional-cache implementation.

## Dynamic TLS identities and nested interception

Create an explicit CA, then enable CA-backed SNI identities on the TLS listener:

```sh
jovian ca create --directory /tmp/jovian-test-ca
jovian serve --tls-port 4443 --tls-ca /tmp/jovian-test-ca --tls-default-host localhost
```

`--tls-ca` selects a certificate for each valid DNS SNI name and caches the issued
identity using the existing CA store. Missing SNI uses `--tls-default-host`, which
defaults to localhost. Invalid names fail the handshake. The CA must already
exist. Static `--tls-cert`/`--tls-key` and dynamic `--tls-ca` are mutually exclusive.
TLS requires version 1.2 or newer. No CA is installed or trusted automatically.
This adds dynamic identities to Jovian's explicit TLS proxy listener; it does not
implement transparent TCP redirection or HTTP/2.

Add `--intercept-ca /tmp/jovian-test-ca` to intercept CONNECT on both the ordinary
and TLS proxy listeners. Inside a TLS proxy connection, the inner TLS session is
terminated independently, then uses the same modifiers, control routes, ranges,
origin trust validation, and keep-alive behavior as ordinary interception.
Clients must trust both proxy and interception identities. Without `--intercept-ca`,
CONNECT remains opaque. Proxy authentication applies before CONNECT; the established
inner connection inherits that authorization. Pending inner handshakes are
interrupted when the shutdown grace deadline expires.

## Validation

```sh
swift test
swift build --product jovian
python3 scripts/proxy-upgrades-smoke.py
python3 scripts/mocking-smoke.py
python3 scripts/martian-completion-smoke.py --live
python3 scripts/headers-shaping-smoke.py --live
python3 scripts/routing-smoke.py --live
```

The upgrade smoke is entirely local and uses an isolated CA trusted only by its
test clients. It covers chained and self-chained proxies, special headers,
request/response aggregation, framing rejection, replacement/static ranges,
large fixed/chunked uploads and responses, log interruption, distinct SNI identities,
nested TLS interception with keep-alive, and shutdown during an inner handshake.
