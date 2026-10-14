# Cookies, priority, logging, and listeners

Jovian now parses all 33 registered modifier names from the pinned Martian source.
Acceptance of every name does not mean full semantic parity; see
[the compatibility matrix](martian-compatibility.md).

## Priority groups and URL stashing

Post this canonical configuration to `/configure`:

```json
{
  "priority.Group": {
    "scope": ["request", "response"],
    "modifiers": [
      {
        "priority": 100,
        "modifier": {
          "stash.Modifier": {
            "scope": ["request", "response"],
            "headerName": "X-Original-URL"
          }
        }
      },
      {
        "priority": 0,
        "modifier": {"url.Modifier": {"path": "/rewritten"}}
      }
    ]
  }
}
```

Higher numbers run first in both directions. Equal priorities execute in reverse
JSON declaration order, matching Martian's newer-before-older insertion rule.
An omitted priority is zero. Priorities must be integers, not booleans or strings.
Child scopes still apply. Modifier errors stop subsequent children.

Stash records the URL at its position in the request chain. Its response operation
copies the final request's named header, so later header changes are visible.
Response scope also requires request scope. Invalid header names are rejected.
The stashed URL travels to the origin as a header and can contain query values.

## Canonical cookie appending

```json
{
  "cookie.Modifier": {
    "scope": ["request", "response"],
    "name": "test-session",
    "value": "example",
    "path": "/",
    "domain": "example.com",
    "expires": "2027-04-12T23:20:50Z",
    "secure": true,
    "httpOnly": true,
    "maxAge": 86400
  }
}
```

The request operation appends `name=value` to the first Cookie header, retaining
existing cookies, including duplicates with the same name. The response operation
adds a separate Set-Cookie field with attributes, preserving origin Set-Cookie
fields. Request cookies do not carry response attributes. A leading dot in Domain
is removed. Spaces/commas in values are quoted. Positive MaxAge emits seconds,
zero omits the attribute, and negative MaxAge emits `Max-Age=0`.

Jovian rejects invalid cookie names, control characters, unsupported cookie value
characters, malformed domains, invalid dates, and non-integer MaxAge values at
configuration time. Go may sanitize or drop some of these instead. Native Jovian
`cookie` rules continue to provide set/remove behavior.

## Filtered message logging

```json
{
  "url.Filter": {
    "path": "/api/failure",
    "modifier": {
      "log.Logger": {
        "scope": ["response"],
        "headersOnly": false,
        "decode": true
      }
    }
  }
}
```

A logger snapshots the message at its position in the modifier tree. It prints
one bounded message per invocation to stdout. Swift callers can supply a
`RuntimeConfiguration(modifierLogSink:)` closure instead. Multiple matching
logger nodes produce multiple snapshots. `headersOnly` omits the body entirely.
`decode` uses Apple's Compression framework to decode gzip, zlib-wrapped deflate,
or raw deflate for diagnostics without changing the forwarded headers or payload.
Gzip/zlib headers and checksums are validated separately from raw DEFLATE decoding.
As before, trailing bytes and concatenated gzip members are rejected.
Decoding is capped at 64 KiB by default; malformed,
unsupported, or oversized encodings yield an explicit marker without failing
forwarding. Binary snapshots are base64.

Credential headers are redacted. JSON and URL-encoded form credential fields are
redacted recursively/by decoded field name. CLI `--body-redact-field NAME` adds
case-insensitive field names to both message logs and HAR capture. Library callers
can configure `BodyCapturePolicy` via `modifierLogCapture` or directly on
`MessageLoggerModifier`.

Buffered bodies are logged immediately. Streaming bodies use a shared bounded
payload tee and emit once after transfer, with explicit truncation/interruption
markers. Headers are frozen at the modifier position. See [streaming logger
semantics](ProxyUpgrades.md#streaming-logger-bodies). Exact Go message dumps,
snapshot timing, and decode-error behavior are not mirrored.

## Optional HAR body retention

```sh
jovian serve --har-bodies --har-body-limit 65536 --har-body-budget 33554432 \
  --body-redact-field client_secret
```

Body retention is off by default, including inside `HARStore`. Opt-in retention
is capped per body (default 64 KiB, maximum 4 MiB) and across retained bodies
(default 32 MiB, maximum CLI budget 256 MiB). The history also keeps its existing
10,000-entry cap. Oldest entries are evicted until both caps fit; an entry larger
than the total budget is evicted too. Reset releases the retained body budget.

Captured request bodies use HAR `postData.text` for UTF-8, with `_encoding: base64`
for binary payloads. Response content uses standard HAR `encoding: base64`.
`_truncated` distinguishes prefixes from complete payloads. Streaming uploads and
responses retain bounded decoded HTTP payload prefixes, excluding chunk framing.
Opaque CONNECT/upgrade payloads are not captured as HTTP bodies. Partial transfers
closed by traffic shaping retain the available snapshot and truncation marker.

Default redacted fields are password, passwd, secret, token, access_token,
refresh_token, api_key, apikey, and authorization. Complete JSON and form bodies
are redacted before retention; unsafe incomplete, encoded, or malformed structured
bodies are replaced by a marker. Redaction does not alter forwarded traffic.
It is field-based: arbitrary text, binary data, URL/query values, and secrets under
other field names can still be retained. Header capture retains its existing
`--capture-sensitive-headers` opt-in. HAR retention is independent of disk session
body retention and JSONL logging.

## Shared control routes and CORS

Every existing control route is available on the admin listener and through the
proxy at `http://martian.proxy/PATH`. No DNS lookup or upstream connection is
made for the reserved hostname. Control requests bypass modifiers, session-origin
checks, and HAR recording. Proxy authentication still applies on the proxy port.
The separate admin listener remains unauthenticated and defaults to loopback.

```sh
curl --proxy http://127.0.0.1:8080 http://martian.proxy/configure
curl --proxy http://127.0.0.1:8080 http://martian.proxy/authority.cer
curl http://127.0.0.1:8181/authority.cer
```

With `--intercept-ca PATH`, `/authority.cer` returns the public CA certificate in
PEM format with `application/x-x509-ca-cert`, matching Martian. It returns 404 if
no interception CA is configured. No private key is exported.

`--api-cors` (alias `--cors`) enables Martian-style `Access-Control-Allow-Origin: *`
when Origin is supplied. Requested methods/headers are echoed; OPTIONS preflight
returns an empty 200 without invoking the route. The wrapper covers route errors
as well as successes on both listeners. It is disabled by default and does not
allow credentials. Control bodies use one Content-Length up to 1 MiB;
Transfer-Encoding is rejected. Responses close the connection.

## TLS proxy listener

Supply a certificate valid for the proxy hostname/IP and its matching key:

```sh
jovian serve --tls-host 127.0.0.1 --tls-port 4443 \
  --tls-cert certificates/hosts/127.0.0.1/cert.pem \
  --tls-key certificates/hosts/127.0.0.1/key.pem

curl --proxy https://127.0.0.1:4443 --proxy-cacert certificates/ca-cert.pem \
  http://example.com/
```

All three of `--tls-port`, `--tls-cert`, and `--tls-key` are required. Host defaults
to the ordinary proxy bind host. Certificate/key pairing is checked before binding.
TLS 1.2 or newer is required. Clients must trust the proxy identity separately
from their origin trust. The ordinary HTTP proxy listener stays available.

The TLS listener accepts absolute-form HTTP/HTTPS requests and CONNECT
(including end-to-end HTTPS inside the encrypted proxy connection). Origin-form
requests use `https://HOST/path`, with Host required. Proxy authentication and
shared control routing apply. Origin TLS validation remains enabled.

Alternatively, `--tls-ca DIRECTORY` selects dynamic SNI identities from an existing
CA, with `--tls-default-host localhost` used when SNI is absent. It replaces the
static certificate/key options. `--intercept-ca DIRECTORY` enables interception
inside TLS-proxy CONNECT as well as ordinary CONNECT; without it CONNECT is
opaque. See [dynamic TLS and nested interception](ProxyUpgrades.md#dynamic-tls-identities-and-nested-interception).
The listener speaks HTTP/1.1 and does not implement transparent TCP redirection.

## Bounded graceful shutdown

```sh
jovian serve --shutdown-grace-ms 5000
```

SIGINT and SIGTERM stop both proxy listeners and the admin listener, interrupt
idle client reads, and let active exchanges finish. Completed connections stop
accepting additional keep-alive requests. Response headers generated during drain
advertise Connection: close. Tunnels/upgrades count as active until they close.

At the deadline, client/upstream transport I/O and pacing/shaping/interception
waits are interrupted. Active TLS handles are fjovian by their owning worker, after
I/O exits, rather than concurrently by the stopping thread. The process remains
alive during the grace period. A deadline diagnostic identifies forced shutdown.
The CLI default is five seconds, configurable from zero to five minutes.

Swift callers use `server.stop(gracePeriod: seconds)`. The return value is true
when connections drained, false when the deadline required cancellation. Default
library stop remains immediate. It does not guarantee every worker has exited
when cancellation is required: DNS/connect/handshake work already in progress may
finish on its transport timeout. Server instances cannot restart after stop.

## Validation

```sh
swift test
swift build --product jovian
python3 scripts/proxy-upgrades-smoke.py
python3 scripts/martian-completion-smoke.py --live
python3 scripts/headers-shaping-smoke.py --live
python3 scripts/mocking-smoke.py
python3 scripts/routing-smoke.py --live
```

The completion smoke uses isolated temporary state and explicit client trust,
without installing a CA in the system keychain. `--live` adds a trusted public
HTTPS-origin probe. Unit tests cover priorities/ties/scopes, cookie attributes,
redacted logger snapshots, bounded decompression, HAR limits/reset, CORS/framing,
proxy-authenticated reserved routing, successful drain, and deadline cancellation.

Standalone validation does not claim compatibility with an external Lowlight
build or its session adapter.
