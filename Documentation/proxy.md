# jovian

jovian is a Swift implementation of the small, composable proxy architecture used by [Google Martian](https://github.com/google/martian). It is an HTTP/1.1 forward proxy with traffic logging and HTTPS tunnels.

## Current features

- Concurrent HTTP forwarding
- Persistent downstream HTTP/1.1 connections, including pipelined requests
- Bounded per-origin upstream HTTP connection pooling
- `Expect: 100-continue`, informational `1xx` responses, and `103 Early Hints`
- HTTPS `CONNECT` tunneling, with TLS handled by the client and destination
- Console and JSON Lines traffic logs
- In-memory HAR 1.2 capture with retrieval and reset endpoints
- Loopback runtime configuration and verification API
- Host-specific status and request/response header verifiers with resettable failures
- Ordered request/response `Modifier` pipeline
- Header modifier and host filter
- HTTP and HTTPS downstream proxy chaining
- Optional TLS interception and a direct TLS listener with dynamic SNI certificates
- Configurable request/connect timeouts and bounded graceful shutdown
- Via loop detection and forwarding headers
- Loopback-only default listener

CONNECT tunnels are opaque by default. Configuring an authority enables TLS
interception and applies the same request/response modifiers to decrypted HTTP.
Absolute-form HTTPS requests use a verified upstream TLS connection.

## Build and test

Requires macOS 13 or later and Swift 6.4. Run these commands from the
`jovian/` package directory. No separate OpenSSL installation is needed;
the [certificate guide](certificates.md) explains transitive crypto code.

```bash
swift build
swift test
```

## Run the proxy

```bash
swift run jovian serve
```

Add `--har traffic.har` to keep a bounded HAR file after a standalone run.
The file is updated after each completed request. To store it with a workspace,
choose a path beneath that workspace's `runs/` folder. Jovian is an independent
Swift package and command. The optional `jovian-plugin` adapter embeds it in
ono-sendai; the standalone command works without that host or lowlight.

The default listener is `127.0.0.1:8080`. Configure both the HTTP and HTTPS proxy in a test browser to that address, or use curl:

```bash
curl -x http://127.0.0.1:8080 http://example.com/
curl -x http://127.0.0.1:8080 https://example.com/
```

The control API listens on `127.0.0.1:8181` by default. Change it with `--api-host` and `--api-port`. Keep it on loopback unless you add an authentication boundary in front of it.

## HTTPS and proxy chaining

Enable interception with an in-memory authority and export its public certificate:

```sh
swift run jovian serve --generate-ca-cert --ca-output /tmp/jovian-authority.pem
```

Clients must explicitly trust that certificate for the test session. This command
does not install system trust or persist the private key. To reuse an existing
CA, pass `--cert authority.pem --key authority-key.pem`. Both files must contain
matching PEM material. Certificates are generated for DNS names or IP addresses,
cached with a bounded capacity, and limited to the authority's validity.

Add `--tls-port 4443` to accept proxy connections over TLS. SNI chooses the leaf
identity; `--tls-server-name localhost` sets the fallback for clients without SNI.
HTTP/1.1 is advertised for both TLS directions. Upstream certificates and names
are verified by default. Use `--upstream-ca origin-ca.pem` for private test roots;
`--skip-tls-verify` explicitly disables upstream validation for a test session.

Forward requests through another proxy:

```sh
swift run jovian serve --downstream-proxy-url http://127.0.0.1:8888
```

Both HTTP and HTTPS next-hop URLs are supported. Plain HTTP uses absolute-form
requests; HTTPS origins and opaque CONNECT traffic use a next-hop CONNECT.
URL credentials are supplied only to the next proxy and are excluded from traffic
records. A unique Via identity per instance permits chains of Jovian proxies.

`--request-timeout 300` bounds each request's socket work and pacing; zero disables
it. `--connect-timeout 30` limits connection establishment. SIGINT and SIGTERM stop
new requests and allow active work up to `--shutdown-grace 30` seconds before
closing remaining connections. Custom synchronous callbacks must terminate or
respond to their own cancellation hook. System DNS resolution can remain pending
until the connect timeout; the grace period does not forcibly terminate resolver work.

See [the source-based engine comparison](ProxyEngineParity.md) for coverage and
intentional boundaries.

## Proxy authentication

Require HTTP Basic proxy authentication without placing the password in command-line arguments:

```bash
export JOVIAN_PROXY_PASSWORD='use-a-secret-value'
swift run jovian serve \
  --proxy-user tester \
  --proxy-password-env JOVIAN_PROXY_PASSWORD
```

Clients without valid credentials receive `407 Proxy Authentication Required` and a `Proxy-Authenticate` challenge. Valid `Proxy-Authorization` credentials are consumed by jovian and never forwarded upstream or written to HAR. Basic authentication is only base64 encoding, so keep the proxy on loopback or a trusted protected network.

Test with curl:

```bash
curl -x http://127.0.0.1:8080 --proxy-user 'tester:use-a-secret-value' http://example.com/
```

## Traffic-rate shaping

Set per-connection upload and download rates in bytes per second:

```bash
swift run jovian serve --upload-bps 65536 --download-bps 131072
```

Shaping covers HTTP payload bytes and opaque bytes in `CONNECT` tunnels. HTTP
headers and chunk-framing overhead are not included. Transfer pacing suspends
asynchronous work without blocking NIO event loops.

## Runtime configuration API

Replace the active runtime rules without restarting the proxy:

```bash
curl -X POST http://127.0.0.1:8181/configure \
  -H 'Content-Type: application/json' \
  --data '{
    "requestHeaders": {"X-Through-Proxy": "true"},
    "responseHeaders": {"X-Jovian": "true"},
    "verifyStatus": {"example.com": 200}
  }'
```

Available endpoints:

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/health` | Health and current HAR entry count |
| `GET` | `/configure` | Read active runtime rules |
| `POST` | `/configure` | Replace runtime header modifiers and status verifiers |
| `GET` | `/logs` | Retrieve an in-memory HAR 1.2 document |
| `DELETE` or `POST` | `/logs/reset` | Clear captured HAR entries |
| `GET` | `/verify` | Retrieve verification failures |
| `POST` or `DELETE` | `/verify/reset` | Clear verification failures |

The in-memory HAR retains at most 10,000 entries; `--har` files retain at most
1,000 entries by default. HAR records request/response headers and computed
header sizes, parsed query parameters, URL/method, response status/size and MIME
type, timing, and transport. By default, `Authorization`, `Proxy-Authorization`,
`Cookie`, and `Set-Cookie` values are stored as `[REDACTED]`. HAR omits bodies.

`TrafficEntry` can contain bounded body snapshots, and `--log` writes those
records as JSON Lines, including available body data. Header redaction does not
redact secrets embedded in a URL or body. Console diagnostics contain summary
metadata, omit headers and bodies, and strip URL credentials, query strings, and fragments.

For an isolated, authorized debugging session, exact sensitive header values can be retained:

```bash
swift run jovian serve --capture-sensitive-headers
```

This option affects only log/HAR copies. It does not change forwarding. Treat the resulting logs as credentials: keep the API on loopback, restrict file permissions, and delete the capture when finished.

Nested modifier trees use the same composition model as Martian:

```json
{
  "modifier": {
    "type": "group",
    "modifiers": [
      {
        "type": "header",
        "scope": ["request"],
        "name": "X-Global",
        "value": "true"
      },
      {
        "type": "hostFilter",
        "host": "example.com",
        "modifier": {
          "type": "header",
          "scope": ["response"],
          "name": "X-Filtered",
          "value": "true"
        }
      }
    ]
  }
}
```

Supported runtime modifier nodes:

| `type` | Fields | Behavior |
|---|---|---|
| `header` | `scope`, `name`, `value` | Add or replace a request/response header |
| `group` | `modifiers` | Apply child modifiers in order |
| `hostFilter` | `host`, `modifier` | Apply a child only for an exact hostname |
| `methodFilter` | `methods`, `modifier` | Apply a child for selected HTTP methods |
| `urlFilter` | optional `host`, optional `pathPrefix`, `modifier` | Apply a child when URL fields match |
| `status` | `statusCode`, optional `reason` | Replace the response status |
| `delay` | `scope`, `milliseconds` | Delay requests/responses by up to 60 seconds |
| `queryString` | `name`, optional `value` | Replace a query parameter, or remove it when value is omitted |
| `cookie` | `scope`, `name`, optional `value` | Replace/add a cookie, or remove it when value is omitted |
| `body` | `scope`, `content`, optional `contentType` | Replace a buffered request/response body with UTF-8 content |
| `failure` | `statusCode`, optional `reason`, `content`, `contentType` | Return a synthetic 4xx/5xx response without connecting upstream |
| `ipFilter` | `networks`, `modifier` | Apply a child for actual client IPv4/IPv6 addresses or CIDR ranges |
| `cors` | `allowOrigin`, optional method/header/credential/max-age fields | Add validated CORS response headers |

Filters and groups can be nested arbitrarily. For example, a method filter can contain a URL filter, which can contain a status or header modifier. Header and status values are validated against CRLF response splitting.

Targeted failure injection:

```json
{
  "modifier": {
    "type": "urlFilter",
    "host": "api.example.test",
    "pathPrefix": "/maintenance",
    "modifier": {
      "type": "failure",
      "statusCode": 503,
      "reason": "Planned Outage",
      "content": "try later",
      "contentType": "text/plain"
    }
  }
}
```

Matching failures short-circuit before DNS resolution or TCP connection. They are logged with the `synthetic` transport label and can still be processed by response modifiers later in the same group.

Runtime traffic shaping uses top-level configuration fields:

```json
{
  "uploadBytesPerSecond": 65536,
  "downloadBytesPerSecond": 131072
}
```

Runtime values override startup shaping rates. Posting a new configuration replaces the full runtime document; omit both rate fields to return to startup defaults.

Header verification is also host-scoped. An expectation without a `value` checks only that the header is present:

```json
{
  "verifyRequestHeaders": {
    "example.com": [{"name": "X-Client-Version", "value": "2"}]
  },
  "verifyResponseHeaders": {
    "example.com": [{"name": "X-Request-ID"}]
  }
}
```

Header names and hostnames are matched case-insensitively. Failures distinguish missing headers from value mismatches and appear through `GET /verify` alongside status failures.

IP filters use the accepted socket peer address and ignore spoofable headers such as `X-Forwarded-For`. Both exact addresses and CIDR ranges are accepted, including IPv6:

```json
{
  "type": "ipFilter",
  "networks": ["127.0.0.0/8", "2001:db8::/32"],
  "modifier": {
    "type": "failure",
    "statusCode": 403,
    "content": "blocked by client network"
  }
}
```

CORS rejects the invalid combination of wildcard origin plus credentials. Non-wildcard origins automatically add `Vary: Origin`.

Add request/response modifiers and persistent JSON Lines logging:

```bash
swift run jovian serve \
  --request-header 'X-Through-Proxy:true' \
  --response-header 'X-Jovian:true' \
  --log traffic.jsonl
```

## Architecture

See [networking](networking.md) for event-loop ownership, memory limits,
connection reuse, upgrades, and the public API migration.

- `ProxyServer` owns listening, forwarding, persistent downstream connections, `CONNECT`, and request lifecycles.
- `UpstreamConnectionPool` retains up to four safely delimited idle connections per origin for 30 seconds.
- Pool reuse requires a complete no-body, fixed-length, or terminal-chunk boundary and origin keep-alive approval. EOF-delimited, expired, failed, upgraded, and `Connection: close` connections are discarded.
- `Modifier` mirrors Martian's request/response modification interfaces.
- `ModifierGroup` applies small behaviors in deterministic order.
- `HostFilter` conditionally applies a contained modifier.
- `TrafficLogger` supports multiple log destinations without coupling logging to transport.
- `RuntimeConfiguration` is both a modifier and verifier logger, allowing atomic rule replacement.
- `AdminServer` exposes the local control API; `HARStore` owns bounded capture.
- `ProxyCredentials` compares credential bytes; `TransferPacer` paces payload bytes per connection.

## Deliberate first-milestone limits

- Runtime configuration implements a growing subset of Martian's modifier/filter registry; priority and advanced network-condition filters are not yet included.
- Body replacement is bounded: complete request bodies up to 4 MiB are mutable;
  larger bodies stream incrementally. Fixed or close-delimited responses up to
  4 MiB are mutable, while larger and chunked responses stream without body
  replacement. Runtime replacement content is limited to 1 MiB. NIO owns wire
  framing, so chunk extensions are not reproduced byte for byte.
- The admin API has no authentication and therefore defaults to loopback only.
- HAR omits bodies. Proxy authentication remains a startup option; byte-rate shaping supports both startup defaults and runtime overrides.
- Downstream HTTP/1.1 connections can carry multiple sequential or pipelined requests. Upstream HTTP connections are pooled only after complete no-body, fixed-length, or chunked responses; close-delimited or origin-closed connections are discarded.
- HTTPS `CONNECT` traffic stays opaque unless an interception authority is configured. Interception is HTTP/1.1 only.
- Accepted `101 Switching Protocols` upgrades switch to an opaque bidirectional
  stream after the HTTP handshake; rejected upgrades close the downstream
  connection after the final HTTP response.
- Chunked requests and responses stream incrementally; request trailers are validated and preserved on the streaming path.
- This package is validated on macOS. Linux support has not been established by
  the current test fixtures.

Use this software only for traffic and systems you are authorized to test.

## Consolidated features

The original Jovian options remain supported. `--upstream-proxy` aliases
`--downstream-proxy-url` and adds `socks5` / `socks5h` (remote DNS).
Use `--upstream-proxy-user` with `--upstream-proxy-password-env` to keep next-hop
credentials out of URLs. `--upstream-proxy-ca` supplies PEM next-hop trust without
changing origin trust. No failed next hop falls back to a direct connection.

`jovian ca create --directory DIR` creates a persistent authority;
`jovian ca issue HOST --directory DIR` exports a local TLS identity.
`--intercept-ca DIR` loads it for interception, and `--tls-ca DIR` loads it
for SNI-based proxy TLS. Static listener identities use `--tls-cert` / `--tls-key`.
These commands do not install any system trust.

`--har-bodies`, `--har-body-limit`, `--har-body-budget`, and repeated
`--body-redact-field` opt into bounded redacted HAR bodies. The default omits
bodies. `--api-cors` enables control CORS. Both the admin listener and reserved
`http://martian.proxy/` expose configuration, verification, logs, traffic
shaping, and public authority export. Proxy authentication applies to the
reserved host; the separate admin listener remains a local trusted interface.

`jovian sessions new NAME --origin URL [--retain-bodies]` creates a bounded store.
`list`, `show`, `close`, `resume`, `delete`, and `retention` manage it.
`serve --session NAME` checks the origin before and after edits and records
traffic. `--sessions-directory DIR` and `JOVIAN_SESSIONS_DIR` choose storage.
The direct request API is `JovianRequestExecutor`; it does not follow redirects.

The CLI returns 502 on modifier errors. Existing library callers retain warning
and forwarding behavior by default; choose `failOnModifierError: true` for the
CLI policy. RuntimeConfiguration and HeaderModifier now expose throwing modifier
methods, so direct calls need `try`. Explicit body replacements now also work
on streamed sources; replaced unread bodies retire their channels instead of
blocking on a drain.

Examples and behavior limits:
[Routing](Routing.md), [Mocking and verification](MockingAndVerification.md),
[Logging and listeners](MartianCompletion.md),
[Headers and traffic shaping](HeadersAndTrafficShaping.md),
[Streaming and ranges](ProxyUpgrades.md).
