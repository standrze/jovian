# Routing, chaining, and conditional rules

Jovian chooses the destination after request modifiers and interception edits. The
final scheme, host, and port determine the connection pool entry. A session-bound
listener checks its allowed origin again before connecting, so a rule cannot
expand the session's allowed destinations.
Rules apply to HTTP requests, including decrypted HTTPS when interception is
enabled. CONNECT headers pass through modifiers; encrypted opaque tunnel payloads are not inspected. URL rewriting applies to decoded HTTP requests.

## Proxy chaining

```sh
jovian serve --upstream-proxy http://127.0.0.1:8888
```

`--downstream-proxy-url` is an alias for `--upstream-proxy`. Supported schemes:

| URL scheme | Default port | Transport and destination lookup |
|---|---|---|
| `http://` | 80 | HTTP proxy; absolute-form HTTP requests or CONNECT |
| `https://` | 443 | The same proxy protocol over validated TLS |
| `socks5://` / `socks5h://` | 1080 | SOCKS5 TCP CONNECT; both resolve destination hostnames at the proxy |

HTTP and HTTPS proxies receive absolute-form URLs for HTTP destinations.
SOCKS5 creates a connection to the origin, then receives origin-form HTTP.
Opaque client CONNECT creates an HTTP CONNECT or SOCKS5 tunnel. Intercepted
HTTPS, direct HTTPS URLs, and requests rewritten to HTTPS add validated TLS to
the final origin. An HTTPS next hop carries that origin TLS inside its own TLS
connection. Both layers validate the certificate chain and hostname before
sending application data. Chaining never falls back to a direct connection
when the next hop fails.

For an HTTPS proxy signed by a private CA, supply a PEM certificate bundle:

```sh
jovian serve --upstream-proxy https://proxy.example.test:8443 \
  --upstream-proxy-ca ./proxy-ca.pem
jovian serve --upstream-proxy socks5h://127.0.0.1:1080
```

Without `--upstream-proxy-ca`, HTTPS proxies use the existing upstream TLS policy
(system trust by default, or the explicit legacy `--upstream-ca` / `--skip-tls-verify` policy).
With it, the supplied certificates replace the trust anchors for that proxy
connection only. Hostname and certificate validity checks remain enabled. The
file never changes system trust or trust for the final origin. A CA option with
an HTTP/SOCKS proxy or without a proxy URL is rejected at startup.

Configure credentials for the next hop separately from credentials required by
Jovian's own listener:

```sh
export NEXT_PROXY_PASSWORD='your-password'
jovian serve --upstream-proxy http://127.0.0.1:8888 \
  --upstream-proxy-user tester \
  --upstream-proxy-password-env NEXT_PROXY_PASSWORD
```

Embedded URL credentials are rejected. HTTP/HTTPS next-hop `Proxy-Authorization`
is added only to the outgoing proxy request or CONNECT handshake. SOCKS5 uses
its separate username/password handshake when credentials are configured; each
field must contain 1–255 UTF-8 bytes. It offers only the configured authentication
method, so a proxy cannot downgrade configured authentication to no authentication.
Without credentials it offers only no authentication. SOCKS5 itself does not
encrypt this handshake ([RFC 1929](https://www.rfc-editor.org/rfc/rfc1929)).
TCP CONNECT and address encoding follow [RFC 1928](https://www.rfc-editor.org/rfc/rfc1928).
SOCKS4, GSSAPI, SOCKS BIND, UDP ASSOCIATE, and TLS-wrapped SOCKS are not implemented.

Next-hop credentials are absent from origin requests and Jovian's HAR, session
records, and traffic logs, including captures with sensitive-header redaction disabled. Client-supplied proxy
credentials are consumed locally and never reused for the next hop.

HTTP errors, including CONNECT rejection bodies and 407 authentication challenges,
remain HTTP responses. Connection/TLS/SOCKS negotiation failures produce 502.
Jovian applies its configured request deadline and connect timeout to chained
requests, including opaque tunnels.
Chaining is a startup/library option, not a runtime rule. Shutdown interrupts
pending next-hop TLS/SOCKS negotiation after the configured grace period.

Library users pass `UpstreamProxy(url:credentials:)` to `ProxyServer`'s optional
`downstreamProxy` initializer parameter. The optional `certificateAuthority: URL`
argument reads HTTPS proxy trust anchors at initialization.

## Martian configuration

POST a canonical one-key `package.Type` object to `/configure`. For example,
rewrite matching traffic while tagging the other requests:

```json
{
  "url.Filter": {
    "scope": ["request"],
    "host": "api.example.test",
    "path": "/v1/items",
    "modifier": {
      "fifo.Group": {
        "modifiers": [
          {"url.Modifier": {"scheme": "http", "host": "127.0.0.1", "path": "/fixtures/items"}},
          {"port.Modifier": {"port": 9000}}
        ]
      }
    },
    "else": {"header.Modifier": {"name": "X-Jovian-Unmatched", "value": "true"}}
  }
}
```

`url.Modifier` replaces nonempty `scheme`, `host`, decoded `path`, and raw
`query` fields. Other fields are preserved. `host` is an authority and can
include a port or bracketed IPv6. Empty fields are no-ops, matching Martian;
they cannot clear an existing query. Only HTTP(S) destinations are supported.
`port.Modifier` accepts exactly one of `port` (1–65535), `defaultForScheme: true`,
or `remove: true`. Rewriting updates both the destination and Host header.
Unchanged original Authorization and Cookie headers are removed when a rewrite
changes the origin; a rule may deliberately replace them for the new origin.

Supported canonical filters:

| Type | Match | Else |
|---|---|---|
| `url.Filter` | All nonempty `scheme`, `host`, exact decoded `path`, and raw `query` fields | Yes |
| `url.RegexFilter` | Regex search of the entire request URL | Yes |
| `header.Filter` | `name` and exact `value` against the current message's header values | Yes |
| `header.RegexFilter` | `header` and `regex`; response matching uses the request headers | No |
| `querystring.Filter` | Exact decoded parameter `name`, optionally `value`; any repeated value may match | Yes |
| `cookie.Filter` | Case-sensitive cookie `name`, optionally `value`; response checks Set-Cookie | Yes |
| `method.Filter` | One `method`, compared case-insensitively | Yes |
| `port.Filter` | Effective URL port, including implicit 80/443 | No |

Groups and branches nest recursively. Scope restricts whether the rule executes
on requests, responses, or both. Response URL/query/method/port conditions use
the final modified request destination/method. URL-host matching includes an
explicit port; `*` matches a complete single hostname label, as in
`*.example.test:8443`. Host matching is case-insensitive. For the pinned Martian
`header.Filter`, an omitted value means an exact empty value. Query and cookie
filters treat an omitted or empty value as a presence test.

Regex uses Foundation/ICU, **not full Go RE2 compatibility**. Patterns are
limited to 4096 UTF-8 bytes and each value match has a 50 ms processing budget.
A timeout fails the request before origin transmission when evaluated in request
scope; response-scope failures may occur after the request reached the origin.
Canonical header regex checks all matching header values rather than Martian's
first value. These differences remain partial compatibility.

## Jovian configuration

Existing Jovian modifier trees remain supported. New nodes are `url`, `port`, and
`match`. A `match` condition has a `kind` of `url`, `urlRegex`, `header`,
`headerRegex`, `queryString`, `cookie`, `method`, or `port`:

```json
{
  "modifier": {
    "type": "match",
    "scope": ["request"],
    "condition": {"kind": "header", "name": "Authorization"},
    "modifier": {"type": "url", "host": "localhost:9000", "path": "/authenticated"},
    "else": {"type": "url", "host": "localhost:9000", "path": "/anonymous"}
  }
}
```

Every Jovian `match` kind supports `else`. Header conditions without `value` test
presence; an explicit empty value matches only an empty header. Native
`headerRegex` checks the current message's headers for each scope. URL conditions
also accept `pathPrefix`, and method conditions take a `methods` array. The other
condition fields correspond to the canonical table above, except native header
regex uses `name` instead of `header`.

Invalid configuration leaves the active rules unchanged. Runtime modifier errors
propagate through the throwing `Modifier` interface; direct Swift callers of
`RuntimeConfiguration.modify` must now use `try`.

## Verification

```sh
swift test
swift build --product jovian
python3 scripts/routing-smoke.py
python3 scripts/routing-smoke.py --live
python3 scripts/upstream-proxies-smoke.py
python3 scripts/upstream-proxies-smoke.py --live
```

The default smoke uses temporary local origins, an authenticated next-hop proxy,
and an untrusted local TLS origin. `--live` additionally validates intercepted
chained HTTPS against `https://example.com/` using macOS trust. It requires
outbound network access. The upstream-proxies smoke covers HTTPS and SOCKS5
forwarding, CONNECT, authentication, remote DNS, trust isolation, early tunnel
bytes, malformed replies, pooling, failure behavior, and interrupted negotiation.
Its `--live` checks also cover nested origin TLS, HTTPS URL rewrites, and client
TLS interception through all next-hop schemes. No certificates are installed in
any trust store.
