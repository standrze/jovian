# Martian compatibility target

Jovian's compatibility reference is the pinned `google/martian` commit
[`0f7e6797a04da412118541344bbe0d65945e24c9`](https://github.com/google/martian/tree/0f7e6797a04da412118541344bbe0d65945e24c9)
(Martian v3 source; the original audit recorded 2022-08-16). This document was
derived from that source tree, especially `cmd/proxy/main.go`, `parse/parse.go`, and every call to
`parse.Register`.

Status meanings:

- **Implemented**: behavior and external interface are compatible enough for a Martian client/configuration.
- **Partial**: Jovian has overlapping behavior, but Martian JSON, semantics, API, or coverage differs.
- **Missing**: no equivalent Martian-facing capability exists.

Having a generally similar proxy feature does not count as Martian compatibility.

The proxy engine work and executable regression coverage are tracked separately
in [ProxyEngineParity.md](ProxyEngineParity.md). The remaining JSON/control-plane
registry is outside that engine comparison.

## Proxy binary and control API

| Martian capability | Jovian | Evidence / gap |
|---|---|---|
| HTTP forward proxy | Implemented | Absolute-form HTTP requests are forwarded and logged. |
| HTTPS `CONNECT` tunnel | Implemented | TLS bytes pass between client and destination without decryption. |
| Dynamic TLS MITM | Implemented for HTTP/1.1 | Explicit CA generation/loading, cached DNS/IP identities, SNI selection, and local interception tests. |
| Persistent client connections | Implemented | Plain HTTP/1.1 accepts sequential and pipelined requests. |
| Runtime `POST /configure` | Partial | Jovian replaces configuration atomically and accepts its own schema plus five canonical `package.Type` nodes. Full registry and API parity are incomplete. |
| `GET /configure` | Jovian extension | Martian's modifier handler supports GET, but its representation and behavior need compatibility tests. |
| API through `http://martian.proxy/...` | Missing | Jovian exposes only the separate admin listener; it does not route the reserved proxy hostname to the API. |
| `GET /authority.cer` | Missing | CA export through both the API listener and reserved proxy hostname is absent. |
| `GET /verify`, reset | Partial | Endpoints exist, but only Jovian's top-level status/header rules feed them. Composable Martian verifiers are absent. |
| HAR `GET /logs`, reset | Partial | Endpoints and HAR 1.2 exist. Jovian deliberately omits bodies, uses bounded retention, and does not match Martian's full capture semantics. |
| Configurable logging modifier | Partial | Console/JSONL logging and bounded traffic body snapshots exist, but `log.Logger` JSON, `headersOnly`, and `decode` are absent. HAR still omits bodies. |
| `POST /shape-traffic` | Partial | Jovian has global upload/download byte rates and delays, not Martian's defaults, latency, URL regex shapes, byte ranges, halts, forced closes, or global bandwidth buckets. |
| API CORS flag | Missing | Jovian has a response CORS modifier, not Martian's CORS wrapper for control endpoints. |
| Direct TLS proxy listener (`-tls-addr`) | Implemented | `--tls-port` enables a TLS listener with SNI-selected identities. |
| Downstream proxy chaining | Implemented | `--downstream-proxy-url` supports HTTP/HTTPS next hops, credentials, absolute HTTP forwarding and CONNECT. |
| Optional insecure upstream TLS | Implemented | Validation is enabled by default; `--skip-tls-verify` and `--upstream-ca` explicitly configure upstream trust. |
| Proxy authentication | Partial | Jovian supports startup Basic credentials; Martian's `proxyauth` library behavior/API is not mirrored. |
| Graceful shutdown | Implemented with a finite bound | `shutdown(gracePeriod:)` drains current requests and rejects new work. The CLI drains on SIGINT/SIGTERM. Immediate `stop()` remains available. |

## Registered Martian JSON types

The original source audit recorded these 33 registered types in the pinned
Martian source. Jovian currently accepts five under the canonical one-key
envelope: `fifo.Group`, `header.Modifier`, `status.Modifier`, `body.Modifier`, and
`querystring.Modifier`. Parser and modifier tests exercise those nodes, but their
rows remain partial until the full semantics and integration acceptance rule
below are satisfied. Unknown types are rejected.

| Registered type | Jovian | Compatibility gap |
|---|---|---|
| `body.Modifier` | Partial | Canonical base64 `body` is accepted up to 1 MiB; Jovian's own schema also accepts UTF-8 `content`. Martian range-response behavior is not implemented. |
| `cookie.Filter` | Missing | No cookie-conditioned true/else filter. |
| `cookie.Modifier` | Partial | Basic set/remove exists; Martian appends cookies and accepts path, domain, expiry, secure, HTTP-only, and max-age. |
| `failure.Verifier` | Missing | Jovian's synthetic failure response is unrelated; Martian records a verifier error whenever traffic reaches this node. |
| `fifo.Group` | Partial | Canonical ordered grouping and scope are accepted; `aggregateErrors: true` is explicitly unsupported. Full Martian composition semantics need integration coverage. |
| `header.Append` | Missing | Jovian replaces all values rather than appending another field value. |
| `header.Blacklist` | Missing | No configurable header deletion list. |
| `header.Copy` | Missing | No copy-from/copy-to modifier. |
| `header.Filter` | Missing | No exact header true/else filter. |
| `header.Id` | Missing | No stable per-request `X-Martian-ID` equivalent. |
| `header.Modifier` | Partial | Canonical name/value and scope plus Jovian's own schema are accepted. Full Martian header behavior needs integration coverage. |
| `header.RegexFilter` | Missing | No request-header regular-expression filter. |
| `header.Verifier` | Partial | Host-scoped top-level expectations exist, not a composable scoped verifier. |
| `log.Logger` | Partial | Logging exists outside the modifier tree; canonical options and body logging are absent. |
| `method.Filter` | Partial | Method filtering exists, but schema, exact one-method semantics, scope, and `else` differ. |
| `method.Verifier` | Missing | No composable method verifier. |
| `noop.Modifier` | Missing | No canonical no-op node. |
| `pingback.Verifier` | Missing | No verifier that begins failed and passes after a matching URL is observed. |
| `port.Filter` | Missing | No URL-port-conditioned filter. |
| `port.Modifier` | Missing | No port set/default/remove URL and Host modifier. |
| `priority.Group` | Missing | No numeric-priority modifier group. |
| `querystring.Filter` | Missing | No query-conditioned true/else filter. |
| `querystring.Modifier` | Partial | Canonical name/value and request scope are accepted; Jovian's own schema additionally supports removal. Full Martian behavior needs integration coverage. |
| `querystring.Verifier` | Missing | No composable query verifier. |
| `skip.RoundTrip` | Missing | Synthetic responses can avoid an origin connection, but do not implement Martian's context-driven skip-round-trip primitive. |
| `stash.Modifier` | Missing | No request-URL snapshot copied through a named header into the response. |
| `static.Modifier` | Missing | No rooted local-file response modifier or explicit path map. |
| `status.Modifier` | Partial | Canonical status code and response scope plus Jovian's own schema are accepted. Full Martian behavior needs integration coverage. |
| `status.Verifier` | Partial | Host-scoped top-level expected status exists, not a composable scoped verifier. |
| `url.Filter` | Partial | Jovian supports host plus path-prefix matching; Martian matches optional scheme, host, exact path, and raw query with true/else branches. |
| `url.Modifier` | Missing | No scheme/host/path/raw-query URL replacement. |
| `url.RegexFilter` | Missing | No RE2-compatible full-URL regular-expression filter. |
| `url.Verifier` | Missing | No composable scheme/host/path/query verifier. |

## Programmatic packages outside the JSON registry

The Martian source also includes library-level behavior not represented by the
33 registered JSON names. Important compatibility areas include `auth`, `cors`,
`h2`, `har`, `httpspec`, `ipauth`, `messageview`, `mitm`, `proxyauth`,
`servemux`, `trafficshape`, and request `Context` state. These must be audited
separately; their presence in Martian does not imply they are enabled by the
stock proxy binary. MARBL is a stock opt-in `-marbl` feature with a `/binlogs`
endpoint; Jovian does not implement that logging format.

## Implementation order

1. **Canonical parser and composition core** — extend the existing one-key
   envelope, scope, and five supported nodes with remaining composition semantics
   and Martian-style true/`else` filters. Complete integration fixtures for
   `fifo.Group` and its child modifiers.
2. **Control-plane compatibility** — reserved `martian.proxy` routing,
   `/configure`, `/verify`, reset routes, `/logs`, and `/authority.cer` on both
   proxy and API listeners.
3. **Core mutation/filter parity** — header family, URL/query/method/cookie
   filters and modifiers, status/body, priority, port, stash, no-op, and skip.
4. **Verifier parity** — header, status, method, URL, query, failure, and
   pingback with correct reset/initial-state behavior.
5. **Mocking and observability** — static files, modifier logging, full optional
   HAR capture, and API CORS.
6. **Network API parity** — Martian traffic-shape schema/actions. Chaining,
   direct TLS, interception, deadlines, and bounded draining are covered by the
   separate engine implementation and regression tests.
7. **Library-only review** — decide explicitly whether `h2`, MARBL, mobile,
   and other non-stock-binary packages belong in Jovian's compatibility promise.

## Acceptance rule

A row moves to **Implemented** only when Jovian accepts a Martian-format fixture
for that capability and an integration test proves the externally visible
behavior. Jovian-only features may remain, but they do not advance this matrix.
