# Martian compatibility target

Jovian targets the final archived `google/martian` `master` commit
[`0f7e6797a04da412118541344bbe0d65945e24c9`](https://github.com/google/martian/tree/0f7e6797a04da412118541344bbe0d65945e24c9)
(Martian v3 source, 2022-08-16). This document is derived from that source tree,
especially `cmd/proxy/main.go`, `parse/parse.go`, and every call to
`parse.Register`.

Status meanings:

- **Implemented**: behavior and external interface are compatible enough for a Martian client/configuration.
- **Partial**: Jovian has overlapping behavior, but Martian JSON, semantics, API, or coverage differs.
- **Missing**: no equivalent Martian-facing capability exists.

Having a generally similar proxy feature does not count as Martian compatibility.

## Proxy binary and control API

| Martian capability | Jovian | Evidence / gap |
|---|---|---|
| HTTP forward proxy | Implemented | Absolute-form HTTP requests are forwarded and logged. |
| HTTPS `CONNECT` tunnel | Implemented | Tunneling is the default when no interception CA is configured. |
| Dynamic TLS MITM | Partial | Dynamic host certificates and validated upstream TLS work. Jovian retains ephemeral CA generation and native X.509 validity/cache checks. CLI spelling and transparent TCP redirection differ. |
| Via and loop detection | Implemented | Per-instance request Via identities preserve hop history, reject returning traffic before origin contact, and propagate through next-hop CONNECT. Protected against header-rule deletion. |
| Persistent client connections | Implemented | Plain and intercepted HTTP/1.1 accept sequential and pipelined requests. |
| Runtime `POST /configure` | Partial | Atomic replacement accepts native Jovian rules and the explicit canonical subset below; unsupported types fail. |
| `GET /configure` | Jovian extension | Martian's modifier handler supports GET, but its representation and behavior need compatibility tests. |
| API through `http://martian.proxy/...` | Implemented | Shared control routes bypass origin DNS, modifiers, and traffic logs; proxy authentication is enforced. |
| `GET /authority.cer` | Implemented | PEM CA export with Martian content type on admin and reserved proxy routes; no private key exposure. Absent CA returns 404. |
| `GET /verify`, reset | Partial | Composable canonical verifiers and legacy host rules feed `/verify`; reset clears failures and re-arms pingbacks. Jovian uses bounded retention and redacted diagnostic strings. |
| HAR `GET /logs`, reset | Partial | Endpoints and HAR 1.2 exist. Optional bounded body capture supports JSON/form field redaction, binary base64, and truncation markers. Default retention omits bodies. Jovian does not match Martian's full capture semantics. |
| Configurable logging modifier | Partial | Canonical `log.Logger`, `headersOnly`, and bounded gzip/deflate decoding work at the modifier position, with redaction. Streaming bodies use bounded deferred payload tees with interruption/truncation markers; text format and snapshot timing differ. |
| `POST /shape-traffic` | Partial | Canonical defaults, latency, URL regex policies, byte throttles, halts, closes, and aggregate limits have unit/wire coverage. Strict pacing, ICU, decoded chunk offsets, policy replacement, and corrected up/down labels differ from the pinned implementation. |
| API CORS flag | Implemented | Opt-in `--api-cors` handles Origin and preflight headers on both control paths. |
| Direct TLS proxy listener (`-tls-addr`) | Partial | Static or CA-backed SNI identities accept absolute-form HTTP/HTTPS, origin-form HTTPS, control requests, and CONNECT. Explicit interception CA enables nested TLS MITM. No transparent TCP redirection; Jovian CLI flags differ. |
| Downstream proxy chaining | Partial | `--upstream-proxy` / `--downstream-proxy-url` supports HTTP, HTTPS, and SOCKS5 (`socks5`/`socks5h`) next hops for HTTP, CONNECT, and intercepted HTTPS. Separate Basic/SOCKS credentials; optional HTTPS proxy CA file. Proxy and origin TLS validate independently; SOCKS hostnames resolve remotely. SOCKS4, GSSAPI, BIND, and UDP are absent. |
| Optional insecure upstream TLS | Implemented | Verification is enabled by default. Existing `--skip-tls-verify` and `--upstream-ca` remain available for explicit test configurations; `--upstream-proxy-ca` configures next-hop trust separately. |
| Proxy authentication | Partial | Jovian supports startup Basic credentials; Martian's `proxyauth` library behavior/API is not mirrored. |
| Graceful shutdown | Implemented | SIGINT/SIGTERM stops listeners and idle clients, drains active connections to a configurable deadline, then interrupts transport and shaping waits. Library `shutdown(gracePeriod:)` waits for the bounded drain. |

## Registered Martian JSON types

Martian registers exactly these 33 types in the pinned source. Jovian now parses
all 33 names under the canonical one-key envelope, with the behavioral limits
listed below. Parser coverage alone does not establish full compatibility. Routing behavior, deliberate differences,
and verification commands are documented in [Routing](Routing.md) and
[Mocking and verification](MockingAndVerification.md), [Headers and traffic shaping](HeadersAndTrafficShaping.md), and
[Cookies, priority, logging, and listeners](MartianCompletion.md), and
[Proxy upgrades](ProxyUpgrades.md).

| Registered type | Jovian | Compatibility gap |
|---|---|---|
| `body.Modifier` | Partial | Canonical base64 and native UTF-8 replacements support streaming originals, HEAD metadata, and single/suffix/open/multipart ranges. Strict range validation and a 16-range cap differ from pinned Go behavior. |
| `cookie.Filter` | Partial | Canonical scoped true/else rules match request Cookie and response Set-Cookie names/values. Full Go cookie parsing parity is not claimed. |
| `cookie.Modifier` | Partial | Canonical append and path/domain/RFC3339 expiry/Secure/HttpOnly/MaxAge attributes work with unit/wire coverage. Invalid values are rejected rather than silently sanitized/dropped as in Go. Native set/remove remains distinct. |
| `failure.Verifier` | Implemented | Canonical request-scoped node records an error whenever reached, without changing the HTTP response; wire-tested with resettable bounded retention. |
| `fifo.Group` | Implemented | Canonical ordered scoped composition supports fail-fast or ordered request/response error aggregation. Jovian returns 502 for modifier errors; exact error formatting differs. |
| `header.Append` | Partial | Canonical scoped append preserves duplicates/order with unit/wire coverage; Host/Content-Length/Transfer-Encoding use Martian field semantics; wire framing remains transport-owned. |
| `header.Blacklist` | Partial | Canonical scoped names delete all case-insensitive values with unit/wire coverage; Host/Content-Length/Transfer-Encoding use Martian field semantics; wire framing remains transport-owned. |
| `header.Copy` | Partial | Canonical scoped from/to uses the first source value and copies missing sources as empty; unit/wire coverage. Host/Content-Length/Transfer-Encoding use Martian field semantics; wire framing remains transport-owned. |
| `header.Filter` | Partial | Canonical scoped true/else matching checks duplicate header values. Omitted value matches an empty value as in the pinned source; special-field presence/value matching includes zero-length semantics. |
| `header.Id` | Implemented | Canonical request-only ID uses the exchange UUID and preserves nonempty caller IDs. Native response echo correlates request/response/HAR; keep-alive and wire coverage. |
| `header.Modifier` | Partial | Canonical and native scoped replacement work; Host and length/encoding field semantics work; outgoing framing is normalized to actual bodies. |
| `header.RegexFilter` | Partial | Canonical header/regex fields and request-header matching on response work. ICU with a time budget replaces RE2; matching considers all duplicate values. Native match supports else. |
| `header.Verifier` | Partial | Canonical composable request/response verifier supports presence and duplicate exact values. Special fields use Martian presence semantics; error text differs and legacy host rules remain available. |
| `log.Logger` | Partial | Canonical scope, headersOnly, decode, filters, and bounded/redacted buffered-body snapshots work. Streaming payload snapshots are deferred and bounded; exact Go dump/error semantics differ. |
| `method.Filter` | Partial | Canonical one-method, case-insensitive, scoped true/else matching exists alongside native multi-method rules; wire-level Martian parity coverage remains limited. |
| `method.Verifier` | Implemented | Canonical request-scoped, case-sensitive method expectation records failures without blocking; wire-tested. |
| `noop.Modifier` | Implemented | Canonical scoped no-op preserves ordinary forwarding with unit/wire coverage. |
| `pingback.Verifier` | Implemented | Canonical nonempty URL fields match exactly. Pending before traffic, sticky success, reset re-arms, and unreached nested nodes remain pending; unit/wire coverage. |
| `port.Filter` | Partial | Canonical effective-port matching includes implicit 80/443 and IPv6; native match also supports else. Integration parity coverage remains limited. |
| `port.Modifier` | Implemented | Canonical set/default/remove modes update URL and Host, with IPv6 and real forwarding coverage. Invalid/conflicting modes are rejected. |
| `priority.Group` | Implemented | Canonical numeric priorities sort descending; later declarations win ties, in both directions, with scoped children. Unit/wire coverage. |
| `querystring.Filter` | Implemented | Canonical scoped true/else checks exact decoded names and any repeated value; omitted/empty value tests presence. |
| `querystring.Modifier` | Partial | Canonical set-value and native set/remove work; raw encoding parity is not fully verified. |
| `querystring.Verifier` | Partial | Canonical presence/any-value matching handles query plus buffered URL-encoded POST/PUT/PATCH forms and plus decoding. Streaming forms record an unavailable-body failure; exact Go form/error parity is not claimed. |
| `skip.RoundTrip` | Implemented | Canonical request-scoped flag skips the origin and supplies an empty 200 for response modifiers. Wire checks cover body/status composition and unread-upload closure. |
| `stash.Modifier` | Implemented | Canonical headerName snapshots current request URL and echoes that request header on response. Response-only scope is rejected. Valid header names are required. Unit/wire coverage. |
| `static.Modifier` | Partial | Canonical rooted regular files bypass origin contact. HEAD and single/multipart ranges work; files over 4 MiB use bounded descriptor reads. Traversal/symlinks are rejected. No directory listing or conditional caching. |
| `status.Modifier` | Partial | Canonical statusCode and native status replacement exist; full reason-phrase parity is not claimed. |
| `status.Verifier` | Partial | Canonical composable response status verification has unit/wire coverage; diagnostics are bounded/redacted and differ from Martian. Legacy host rules remain available. |
| `url.Filter` | Partial | Canonical scheme/authority/exact-path/raw-query true/else rules exist. Host matching is case-insensitive and supports whole-label wildcards rather than all Martian wildcard forms. |
| `url.Modifier` | Partial | Canonical nonempty scheme/authority/path/raw-query rewriting routes before DNS. Session scope is rechecked, and unchanged origin credentials are stripped on origin changes. |
| `url.RegexFilter` | Partial | Canonical scoped URL regex with true/else exists; Foundation/ICU and a 50 ms per-value budget replace Go RE2. |
| `url.Verifier` | Partial | Canonical request verifier checks nonempty scheme/authority/decoded-path/raw-query fields. Host wildcard behavior follows Jovian URL filters rather than every Martian wildcard form. |

## Programmatic packages outside the JSON registry

The Martian source also includes library-level behavior not represented by the
33 registered JSON names. Important compatibility areas include `auth`, `cors`,
`h2`, `har`, `httpspec`, `ipauth`, `marbl`, `messageview`, `mitm`, `proxyauth`,
`servemux`, `trafficshape`, and request `Context` state. These must be audited
separately; their presence in Martian does not imply they are enabled by the
stock proxy binary.

## Remaining compatibility work

The canonical registry and control-plane consolidation are implemented with the
limits above. Remaining work includes exact Go/RE2 matching and encoding
semantics, full HAR/text-log equivalence, conditional static-file caching, and
explicit decisions about HTTP/2, MARBL, mobile, and library-only APIs. Parsing
all 33 names does not imply full Martian parity.

## Acceptance rule

A row moves to **Implemented** only when Jovian accepts a Martian-format fixture
for that capability and an integration test proves the externally visible
behavior. Jovian-only features may remain, but they do not advance this matrix.
