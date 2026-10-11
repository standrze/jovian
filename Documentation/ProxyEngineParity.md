# Proxy engine comparison with Google Martian

This comparison covers forwarding, connection handling, TLS, and lifecycle behavior.
It does not claim compatibility with every Martian modifier, JSON document, or
administration endpoint. The reference is Martian v3 commit
[`0f7e6797a04da412118541344bbe0d65945e24c9`](https://github.com/google/martian/tree/0f7e6797a04da412118541344bbe0d65945e24c9),
reviewed from its source on 2026-10-03.

The primary references are
[`proxy.go`](https://github.com/google/martian/blob/0f7e6797a04da412118541344bbe0d65945e24c9/proxy.go),
[`cmd/proxy/main.go`](https://github.com/google/martian/blob/0f7e6797a04da412118541344bbe0d65945e24c9/cmd/proxy/main.go),
[`mitm`](https://github.com/google/martian/tree/0f7e6797a04da412118541344bbe0d65945e24c9/mitm), and
[`header/via_modifier.go`](https://github.com/google/martian/blob/0f7e6797a04da412118541344bbe0d65945e24c9/header/via_modifier.go).
Jovian independently implements these capabilities with SwiftNIO, NIOSSL, and
Swift Certificates.

## Features and regression coverage

The test names below identify executable coverage, not a promise that every
upstream edge case or platform has been exercised. Record test execution and
platform results separately when validating a release.

| Engine capability | Jovian implementation and coverage |
|---|---|
| HTTP/1.1 forwarding and framing | SwiftNIO handles framing, persistent clients, and bounded pipelining. `JovianNetworkingTests.testNIOFramingPreservesFragmentedChunkedBodyTrailersAndPipelining` covers fragmented messages and trailers. |
| Upstream connection reuse | Fully consumed responses may return their connection to the origin pool. `JovianLoopbackTests.testPoolReusesFullyConsumedUpstreamAcrossDownstreamConnections` covers reuse. |
| Opaque CONNECT tunnels | Bidirectional bytes retain data coalesced with the handshake and support independent half-closes. `JovianLoopbackTests.testConnectRetainsCoalescedOpaqueBytesBeforeClientHalfClose` covers this path. |
| Modifier errors and upstream failures | Thrown request/response modifier errors append Warning fields while retaining earlier mutations and forwarding. Upstream HTTP dial failures run response modifiers. `ProxyFeatureTests.testThrowingModifiersPreserveChangesAndAppendWarningsWhileForwarding` and `testHTTPDialFailureRunsResponseModifiers` cover these paths. |
| CONNECT modification | Request modifiers run before dialing; response modifiers run for established tunnels, synthetic rejection, and dial failures. `ProxyFeatureTests.testConnectAppliesTargetAndResponseModifiers`, `testConnectSyntheticRejectionRunsResponseModifiersBeforeAnyDial`, and `testConnectDialFailureRunsTheResponseModifier` cover those decisions. |
| HTTP upgrades | A successful upgrade transitions to opaque transport and preserves early bytes. `JovianLoopbackTests.testUpgradePreservesBothDirectionsAndCoalescedUpstreamBytes` covers a local upgrade protocol. |
| HTTP downstream proxy | Plain HTTP uses absolute-form targets; CONNECT establishes tunnels through the next proxy. `ProxyFeatureTests.testDownstreamProxyReceivesAbsoluteTargetAndItsOwnCredentials` and `testChainedConnectPreservesEarlyBytesAndBothHalfCloses` cover both paths. |
| Proxy credential separation | Next-hop URL credentials are supplied to that proxy and consumed before reaching the origin. `ProxyFeatureTests.testProxyChainConsumesProxyCredentialsBeforeTheOrigin` covers a chain of two default-configured instances. |
| TLS interception and direct HTTPS | Explicitly configured authorities issue cached DNS/IP identities. Decrypted HTTP runs through normal modifiers. `ProxyTLSIntegrationTests.testConnectInterceptionUsesProxyAuthorityAndMutatesDecryptedHTTP` and `testAbsoluteHTTPSUsesExplicitTrustAndRunsModifiers` cover real loopback TLS peers. |
| Plain HTTP inside intercepted CONNECT | Protocol detection retains the first bytes and re-enters HTTP processing. `ProxyTLSIntegrationTests.testInterceptionRetainsPlaintextRequestCoalescedWithConnect` covers this transition. |
| Direct TLS listener and HTTPS next hop | A configured server context encrypts the listener; HTTPS chaining can nest origin TLS inside proxy TLS. `ProxyTLSIntegrationTests.testDirectTLSListenerForwardsOriginFormAsHTTPS` and `testHTTPSDownstreamProxyAndOriginBothVerifyIPSubjectAlternativeNames` cover these paths. |
| Trust and hostname validation | Upstream TLS validates peers by default; custom roots and verification disabling are explicit options. `ProxyTLSIntegrationTests.testUntrustedAuthorityAndWrongIPIdentityAreRejected` and `CertificateAuthorityTests.tlsHandshakeValidatesTrustAndRequestedDNSOrIPAddress` cover trust and identity checks. |
| Request deadlines | The default request deadline is 300 seconds; the default connect timeout is 30 seconds, matching Martian's numeric defaults. `ProxyFeatureTests.testRequestTimeoutClosesAnExchangeWaitingForOriginHeaders` checks stalled-origin cleanup. |
| Via loop detection | Each instance uses a distinct identity so ordinary chains do not collide. A request returning to the same instance receives 400. `ProxyFeatureTests.testViaLoopIsRejectedBeforeOriginDial` and the two-instance credential test cover rejection and valid chaining. |
| Graceful draining | `shutdown(gracePeriod:)` stops admission, lets active exchanges finish, and closes remaining work at expiry. `ProxyDrainTests.testGracefulShutdownFinishesCurrentResponseAndRejectsPipelinedRequest`, `testGraceDeadlineClosesAnActiveTunnel`, and `testImmediateStopInterruptsAnExistingGracefulDrain` cover lifecycle behavior. |

Tests live under [Tests/JovianTests](../Tests/JovianTests/). Certificate issuance,
cache bounds, authority loading, and concurrent issuance have additional coverage
in [CertificateAuthorityTests.swift](../Tests/JovianTests/CertificateAuthorityTests.swift).

## Boundaries and differences

- HTTP/1.1 is the supported application protocol. TLS advertises HTTP/1.1;
  Martian's optional HTTP/2 interception package is outside this implementation.
- Bodies larger than the configured buffer limit stream without body access for
  modifiers. The default limit is 4 MiB. This bounded-memory contract differs
  from Martian's Go request/response body interfaces.
- TLS interception requires an explicit authority. Generating, loading, or exporting
  one does not install trust on the machine. Dynamic listener contexts select
  certificates from ClientHello SNI and use a configured fallback without SNI.
- A request deadline bounds network work and cancellable pacing. Synchronous custom
  modifiers or interceptors must implement their own termination behavior; cancelling
  a Swift task cannot interrupt arbitrary blocking callback code. System DNS
  resolution may also remain pending until the connect timeout. Pending TCP
  channel registration is source-reviewed; the stalled TLS-handshake cancellation
  path has a deterministic loopback test.
- `stop()` and parameterless `shutdown()` close immediately. Call
  `shutdown(gracePeriod:)` for draining. Unlike Martian's unbounded `Close()` wait,
  Jovian lets the application choose a finite grace period.
- Programmatic APIs are native Swift contracts. Martian's custom Go
  `RoundTripper`/dial injection, `Context` storage, and session hijacking API are
  not source-compatible equivalents. Synthetic responses and `RequestInterceptor`
  cover selected request-routing decisions.
- Modifier failures retain prior mutations and append Warning headers before
  continuing the exchange. A thrown error stops the current ordered group;
  aggregate-error groups and Martian Context error storage remain separate API work.
  `RuntimeConfiguration` continues to suppress errors from its compiled snapshot.
- Full Martian JSON registration, reserved `martian.proxy` control routing, HAR
  fidelity, verifier composition, MARBL, and traffic-shaping rules remain separate
  compatibility work. See [martian-compatibility.md](martian-compatibility.md).

Run `scripts/check-format.sh`, `swift test`, and `swift build --product jovian`
from the package root, sequentially. The local integration tests do not establish
Linux support, HTTP/2 support, or interoperability with every proxy product.
