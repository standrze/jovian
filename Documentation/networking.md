# jovian networking

The HTTP proxy and control API use Apple SwiftNIO's `NIOPosix` channels and
`NIOHTTP1` codecs. A bounded CONNECT handoff gate separates response headers
from early tunnel bytes before passing the headers to NIO. It retains at most
64 KiB of headers and 1 MiB of early tunnel data. NIO owns HTTP field parsing
and chunk decoding. The production target has no custom socket implementation.
Its `HTTPHead` type is modifier data;
NIO request and response heads are converted at the application boundary.

## ownership and limits

- Each server owns two NIO event-loop threads and four worker-pool threads.
  Client connections run asynchronous transfer tasks. Synchronous modifiers,
  interception callbacks, HAR/JSONL file writes, and admin JSON work run on the
  worker pool, never on NIO event loops. Custom callbacks must eventually return;
  stopping calls the interceptor's existing cancellation hook.
- Asynchronous shutdown cancels transfer tasks, closes their channels, and waits
  for task cleanup before shutting down workers and event loops. It also cancels
  pool-expiry timers, waits for upstream channels to close, and waits for any
  concurrent bind to finish. This wakes transfers paused by rate limits.
- Automatic socket reads are disabled. A single consumer requests each decoded
  part; a socket read is at most 16 KiB, and an inbox rejects more than 256 queued
  parts from an excessive pipelined batch. HTTP header fields and their combined
  list are limited to 64 KiB by NIO's decoder configuration.
- Writes await NIO completion before the next chunk. Traffic pacing suspends the
  transfer task using `ContinuousClock`; it does not sleep on event-loop threads.
  Pacing applies to payload bytes, not HTTP header or chunk-framing overhead.
  Runtime traffic-shape defaults share budgets across transfers; URL actions use
  decoded response offsets. Opaque tunnels use only the shared defaults.
- Body inspection receives complete bodies up to the configured cap (4 MiB by
  default). Larger bodies stream with `body == nil`; explicit body replacement still works; collecting an unknown-sized
  body can temporarily retain the cap plus one 16 KiB read. Chunked responses
  stream immediately so long-running responses are not held until completion.
- Traffic-entry body snapshots stay capped. JSON Lines can include those
  snapshots; HAR serialization omits bodies by default; `--har-bodies` enables bounded, field-redacted retention. Opaque tunnels retain metadata and
  byte counts. Explicit TLS interception decodes HTTP into the same bounded pipeline.
- Admin bodies are limited to 1 MiB, requiring Content-Length and rejecting chunked input. The admin
  listener remains loopback by default; no new authentication policy was added.

## connections and protocol handoff

Only upstream responses consumed through NIO's end-of-message event can return
an HTTP channel to the per-origin pool. The pool keeps at most four idle channels
per origin, closes expired channels after 30 seconds even if that origin is never
used again, and tracks leased channels for shutdown. A failed exchange is not
retried automatically. Connect attempts default to 30 seconds; the configurable
request deadline defaults to 300 seconds and includes socket work and pacing.
System DNS resolution may remain pending until the connect timeout; a grace period
cannot interrupt a synchronous resolver or custom callback. Connecting channels
are registered before dialing, so socket shutdown covers pending connects.
Deadline completion is synchronized before a channel returns to the pool.

CONNECT and accepted HTTP 101 upgrades remove NIO's HTTP codecs after the
handshake is written. A small event handler delays a peer's half-close while
NIO forwards decoder-held upgrade bytes, preserving payload coalesced with the
handshake. Each tunnel direction can finish independently. Transfer errors close
both peers before waiting for the other transfer task, since cancellation alone
does not cancel an outstanding NIO future.

A rejected Upgrade request receives the ordinary final response and closes the
downstream connection; that HTTP decoder has already stopped at the requested
protocol boundary. Ordinary HTTP/1.1 requests retain downstream keep-alive and
ordered pipelining. HTTP/1.0 streaming responses without a known content length
close to delimit the response.

NIO owns wire framing and validates input. Chunk extensions are decoded rather
than reproduced byte for byte. Trailers survive forwarding when the body is
unchanged; replacing a buffered body drops its old trailers. Final HEAD/204/304
responses suppress body bytes, including when a modifier changes the status.
Response encoding uses NIO's public explicit-framing configuration so CONNECT
has no invented chunk terminator. Absolute HTTPS URLs use NIOSSL with verified
upstream TLS. HTTP and HTTPS routes occupy distinct pool entries; optional
next-hop proxies use CONNECT before origin TLS.

## TLS and forwarding policy

NIOSSL owns encryption and trust-chain verification. TLS defaults to 1.2 or newer
and advertises HTTP/1.1. Custom roots replace system roots only when explicitly
configured. IP SAN verification checks the intended origin even when its socket
peer is a chained proxy; the additional-verification hook is isolated in
`TLSConfiguration.swift` because NIOSSL currently exposes it as a public underscored API.

Certificate authorities use Swift Certificates and Crypto for signing. Generated
or loaded authorities never change system trust. A bounded, locked certificate
cache is shared across connections. ClientHello SNI selects listener certificates;
a private serial queue performs issuance outside the NIO event loop. The fallback
hostname handles TLS clients without SNI. CONNECT can re-enter TLS or plaintext
HTTP handling without discarding bytes coalesced with its handshake.

Request/response modifiers apply to CONNECT handshakes as well as HTTP exchanges.
Thrown modifier errors append Warning headers and retain earlier changes. Proxy
credentials are consumed before origin forwarding; separate next-hop credentials
are added only at that transport boundary. Via identities are unique per instance.

## API migration

`ProxyServer`'s initializer and `start()`, `run()`, and `stop()` remain available.
`AdminServer.start()` now also returns a bound port for embedded use. Starts and
blocking `run()` are application-thread boundaries, not event-loop APIs. Stop
initiates asynchronous resource shutdown. Embedded callers should use
`await proxy.shutdown()` to wait for listener, connection, worker, and event-loop
teardown before deactivating the feature or exiting. Concurrent shutdown calls
join the same teardown, including one initiated earlier by `stop()`. Shutdown
cancels in-flight requests. `shutdown(gracePeriod:)` instead stops admission and
lets active exchanges finish until the grace period expires, then cancels remaining
work. A stopped server cannot be restarted. Interceptors must unblock pending work and
prevent new waits when `cancelPending()` is called.

`HTTPHead.parse(Data)` and `HTTPHead.encoded()` were removed. They were public
bespoke wire helpers used only by this repository's former parser tests; code
that needs a wire codec should use `NIOHTTP1` instead. Header lookup/mutation and
request/response modifier contexts remain available. The standalone package is
`swift-jovian`, the library product/module is `Jovian`, and the executable is
`jovian`. Consumers of the former Reed module must update their import and
package dependency. See [provenance](provenance.md) for the project history.

## verification

The test suite includes real loopback fixtures for ordinary forwarding, traffic
body snapshots, HAR metadata, request replacement/drop, pooled upstream reuse,
CONNECT, 101 upgrades, coalesced opaque bytes with immediate half-close, trailers,
modified 204 responses, pending-interception cancellation, concurrent shutdown,
closed pooled upstreams, and listener reuse after shutdown. NIO's async embedded channels cover fragmented chunked input,
pipelined boundaries, ambiguous or malformed framing, and bodyless CONNECT
encoding. Raw socket code exists only in test fixtures, as an independent peer.

The migration has been exercised on macOS. Platform imports and the retained
test peer have Darwin/Glibc branches, but Linux support is not claimed without
running these checks on Linux. No live third-party targets are used.

## Consolidated trust and shutdown

SOCKS5 negotiation uses the same NIO channel and deadline as HTTP/HTTPS next
hops. Both SOCKS URL spellings resolve hostnames remotely. Separate next-hop
credentials and optional PEM/DER roots stay out of origin requests and logs.
`--upstream-proxy-ca` overrides only next-hop trust; the legacy upstream TLS
policy remains the fallback when that option is absent.

TLS close-notify waits are bounded to 100 milliseconds in client and server
contexts, including dynamically issued listener identities. Application data
still follows the normal request drain; this bound applies to TLS teardown
when a peer does not complete its close handshake.
