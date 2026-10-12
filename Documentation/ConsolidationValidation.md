# Jovian 0.3.0 consolidation validation

This revision combines published Jovian `680422e` with the newer local Relay/Reed
working tree, retaining SwiftNIO/NIOSSL transport and native certificate handling.
See [provenance](provenance.md) and the [compatibility matrix](martian-compatibility.md).

Validated on macOS arm64 with Swift 6.4:

- Strict Swift formatter lint and `git diff --check`.
- Full SwiftPM suite: 121 library tests and 10 CLI tests, zero failures.
- `swift build --product jovian` and root, serve, CA, and sessions CLI help.
- Original `scripts/smoke.py` proxy/admin/HAR fixture.
- 124 wire checks: routing 15, mocking/verifiers 13, completion 23,
  headers/shaping 14, proxy upgrades 18, and HTTPS/SOCKS next hops 41.
- Live checks use explicit temporary CA trust and example.com. No system trust
  store was modified. HTTP, HTTPS, SOCKS5, and SOCKS5h chains cover validated
  origin TLS, interception, URL rewrites, authentication, and failure isolation.

The merged wire fixtures retain intentional NIO/Jovian behavior: standard
reason phrases may be normalized; malformed messages may be closed by NIO
before an error response; upstream HTTP CONNECT rejection statuses and bodies
are preserved; session-scope violations return 403; response Via headers remain
present. Assertions were updated for those contracts while preserving payload,
framing, scope, and no-origin-contact checks.

Integration issues fixed during consolidation include cross-origin credential
stripping, protected Via history, streaming request HAR prefixes, bodyless 205
framing, response configuration snapshots, shared opaque-tunnel pacing,
connection-scoped latency, actual byte counts for forced closes, and bounded
TLS close-handshake waits on client and server contexts.

This validation does not establish complete Martian semantic parity, Linux
support, HTTP/2 support, or compatibility with an external application adapter.
