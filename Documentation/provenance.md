# provenance

## relay import

This project began under the name `Reed`, as a copy of relay's recorded `main` revision
`9e974b4f441dc5913774a150dea6c03c2e7444d5`. The original import record states that
uncommitted rename changes and other branches were not copied. The copy was
renamed independently and placed in ono-sendai's former `Sources/Reed/`,
`Sources/ReedCLI/`, and `Tests/ReedTests/` directories. Those are historical
paths. The original relay checkout remains in place; the recorded commit is
dated 2026-09-03 and titled `Initial Relay CLI and core project`.

## standalone swift-jovian

The project is now the independent `swift-jovian` Swift package. Its library
product/module is `Jovian`; its executable is `jovian`. Sources live in
`Sources/Jovian/` and `Sources/JovianCLI/`, with their corresponding test targets
under `Tests/`. These paths are relative to this package directory.

The package was extracted from the ono-sendai development tree. The optional
`jovian-plugin` adapter can embed Jovian in ono-sendai; the standalone package
has no dependency on that host or lowlight. Jovian itself does not read workspace
configuration or enforce `scope.md`.

The transport and HTTP framing now use SwiftNIO. Explicit local certificate
inspection uses Apple's `X509`, `SwiftASN1`, and `Crypto` products. HTTPS
`CONNECT` remains opaque by default. Explicitly configured interception uses
NIOSSL for TLS and Swift Certificates for authority/leaf issuance. The separate
certificate inspection command does not evaluate trust. See [networking](networking.md),
[proxy usage](proxy.md), and [certificate inspection](certificates.md).

## TLS implementation

TLS transport now uses Apple's maintained SwiftNIO SSL package. Certificate
issuance and explicit trust policy are independent of the metadata inspection
command. The implementation keeps cryptographic primitives and TLS handshakes in
maintained packages rather than implementing them in application code.

## Consolidation, 2026-10-11

Jovian 0.3.0 consolidates the published Jovian main revision
`680422e76e5f56e858a5a70e65e00c9c37ff15fa` with the newer local Relay/Reed
working tree based on `9e974b4f441dc5913774a150dea6c03c2e7444d5`.
The latter included uncommitted development beyond the initial import;
commit dates alone therefore did not identify the newest features.

The consolidation retains Jovian's SwiftNIO transport, request deadlines,
connection pool, bounded drain, Swift Certificates authority, certificate
inspection, ArgumentParser CLI, and original regression suite. It ports the
newer canonical rule registry, conditional routing, verifiers, static files and
ranges, bounded streaming diagnostics, HAR capture policy, traffic shaping,
shared control routes, SOCKS negotiation, and origin-scoped sessions into that
engine. The custom Reed socket/OpenSSL transport is not part of this package.
The sole C boundary is the system zlib module for bounded diagnostic inflation.

Jovian is the canonical library, executable, and repository name. Historical
`REED_SESSIONS_DIR` / `RELAY_SESSIONS_DIR` and existing session directories remain
readable; new stores use `JOVIAN_SESSIONS_DIR` or `~/.jovian/sessions`.
