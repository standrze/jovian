# working in jovian

Read [Documentation/SwiftProjectStyle.md](Documentation/SwiftProjectStyle.md)
before adding or reorganizing Swift code. Formatting is defined by `.swift-format`
and `.editorconfig`.

This is a standalone Swift package. Keep its dependency direction explicit:

```text
JovianCLI → Jovian
JovianCLI → ArgumentParser
Jovian → Apple networking, logging, collections, crypto, and X.509 packages
```

The library must not import the executable, ono-sendai, or lowlight. Use
`swift-argument-parser` for launch arguments, SwiftNIO for transport and HTTP
framing, and `swift-certificates` for explicit X.509 work. Certificates and
cryptographic primitives are not a TLS transport. Prefer maintained Apple
packages over bespoke implementations of standard functionality.

Run `scripts/check-format.sh` and `swift test` after Swift changes. Keep protocol
and networking checks local and deterministic. Do not run simultaneous SwiftPM
builds in this package's build directory. Report untested platforms explicitly.
