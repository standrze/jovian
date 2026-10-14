# jovian

A standalone Swift HTTP proxy library and command-line application modeled after
[Google Martian](https://github.com/google/martian).

- `Jovian` owns proxy behavior, traffic records, and explicit X.509 inspection.
- `jovian` provides an Apple ArgumentParser command-line interface.
- SwiftNIO owns socket transport and HTTP framing; NIOSSL owns TLS; maintained Apple packages
  provide logging, collections, cryptography, and certificate parsing.
- Apple's Compression framework decodes diagnostic gzip/deflate bodies, with bounded output
  and gzip/zlib framing and checksum validation. There is no direct zlib library dependency.

The consolidated 0.3.0 version includes all 33 canonical Martian rule names,
HTTP/HTTPS/SOCKS5 upstream proxies, URL and port rewriting, local static mocks
and ranges, verifiers, traffic shaping, streaming diagnostics, optional redacted
HAR bodies, dynamic TLS interception, and origin-scoped sessions. See the
[compatibility matrix](Documentation/martian-compatibility.md) for deliberate limits.

Requires Swift 6.4 and macOS 13 or later. The package has no runtime dependency
on ono-sendai or lowlight.

Clone and build:

```sh
git clone https://github.com/standrze/jovian.git
cd jovian
swift build
swift run jovian serve
swift run jovian certificate /path/to/certificate.pem
swift run jovian ca create --directory /tmp/jovian-ca
swift run jovian serve --intercept-ca /tmp/jovian-ca --upstream-proxy socks5h://127.0.0.1:1080
swift test
```

See [proxy usage](Documentation/proxy.md),
[networking](Documentation/networking.md),
[certificate inspection](Documentation/certificates.md),
[proxy engine comparison](Documentation/ProxyEngineParity.md),
[Martian API compatibility](Documentation/martian-compatibility.md), and
[project history](Documentation/provenance.md).

Development checks are in [CONTRIBUTING.md](CONTRIBUTING.md); code conventions
are in [the Swift style guide](Documentation/SwiftProjectStyle.md).
