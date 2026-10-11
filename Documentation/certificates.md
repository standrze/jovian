# certificate inspection

Jovian uses Apple's [Swift Certificates](https://github.com/apple/swift-certificates)
(`X509`) and [Swift ASN.1](https://github.com/apple/swift-asn1) to inspect local
certificate files. [Swift Crypto](https://github.com/apple/swift-crypto) supplies
the SHA-256 fingerprint implementation.

Run from the `swift-jovian/` package directory:

```sh
swift run jovian certificate /path/to/certificate.pem
swift run jovian certificate /path/to/certificate.der
```

The ArgumentParser command accepts a regular file containing a DER certificate
or a PEM bundle of certificates, up to 1 MiB. It prints a JSON array in file
order, containing subject, issuer, serial number, version, public-key type,
signature algorithm, validity dates, inspection time, alternative names,
critical extension identifiers, and the SHA-256 fingerprint of each original
DER certificate. Mixed certificate/private-key bundles are rejected. The CLI
uses JSON escaping for certificate-controlled strings.

The library API is `CertificateInspection.inspect(_:at:)`. Supplying a date
makes validity checks deterministic. Date bounds are inclusive; the result says
`within validity period`, `not yet valid`, or `expired`. Every result explicitly
reports `trust: "not evaluated"`: a date check does not establish trusted identity.
Bundle order is preserved without claiming that the certificates form a valid
chain. Signature checks, hostname matching, revocation, and trust evaluation are
outside this inspection command.

## tls boundary

X.509 describes certificates; it does not implement the TLS handshake or decrypt
application traffic. Jovian's default CONNECT path forwards opaque bytes. A TLS 1.3
connection also encrypts its certificate exchange, so a tunnel cannot simply
parse those bytes as a certificate. This command reads an explicit local file;
it does not install trust roots, create identities, or start a proxy listener.

The package needs no OpenSSL command or separate OpenSSL installation. Apple
Swift Crypto includes a vendored BoringSSL implementation for some supported
operations, and X509 uses its extras. Adopting Apple packages does not make all
transitive implementation code Swift.

## Proxy authorities

The separate `CertificateAuthority` API generates or loads a signing authority for
explicit proxy interception. NIOSSL performs TLS handshakes and validates upstream
peers; the inspection command still reports metadata only. See [proxy usage](proxy.md)
for authority selection, public certificate export, and trust options.
