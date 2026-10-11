import Crypto
import DequeModule
import Dispatch
import Foundation
import NIOCore
import NIOSSL
import SwiftASN1
import X509

/// A local certificate authority that issues short-lived server identities for configured proxy interception.
///
/// Creation and export do not modify any operating-system trust store. The signing identity is immutable;
/// a lock protects certificate issuance and a bounded FIFO cache shared by all proxy event loops.
public final class CertificateAuthority: @unchecked Sendable {
    public let certificateDER: Data
    public let certificatePEM: Data
    /// Sensitive unencrypted PEM.
    ///
    /// Callers own secure persistence and filesystem permissions.
    public let privateKeyPEM: Data
    public let leafValiditySeconds: TimeInterval
    public let organization: String
    public let cacheCapacity: Int

    private let certificate: Certificate
    private let privateKey: Certificate.PrivateKey
    private let signatureAlgorithm: Certificate.SignatureAlgorithm
    private let lock = NSLock()
    private let signingQueue = DispatchQueue(label: "jovian.certificate-authority")
    private var cache: [String: ServerIdentity] = [:]
    private var insertionOrder = Deque<String>()

    /// Generates a P-256 authority in memory.
    ///
    /// Validity intervals are measured in seconds.
    public static func generate(
        commonName: String = "Jovian Local Proxy CA", organization: String = "Jovian Proxy",
        validitySeconds: TimeInterval = 31_536_000, leafValiditySeconds: TimeInterval = 86_400,
        cacheCapacity: Int = 256
    ) throws -> CertificateAuthority {
        try validateInterval(validitySeconds)
        let key = P256.Signing.PrivateKey()
        let publicKey = Certificate.PublicKey(key.publicKey)
        let name = try DistinguishedName {
            CommonName(commonName)
            OrganizationName(organization)
        }
        let now = Date()
        let certificate = try Certificate(
            version: .v3, serialNumber: .init(), publicKey: publicKey,
            notValidBefore: now.addingTimeInterval(-300), notValidAfter: now.addingTimeInterval(validitySeconds),
            issuer: name, subject: name, signatureAlgorithm: .ecdsaWithSHA256,
            extensions: Certificate.Extensions {
                Critical(BasicConstraints.isCertificateAuthority(maxPathLength: 0))
                Critical(KeyUsage(keyCertSign: true, cRLSign: true))
                SubjectKeyIdentifier(hash: publicKey)
            }, issuerPrivateKey: .init(key))
        return try CertificateAuthority(
            certificatePEM: Data(certificate.serializeAsPEM().pemString.utf8),
            privateKeyPEM: Data(key.pemRepresentation.utf8), leafValiditySeconds: leafValiditySeconds,
            organization: organization, cacheCapacity: cacheCapacity)
    }

    /// Loads one PEM authority and its matching unencrypted RSA, EC, or Ed25519 private key.
    public init(
        certificatePEM: Data, privateKeyPEM: Data, leafValiditySeconds: TimeInterval = 86_400,
        organization: String = "Jovian Proxy", cacheCapacity: Int = 256
    ) throws {
        try Self.validateInterval(leafValiditySeconds)
        guard cacheCapacity > 0 else { throw ProxyTLSError.invalidCacheCapacity }
        guard let certificateText = String(data: certificatePEM, encoding: .utf8),
            let keyText = String(data: privateKeyPEM, encoding: .utf8)
        else { throw ProxyTLSError.invalidAuthority }
        let documents = try PEMDocument.parseMultiple(pemString: certificateText)
        guard documents.count == 1, documents[0].discriminator == Certificate.defaultPEMDiscriminator else {
            throw ProxyTLSError.invalidAuthority
        }
        let certificate = try Certificate(derEncoded: documents[0].derBytes)
        let key = try Certificate.PrivateKey(pemEncoded: keyText)
        guard certificate.publicKey == key.publicKey else { throw ProxyTLSError.mismatchedPrivateKey }
        guard case .isCertificateAuthority = try certificate.extensions.basicConstraints,
            try certificate.extensions.keyUsage?.keyCertSign != false,
            certificate.notValidBefore <= Date(), certificate.notValidAfter > Date()
        else { throw ProxyTLSError.invalidAuthority }
        self.certificate = certificate
        privateKey = key
        self.certificateDER = Data(documents[0].derBytes)
        self.certificatePEM = certificatePEM
        self.privateKeyPEM = privateKeyPEM
        self.leafValiditySeconds = leafValiditySeconds
        self.organization = organization
        self.cacheCapacity = cacheCapacity
        if P256.Signing.PublicKey(key.publicKey) != nil {
            signatureAlgorithm = .ecdsaWithSHA256
        } else if P384.Signing.PublicKey(key.publicKey) != nil {
            signatureAlgorithm = .ecdsaWithSHA384
        } else if P521.Signing.PublicKey(key.publicKey) != nil {
            signatureAlgorithm = .ecdsaWithSHA512
        } else if Curve25519.Signing.PublicKey(key.publicKey) != nil {
            signatureAlgorithm = .ed25519
        } else {
            signatureAlgorithm = .sha256WithRSAEncryption
        }
    }

    /// Returns an immutable TLS server context for one DNS hostname or IP address.
    ///
    /// Expired cached leaves are reissued, and their validity never exceeds the authority's validity.
    public func serverContext(for hostname: String) throws -> NIOSSLContext {
        try identity(for: hostname).context
    }

    /// Creates a TLS listener that selects a certificate from ClientHello SNI.
    ///
    /// Clients without SNI use the supplied fallback hostname. Issuance runs on a private serial queue.
    public func listenerContext(defaultHostname: String = "localhost") throws -> NIOSSLContext {
        let fallback = try Self.normalizedHostname(defaultHostname)
        var configuration = try serverContext(for: fallback).configuration
        configuration.sslContextCallback = { [self] hello, promise in
            signingQueue.async {
                do {
                    let identity = try self.identity(for: hello.serverHostname ?? fallback)
                    var changes = NIOSSLContextConfigurationOverride()
                    changes.certificateChain = identity.context.configuration.certificateChain
                    changes.privateKey = identity.context.configuration.privateKey
                    promise.succeed(changes)
                } catch {
                    promise.fail(error)
                }
            }
        }
        return try NIOSSLContext(configuration: configuration)
    }

    /// Exports the issued leaf followed by this authority, both in PEM format.
    public func certificateChain(for hostname: String) throws -> Data {
        try identity(for: hostname).certificateChainPEM
    }

    private func identity(for hostname: String) throws -> ServerIdentity {
        let host = try Self.normalizedHostname(hostname)
        lock.lock()
        defer { lock.unlock() }
        let now = Date()
        guard certificate.notValidBefore <= now, certificate.notValidAfter > now else {
            throw ProxyTLSError.invalidAuthority
        }
        if let cached = cache[host], cached.expires > now { return cached }
        if cache.removeValue(forKey: host) != nil {
            insertionOrder.removeAll { $0 == host }
        }
        let key = P256.Signing.PrivateKey()
        let publicKey = Certificate.PublicKey(key.publicKey)
        let expires = min(now.addingTimeInterval(leafValiditySeconds), certificate.notValidAfter)
        let name = try DistinguishedName {
            CommonName(host)
            OrganizationName(organization)
        }
        let leaf = try Certificate(
            version: .v3, serialNumber: .init(), publicKey: publicKey,
            notValidBefore: max(now.addingTimeInterval(-300), certificate.notValidBefore), notValidAfter: expires,
            issuer: certificate.subject, subject: name, signatureAlgorithm: signatureAlgorithm,
            extensions: Certificate.Extensions {
                Critical(BasicConstraints.notCertificateAuthority)
                Critical(KeyUsage(digitalSignature: true))
                try ExtendedKeyUsage([.serverAuth])
                SubjectAlternativeNames([Self.alternativeName(host)])
                SubjectKeyIdentifier(hash: publicKey)
                AuthorityKeyIdentifier(keyIdentifier: SubjectKeyIdentifier(hash: certificate.publicKey).keyIdentifier)
            }, issuerPrivateKey: privateKey)
        let chain = Data(try leaf.serializeAsPEM().pemString.utf8) + Data("\n".utf8) + certificatePEM
        let context = try ProxyTLSConfiguration.serverContext(
            certificatePEM: chain, privateKeyPEM: Data(key.pemRepresentation.utf8))
        let identity = ServerIdentity(context: context, certificateChainPEM: chain, expires: expires)
        while cache.count >= cacheCapacity, let oldest = insertionOrder.popFirst() {
            cache.removeValue(forKey: oldest)
        }
        cache[host] = identity
        insertionOrder.append(host)
        return identity
    }

    private static func validateInterval(_ seconds: TimeInterval) throws {
        guard seconds.isFinite, seconds > 0, seconds <= 315_360_000 else { throw ProxyTLSError.invalidValidity }
    }

    private static func normalizedHostname(_ hostname: String) throws -> String {
        var host = hostname.lowercased()
        if host.hasPrefix("["), host.hasSuffix("]") { host = String(host.dropFirst().dropLast()) }
        if host.hasSuffix(".") { host.removeLast() }
        guard !host.isEmpty, !host.contains("%") else { throw ProxyTLSError.invalidHostname }
        if let address = try? SocketAddress(ipAddress: host, port: 0), let canonical = address.ipAddress {
            return canonical
        }
        let labels = host.split(separator: ".", omittingEmptySubsequences: false)
        guard host.utf8.count <= 253,
            labels.allSatisfy({ label in
                !label.isEmpty && label.utf8.count <= 63 && label.first != "-" && label.last != "-"
                    && label.utf8.allSatisfy { (97...122).contains($0) || (48...57).contains($0) || $0 == 45 }
            })
        else { throw ProxyTLSError.invalidHostname }
        return host
    }

    private static func alternativeName(_ host: String) -> GeneralName {
        guard let address = try? SocketAddress(ipAddress: host, port: 0) else { return .dnsName(host) }
        let bytes: [UInt8]
        switch address {
        case .v4(let address): bytes = withUnsafeBytes(of: address.address.sin_addr) { Array($0) }
        case .v6(let address): bytes = withUnsafeBytes(of: address.address.sin6_addr) { Array($0) }
        case .unixDomainSocket: return .dnsName(host)
        }
        return .ipAddress(ASN1OctetString(contentBytes: bytes[...]))
    }

    private struct ServerIdentity {
        let context: NIOSSLContext
        let certificateChainPEM: Data
        let expires: Date
    }
}
