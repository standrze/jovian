import Foundation
import NIOCore
import NIOSSL
import X509

/// Immutable TLS policy for connections from the proxy to HTTPS origins.
///
/// The default validates the certificate chain and hostname using system trust roots.
/// Supplying roots replaces that trust set. HTTP/1.1 is the only advertised application protocol.
public final class ProxyTLSConfiguration: Sendable {
    public let upstreamContext: NIOSSLContext

    /// Creates a client context.
    ///
    /// Disable verification only for explicitly configured local test origins.
    public init(trustRootsPEM: Data? = nil, insecureSkipVerification: Bool = false) throws {
        var configuration = NIOSSL.TLSConfiguration.makeClientConfiguration()
        configuration.applicationProtocols = ["http/1.1"]
        configuration.minimumTLSVersion = .tlsv12
        configuration.shutdownTimeout = .milliseconds(100)
        if let trustRootsPEM {
            let roots = try NIOSSLCertificate.fromPEMBytes(Array(trustRootsPEM))
            guard !roots.isEmpty else { throw ProxyTLSError.emptyCertificateChain }
            configuration.trustRoots = .certificates(roots)
        }
        if insecureSkipVerification {
            configuration.certificateVerification = .none
        }
        upstreamContext = try NIOSSLContext(configuration: configuration)
    }

    /// Creates a listener identity from a leaf-first PEM certificate chain and its matching private key.
    public static func serverContext(certificatePEM: Data, privateKeyPEM: Data) throws -> NIOSSLContext {
        let certificates = try NIOSSLCertificate.fromPEMBytes(Array(certificatePEM))
        guard !certificates.isEmpty else { throw ProxyTLSError.emptyCertificateChain }
        let leaf = try Certificate(derEncoded: certificates[0].toDERBytes())
        let signingKey = try Certificate.PrivateKey(pemEncoded: String(decoding: privateKeyPEM, as: UTF8.self))
        guard leaf.publicKey == signingKey.publicKey else { throw ProxyTLSError.mismatchedPrivateKey }
        let key = try NIOSSLPrivateKey(bytes: Array(privateKeyPEM), format: .pem)
        var configuration = NIOSSL.TLSConfiguration.makeServerConfiguration(
            certificateChain: certificates.map { .certificate($0) }, privateKey: .privateKey(key))
        configuration.applicationProtocols = ["http/1.1"]
        configuration.minimumTLSVersion = .tlsv12
        configuration.shutdownTimeout = .milliseconds(100)
        return try NIOSSLContext(configuration: configuration)
    }
}

/// Invalid certificate or TLS configuration supplied to the proxy.
public enum ProxyTLSError: Error, LocalizedError {
    case emptyCertificateChain
    case invalidAuthority
    case mismatchedPrivateKey
    case invalidValidity
    case invalidCacheCapacity
    case invalidHostname
    case peerIPAddressMismatch

    public var errorDescription: String? {
        switch self {
        case .emptyCertificateChain: "TLS certificate chain is empty"
        case .invalidAuthority: "certificate authority must be a currently valid CA with certificate-signing usage"
        case .mismatchedPrivateKey: "certificate and private key do not match"
        case .invalidValidity: "certificate validity must be a positive, finite interval"
        case .invalidCacheCapacity: "certificate cache capacity must be positive"
        case .invalidHostname: "certificate hostname must be a DNS name or an IP address"
        case .peerIPAddressMismatch: "TLS certificate does not contain the requested IP address"
        }
    }
}

/// TLS handlers are constructed on the owning channel event loop from these immutable contexts.
enum TLSConnectionMode: Sendable {
    case server(NIOSSLContext)
    case client(NIOSSLContext, serverHostname: String?)

    func makeHandler() throws -> NIOSSLHandler {
        switch self {
        case .server(let context): NIOSSLServerHandler(context: context)
        case .client(let context, let hostname): try Self.clientHandler(context: context, hostname: hostname)
        }
    }

    private static func clientHandler(context: NIOSSLContext, hostname: String?) throws -> NIOSSLClientHandler {
        guard let hostname, let address = try? SocketAddress(ipAddress: hostname, port: 0) else {
            return try NIOSSLClientHandler(context: context, serverHostname: hostname)
        }
        if case .none = context.configuration.certificateVerification {
            return try NIOSSLClientHandler(context: context, serverHostname: nil)
        }
        let expected: [UInt8]
        switch address {
        case .v4(let address): expected = withUnsafeBytes(of: address.address.sin_addr) { Array($0) }
        case .v6(let address): expected = withUnsafeBytes(of: address.address.sin6_addr) { Array($0) }
        case .unixDomainSocket: throw ProxyTLSError.invalidHostname
        }
        var configuration = context.configuration
        configuration.certificateVerification = .noHostnameVerification
        let ipContext = try NIOSSLContext(configuration: configuration)
        // NIOSSL's additional-verification hook preserves its chain validation and blocks application data
        // until this check succeeds. Its public API is currently underscored, so keep its use isolated here.
        // Verifying the intended IP explicitly also works when the socket peer is a chained proxy.
        return try NIOSSLClientHandler._makeSSLClientHandler(
            context: ipContext, serverHostname: nil,
            additionalPeerCertificateVerificationCallback: { certificate, channel in
                do {
                    let parsed = try Certificate(derEncoded: certificate.toDERBytes())
                    let matches =
                        try parsed.extensions.subjectAlternativeNames?.contains { name in
                            guard case .ipAddress(let bytes) = name else { return false }
                            return Array(bytes.bytes) == expected
                        } ?? false
                    guard matches else { throw ProxyTLSError.peerIPAddressMismatch }
                    return channel.eventLoop.makeSucceededVoidFuture()
                } catch {
                    return channel.eventLoop.makeFailedFuture(error)
                }
            })
    }
}
