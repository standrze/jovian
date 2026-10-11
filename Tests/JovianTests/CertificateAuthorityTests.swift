import Crypto
import Foundation
import NIOCore
import NIOEmbedded
import NIOSSL
import SwiftASN1
import Testing
import X509

@testable import Jovian

@Suite("local proxy certificate authority")
struct CertificateAuthorityTests {
    @Test func generatesAuthorityAndSignedDNSLeaf() throws {
        let authority = try CertificateAuthority.generate(organization: "Local Fixture", validitySeconds: 3600)
        let root = try Certificate(derEncoded: Array(authority.certificateDER))
        let documents = try PEMDocument.parseMultiple(
            pemString: String(decoding: authority.certificateChain(for: "LOCALHOST."), as: UTF8.self))
        let leaf = try Certificate(derEncoded: documents[0].derBytes)

        #expect(documents.count == 2)
        #expect(root.publicKey.isValidSignature(root.signature, for: root))
        #expect(root.publicKey.isValidSignature(leaf.signature, for: leaf))
        #expect(leaf.issuer == root.subject)
        #expect(leaf.notValidAfter <= root.notValidAfter)
        #expect(try root.extensions.keyUsage?.keyCertSign == true)
        #expect(try leaf.extensions.basicConstraints == .notCertificateAuthority)
        #expect(try leaf.extensions.subjectAlternativeNames == SubjectAlternativeNames([.dnsName("localhost")]))
        #expect(String(describing: leaf.subject).contains("Local Fixture"))
        #expect(try authority.serverContext(for: "localhost").configuration.applicationProtocols == ["http/1.1"])
    }

    @Test func issuesIPSubjectAlternativeNames() throws {
        let authority = try CertificateAuthority.generate()
        for (host, expected) in [
            ("127.0.0.1", [UInt8](arrayLiteral: 127, 0, 0, 1)),
            ("[::1]", [UInt8](repeating: 0, count: 15) + [1]),
        ] {
            let chain = try authority.certificateChain(for: host)
            let documents = try PEMDocument.parseMultiple(pemString: String(decoding: chain, as: UTF8.self))
            let leaf = try Certificate(derEncoded: documents[0].derBytes)
            let names = try #require(try leaf.extensions.subjectAlternativeNames)
            #expect(Array(names) == [.ipAddress(ASN1OctetString(contentBytes: expected[...]))])
        }
    }

    @Test func reusesIdentitiesUntilBoundedCacheEvictsThem() throws {
        let authority = try CertificateAuthority.generate(cacheCapacity: 1)
        let first = try authority.certificateChain(for: "first.localhost")
        #expect(try authority.certificateChain(for: "FIRST.localhost.") == first)
        _ = try authority.certificateChain(for: "second.localhost")
        #expect(try authority.certificateChain(for: "first.localhost") != first)
    }

    @Test func loadingRejectsMismatchedKeysAndLeafCertificates() throws {
        let authority = try CertificateAuthority.generate()
        let unrelated = try CertificateAuthority.generate()
        #expect(throws: ProxyTLSError.self) {
            try CertificateAuthority(certificatePEM: authority.certificatePEM, privateKeyPEM: unrelated.privateKeyPEM)
        }
        let key = P256.Signing.PrivateKey()
        let name = try DistinguishedName { CommonName("leaf.localhost") }
        let leaf = try Certificate(
            version: .v3, serialNumber: .init(), publicKey: .init(key.publicKey),
            notValidBefore: Date().addingTimeInterval(-60), notValidAfter: Date().addingTimeInterval(60),
            issuer: name, subject: name, signatureAlgorithm: .ecdsaWithSHA256,
            extensions: Certificate.Extensions { Critical(BasicConstraints.notCertificateAuthority) },
            issuerPrivateKey: .init(key))
        #expect(throws: ProxyTLSError.self) {
            try CertificateAuthority(
                certificatePEM: Data(leaf.serializeAsPEM().pemString.utf8),
                privateKeyPEM: Data(key.pemRepresentation.utf8))
        }
    }

    @Test func reloadsAuthorityWithoutChangingItsIdentity() throws {
        let original = try CertificateAuthority.generate()
        let loaded = try CertificateAuthority(
            certificatePEM: original.certificatePEM, privateKeyPEM: original.privateKeyPEM)
        #expect(loaded.certificateDER == original.certificateDER)
        _ = try loaded.serverContext(for: "localhost")
    }

    @Test func validatesHostnameAndConfigurationBounds() throws {
        let authority = try CertificateAuthority.generate()
        for host in ["", "https://localhost", "localhost:443", "bad\nname", "*.localhost", "x..localhost", "-x"] {
            #expect(throws: ProxyTLSError.self) { try authority.serverContext(for: host) }
        }
        for seconds in [0, -1, TimeInterval.infinity, TimeInterval.nan] {
            #expect(throws: ProxyTLSError.self) { try CertificateAuthority.generate(validitySeconds: seconds) }
        }
        #expect(throws: ProxyTLSError.self) { try CertificateAuthority.generate(cacheCapacity: 0) }
    }

    @Test func defaultTLSVerifiesPeersAndTrustOverridesAreExplicit() throws {
        let configuration = try ProxyTLSConfiguration()
        #expect(configuration.upstreamContext.configuration.certificateVerification == .fullVerification)
        #expect(configuration.upstreamContext.configuration.applicationProtocols == ["http/1.1"])
        let insecure = try ProxyTLSConfiguration(insecureSkipVerification: true)
        #expect(insecure.upstreamContext.configuration.certificateVerification == .none)
        let authority = try CertificateAuthority.generate()
        let local = try ProxyTLSConfiguration(trustRootsPEM: authority.certificatePEM)
        #expect(local.upstreamContext.configuration.certificateVerification == .fullVerification)
        #expect(throws: (any Error).self) { try ProxyTLSConfiguration(trustRootsPEM: Data()) }
    }

    @Test func simultaneousIssuanceReusesOneIdentity() async throws {
        let authority = try CertificateAuthority.generate()
        let chains = try await withThrowingTaskGroup(of: Data.self) { group in
            for _ in 0..<16 { group.addTask { try authority.certificateChain(for: "localhost") } }
            var values: [Data] = []
            for try await chain in group { values.append(chain) }
            return values
        }
        #expect(chains.count == 16)
        #expect(Set(chains).count == 1)
    }

    @Test func listenerSelectsCertificateFromClientHelloSNI() async throws {
        let authority = try CertificateAuthority.generate()
        let listener = try authority.listenerContext(defaultHostname: "fallback.localhost")
        let callback = try #require(listener.configuration.sslContextCallback)
        let channel = NIOAsyncTestingChannel()
        defer { channel.close(promise: nil) }
        for (sni, expected) in [("named.localhost" as String?, "named.localhost"), (nil, "fallback.localhost")] {
            let promise = channel.eventLoop.makePromise(of: NIOSSLContextConfigurationOverride.self)
            callback(.init(serverHostname: sni), promise)
            let changes = try await promise.futureResult.get()
            let chain = try #require(changes.certificateChain)
            guard case .certificate(let certificate) = try #require(chain.first) else {
                Issue.record("expected an in-memory TLS certificate")
                return
            }
            let leaf = try Certificate(derEncoded: certificate.toDERBytes())
            #expect(try leaf.extensions.subjectAlternativeNames == SubjectAlternativeNames([.dnsName(expected)]))
            #expect(changes.privateKey != nil)
        }
    }

    @Test func tlsHandshakeValidatesTrustAndRequestedDNSOrIPAddress() throws {
        let authority = try CertificateAuthority.generate()
        let unrelated = try CertificateAuthority.generate()
        for host in ["localhost", "127.0.0.1", "::1"] {
            try TLSFixture.exchange(authority: authority, serverHost: host, clientHost: host, roots: authority)
        }
        for (serverHost, clientHost) in [("localhost", "wrong.localhost"), ("127.0.0.1", "127.0.0.2")] {
            #expect(throws: (any Error).self) {
                try TLSFixture.exchange(
                    authority: authority, serverHost: serverHost, clientHost: clientHost, roots: authority)
            }
        }
        #expect(throws: (any Error).self) {
            try TLSFixture.exchange(
                authority: authority, serverHost: "127.0.0.1", clientHost: "127.0.0.1", roots: unrelated)
        }
    }

    @Test func rawTransitionReplaysSniffedBytesQueuedBytesAndEOF() async throws {
        let channel = NIOAsyncTestingChannel()
        let connection = try await channel.eventLoop.submit { try ChannelConnection(channel: channel, role: .raw) }
            .get()
        defer { connection.close() }
        try await channel.writeInbound(ByteBuffer(string: "GET /inside HTTP/1.1\r\nHost: local"))
        guard case .bytes(let sniffed)? = try await connection.next() else {
            Issue.record("missing raw protocol prefix")
            return
        }
        try await channel.writeInbound(ByteBuffer(string: "host\r\n\r\n"))
        try await channel.eventLoop.submit {
            channel.pipeline.fireUserInboundEventTriggered(ChannelEvent.inputClosed)
        }.get()
        try await connection.becomeHTTP(role: .server, replaying: [sniffed])
        guard case .request(let request)? = try await connection.next() else {
            Issue.record("missing replayed HTTP request")
            return
        }
        #expect(request.uri == "/inside")
        #expect(request.headers.first(name: "Host") == "localhost")
        guard case .end? = try await connection.next() else {
            Issue.record("missing replayed request boundary")
            return
        }
        #expect(try await connection.next() == nil)
    }
}

/// Local in-memory TLS transport.
///
/// Its socket peer deliberately differs from the requested IP SAN.
private enum TLSFixture {
    static func exchange(
        authority: CertificateAuthority, serverHost: String, clientHost: String, roots: CertificateAuthority
    ) throws {
        let loop = EmbeddedEventLoop()
        let policy = try ProxyTLSConfiguration(trustRootsPEM: roots.certificatePEM)
        let client = try EmbeddedChannel(
            handler: TLSConnectionMode.client(policy.upstreamContext, serverHostname: clientHost).makeHandler(),
            loop: loop)
        let server = try EmbeddedChannel(
            handler: TLSConnectionMode.server(authority.serverContext(for: serverHost)).makeHandler(), loop: loop)
        defer {
            client.close(promise: nil)
            server.close(promise: nil)
            try? transfer(client, server, loop: loop)
            loop.advanceTime(by: .seconds(10))
            _ = try? client.finish(acceptAlreadyClosed: true)
            _ = try? server.finish(acceptAlreadyClosed: true)
        }
        try client.connect(to: SocketAddress(ipAddress: "192.0.2.1", port: 443)).wait()
        try server.connect(to: SocketAddress(ipAddress: "192.0.2.2", port: 443)).wait()
        client.writeAndFlush(ByteBuffer(string: "local TLS fixture"), promise: nil)
        try transfer(client, server, loop: loop)
        let payload = try #require(try server.readInbound(as: ByteBuffer.self))
        #expect(String(buffer: payload) == "local TLS fixture")
    }

    private static func transfer(_ client: EmbeddedChannel, _ server: EmbeddedChannel, loop: EmbeddedEventLoop) throws {
        for _ in 0..<100 {
            loop.run()
            var moved = false
            for (source, destination) in [(client, server), (server, client)] {
                while let output = try source.readOutbound(as: IOData.self) {
                    guard case .byteBuffer(let bytes) = output else {
                        throw ProxyError.connection("unexpected TLS file region")
                    }
                    try destination.writeInbound(bytes)
                    moved = true
                }
                try source.throwIfErrorCaught()
            }
            if !moved { return }
        }
        throw ProxyError.connection("local TLS handshake did not settle")
    }
}
