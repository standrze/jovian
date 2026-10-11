import Foundation
import NIOCore
import NIOHTTP1
import NIOPosix
import NIOSSL
import XCTest

@testable import Jovian

/// Real loopback TLS peers use independent NIO pipelines rather than the proxy's connection adapter.
final class ProxyTLSIntegrationTests: XCTestCase {
    private struct SilentLogger: TrafficLogger { func record(_ entry: TrafficEntry) {} }

    func testAbsoluteHTTPSUsesExplicitTrustAndRunsModifiers() throws {
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        defer { try? group.syncShutdownGracefully() }
        let authority = try CertificateAuthority.generate()
        let origin = try startOrigin(group: group, tls: authority.serverContext(for: "localhost"))
        defer { try? origin.close().wait() }
        let port = try XCTUnwrap(origin.localAddress?.port)
        let proxy = ProxyServer(
            port: 0, modifier: mutation(), logger: SilentLogger(),
            tlsConfiguration: try ProxyTLSConfiguration(trustRootsPEM: authority.certificatePEM))
        let proxyPort = try proxy.start()
        defer { proxy.stop() }

        let response = try request(
            group: group, proxyPort: proxyPort,
            target: "https://localhost:\(port)/secure", host: "localhost:\(port)")

        XCTAssertEqual(response.head.status.code, 200)
        XCTAssertEqual(response.head.headers.first(name: "X-Origin-Request"), "modified")
        XCTAssertEqual(response.head.headers.first(name: "X-Proxy-Response"), "modified")
        XCTAssertEqual(response.body, Data("origin:/secure".utf8))
    }

    func testUntrustedAuthorityAndWrongIPIdentityAreRejected() throws {
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        defer { try? group.syncShutdownGracefully() }
        let authority = try CertificateAuthority.generate()
        let unrelated = try CertificateAuthority.generate()
        let origin = try startOrigin(group: group, tls: authority.serverContext(for: "localhost"))
        defer { try? origin.close().wait() }
        let port = try XCTUnwrap(origin.localAddress?.port)

        for (trust, host) in [(unrelated.certificatePEM, "localhost"), (authority.certificatePEM, "127.0.0.1")] {
            let proxy = ProxyServer(
                port: 0, logger: SilentLogger(), tlsConfiguration: try ProxyTLSConfiguration(trustRootsPEM: trust))
            let proxyPort = try proxy.start()
            defer { proxy.stop() }

            let response = try request(
                group: group, proxyPort: proxyPort,
                target: "https://\(host):\(port)/must-not-arrive", host: "\(host):\(port)")

            XCTAssertEqual(response.head.status.code, 502)
            XCTAssertNil(response.head.headers.first(name: "X-Origin-Request"))
        }
    }

    func testConnectInterceptionUsesProxyAuthorityAndMutatesDecryptedHTTP() throws {
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        defer { try? group.syncShutdownGracefully() }
        let originAuthority = try CertificateAuthority.generate(commonName: "Origin fixture")
        let proxyAuthority = try CertificateAuthority.generate(commonName: "Proxy fixture")
        let origin = try startOrigin(group: group, tls: originAuthority.serverContext(for: "localhost"))
        defer { try? origin.close().wait() }
        let port = try XCTUnwrap(origin.localAddress?.port)
        let proxy = ProxyServer(
            port: 0, modifier: mutation(), logger: SilentLogger(),
            tlsConfiguration: try ProxyTLSConfiguration(trustRootsPEM: originAuthority.certificatePEM),
            certificateAuthority: proxyAuthority)
        let proxyPort = try proxy.start()
        defer { proxy.stop() }

        let response = try request(
            group: group, proxyPort: proxyPort, target: "/fetch?url=https://example.test", host: "localhost:\(port)",
            tls: clientContext(trusting: proxyAuthority), connectAuthority: "localhost:\(port)")

        XCTAssertEqual(response.head.status.code, 200)
        XCTAssertEqual(response.head.headers.first(name: "X-Origin-Request"), "modified")
        XCTAssertEqual(response.head.headers.first(name: "X-Proxy-Response"), "modified")
        XCTAssertEqual(response.body, Data("origin:/fetch?url=https://example.test".utf8))
    }

    func testInterceptionRetainsPlaintextRequestCoalescedWithConnect() throws {
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        defer { try? group.syncShutdownGracefully() }
        let origin = try startOrigin(group: group)
        defer { try? origin.close().wait() }
        let port = try XCTUnwrap(origin.localAddress?.port)
        let proxy = ProxyServer(
            port: 0, modifier: mutation(), logger: SilentLogger(), certificateAuthority: try .generate())
        let proxyPort = try proxy.start()
        defer { proxy.stop() }
        let client = try Socket.connect(host: "127.0.0.1", port: proxyPort)
        defer { client.close() }
        try client.write(
            Data(
                ("CONNECT localhost:\(port) HTTP/1.1\r\nHost: localhost:\(port)\r\n\r\n"
                    + "GET /plaintext HTTP/1.1\r\nHost: localhost:\(port)\r\nConnection: close\r\n\r\n").utf8))
        var wire = Data()
        while let bytes = try client.read() { wire.append(bytes) }
        let response = String(decoding: wire, as: UTF8.self)

        XCTAssertEqual(response.components(separatedBy: "HTTP/1.1 200").count - 1, 2, response)
        XCTAssertTrue(response.contains("X-Origin-Request: modified"), response)
        XCTAssertTrue(response.hasSuffix("origin:/plaintext"), response)
    }

    func testDirectTLSListenerForwardsOriginFormAsHTTPS() throws {
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        defer { try? group.syncShutdownGracefully() }
        let originAuthority = try CertificateAuthority.generate(commonName: "Origin fixture")
        let proxyAuthority = try CertificateAuthority.generate(commonName: "Listener fixture")
        let origin = try startOrigin(group: group, tls: originAuthority.serverContext(for: "localhost"))
        defer { try? origin.close().wait() }
        let port = try XCTUnwrap(origin.localAddress?.port)
        let proxy = ProxyServer(
            port: 0, modifier: mutation(), logger: SilentLogger(),
            tlsConfiguration: try ProxyTLSConfiguration(trustRootsPEM: originAuthority.certificatePEM),
            tlsListenerContext: try proxyAuthority.listenerContext(defaultHostname: "fallback.localhost"))
        let proxyPort = try proxy.start()
        defer { proxy.stop() }

        let response = try request(
            group: group, proxyPort: proxyPort, target: "/fetch?url=https://example.test", host: "localhost:\(port)",
            tls: clientContext(trusting: proxyAuthority))

        XCTAssertEqual(response.head.status.code, 200)
        XCTAssertEqual(response.head.headers.first(name: "X-Origin-Request"), "modified")
        XCTAssertEqual(response.body, Data("origin:/fetch?url=https://example.test".utf8))
    }

    func testHTTPSDownstreamProxyAndOriginBothVerifyIPSubjectAlternativeNames() throws {
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        defer { try? group.syncShutdownGracefully() }
        let originAuthority = try CertificateAuthority.generate(commonName: "IP origin fixture")
        let downstreamAuthority = try CertificateAuthority.generate(commonName: "IP downstream fixture")
        let origin = try startOrigin(group: group, tls: originAuthority.serverContext(for: "127.0.0.1"))
        defer { try? origin.close().wait() }
        let originPort = try XCTUnwrap(origin.localAddress?.port)
        let downstream = ProxyServer(
            port: 0, logger: SilentLogger(),
            tlsListenerContext: try downstreamAuthority.serverContext(for: "127.0.0.1"),
            proxyName: "downstream")
        let downstreamPort = try downstream.start()
        defer { downstream.stop() }
        let roots = originAuthority.certificatePEM + Data("\n".utf8) + downstreamAuthority.certificatePEM
        let proxy = ProxyServer(
            port: 0, modifier: mutation(), logger: SilentLogger(),
            downstreamProxy: try DownstreamProxy(url: XCTUnwrap(URL(string: "https://127.0.0.1:\(downstreamPort)"))),
            tlsConfiguration: try ProxyTLSConfiguration(trustRootsPEM: roots), proxyName: "upstream")
        let proxyPort = try proxy.start()
        defer { proxy.stop() }

        let response = try request(
            group: group, proxyPort: proxyPort,
            target: "https://127.0.0.1:\(originPort)/nested-tls", host: "127.0.0.1:\(originPort)")

        XCTAssertEqual(response.head.status.code, 200)
        XCTAssertEqual(response.head.headers.first(name: "X-Origin-Request"), "modified")
        XCTAssertEqual(response.body, Data("origin:/nested-tls".utf8))
    }

    func testRequestDeadlineClosesAnUpstreamThatNeverCompletesTLSHandshake() throws {
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        defer { try? group.syncShutdownGracefully() }
        let handshakeStarted = expectation(description: "origin receives TLS ClientHello")
        let originClosed = expectation(description: "deadline closes the stalled TLS origin")
        let origin = try ServerBootstrap(group: group)
            .childChannelInitializer { channel in
                channel.eventLoop.makeCompletedFuture {
                    try channel.pipeline.syncOperations.addHandler(
                        TLSHandshakeStall(started: handshakeStarted, closed: originClosed))
                }
            }
            .bind(host: "127.0.0.1", port: 0).wait()
        defer { try? origin.close().wait() }
        let originPort = try XCTUnwrap(origin.localAddress?.port)
        let proxy = ProxyServer(port: 0, logger: SilentLogger(), requestTimeout: 0.2, connectTimeout: 30)
        let proxyPort = try proxy.start()
        defer { proxy.stop() }

        let started = ContinuousClock.now
        XCTAssertThrowsError(
            try request(
                group: group, proxyPort: proxyPort,
                target: "https://localhost:\(originPort)/stalled", host: "localhost:\(originPort)"))

        XCTAssertLessThan(started.duration(to: .now), .seconds(2))
        wait(for: [handshakeStarted, originClosed], timeout: 2)
    }

    private func mutation() -> ModifierGroup {
        ModifierGroup([
            HeaderModifier(scope: .request, name: "X-Fixture", value: "modified"),
            HeaderModifier(scope: .response, name: "X-Proxy-Response", value: "modified"),
        ])
    }

    private func clientContext(trusting authority: CertificateAuthority) throws -> NIOSSLContext {
        var configuration = NIOSSL.TLSConfiguration.makeClientConfiguration()
        configuration.trustRoots = .certificates(try NIOSSLCertificate.fromPEMBytes(Array(authority.certificatePEM)))
        configuration.applicationProtocols = ["http/1.1"]
        return try NIOSSLContext(configuration: configuration)
    }

    private func startOrigin(group: EventLoopGroup, tls: NIOSSLContext? = nil) throws -> Channel {
        try ServerBootstrap(group: group)
            .serverChannelOption(ChannelOptions.socketOption(.so_reuseaddr), value: 1)
            .childChannelInitializer { channel in
                channel.eventLoop.makeCompletedFuture {
                    if let tls { try channel.pipeline.syncOperations.addHandler(NIOSSLServerHandler(context: tls)) }
                }.flatMap {
                    channel.pipeline.configureHTTPServerPipeline()
                }.flatMap {
                    channel.eventLoop.makeCompletedFuture {
                        try channel.pipeline.syncOperations.addHandler(TLSOriginResponder())
                    }
                }
            }
            .bind(host: "127.0.0.1", port: 0).wait()
    }

    private func request(
        group: EventLoopGroup, proxyPort: UInt16, target: String, host: String,
        tls: NIOSSLContext? = nil, connectAuthority: String? = nil
    ) throws -> TLSFixtureResponse {
        let channel = try ClientBootstrap(group: group).connect(host: "127.0.0.1", port: Int(proxyPort)).wait()
        defer { try? channel.close().wait() }
        if let connectAuthority {
            let promise = channel.eventLoop.makePromise(of: Void.self)
            let handshake = ConnectAcknowledgement(promise: promise)
            try channel.pipeline.addHandler(handshake).wait()
            let timeout = channel.eventLoop.scheduleTask(in: .seconds(3)) { handshake.fail(TLSFixtureError.timeout) }
            defer { timeout.cancel() }
            try channel.writeAndFlush(
                ByteBuffer(string: "CONNECT \(connectAuthority) HTTP/1.1\r\nHost: \(connectAuthority)\r\n\r\n")
            ).wait()
            try promise.futureResult.wait()
            try channel.pipeline.removeHandler(handshake).wait()
        }
        let promise = channel.eventLoop.makePromise(of: TLSFixtureResponse.self)
        let collector = TLSResponseCollector(promise: promise)
        try channel.eventLoop.submit {
            if let tls {
                try channel.pipeline.syncOperations.addHandler(
                    NIOSSLClientHandler(context: tls, serverHostname: "localhost"))
            }
        }.flatMap {
            channel.pipeline.addHTTPClientHandlers()
        }.flatMap {
            channel.pipeline.addHandler(collector)
        }.wait()
        let timeout = channel.eventLoop.scheduleTask(in: .seconds(4)) { collector.fail(TLSFixtureError.timeout) }
        defer { timeout.cancel() }
        let head = HTTPRequestHead(
            version: .http1_1, method: .GET, uri: target,
            headers: HTTPHeaders([("Host", host), ("Connection", "close")]))
        try channel.writeAndFlush(HTTPClientRequestPart.head(head)).wait()
        try channel.writeAndFlush(HTTPClientRequestPart.end(nil)).wait()
        return try promise.futureResult.wait()
    }
}

private struct TLSFixtureResponse: Sendable {
    let head: HTTPResponseHead
    let body: Data
}

private enum TLSFixtureError: Error { case timeout, closed, unexpectedConnectResponse }

/// Accepts the handshake bytes without replying, so only the proxy's deadline ends this connection.
private final class TLSHandshakeStall: ChannelInboundHandler {
    typealias InboundIn = ByteBuffer
    private let started: XCTestExpectation
    private let closed: XCTestExpectation
    private var receivedHandshake = false

    init(started: XCTestExpectation, closed: XCTestExpectation) {
        self.started = started
        self.closed = closed
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        guard !receivedHandshake else { return }
        receivedHandshake = true
        XCTAssertEqual(unwrapInboundIn(data).readableBytesView.first, 22)
        started.fulfill()
    }

    func channelInactive(context: ChannelHandlerContext) {
        closed.fulfill()
        context.fireChannelInactive()
    }
}

/// State is confined to the local origin's event loop.
private final class TLSOriginResponder: ChannelInboundHandler {
    typealias InboundIn = HTTPServerRequestPart
    typealias OutboundOut = HTTPServerResponsePart
    private var request: HTTPRequestHead?

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        switch unwrapInboundIn(data) {
        case .head(let head): request = head
        case .body: break
        case .end:
            guard let request else { return }
            let body = ByteBuffer(string: "origin:\(request.uri)")
            let head = HTTPResponseHead(
                version: .http1_1, status: .ok,
                headers: HTTPHeaders([
                    ("Content-Length", String(body.readableBytes)), ("Connection", "close"),
                    ("X-Origin-Request", request.headers.first(name: "X-Fixture") ?? "absent"),
                ]))
            context.write(wrapOutboundOut(.head(head)), promise: nil)
            context.write(wrapOutboundOut(.body(.byteBuffer(body))), promise: nil)
            let channel = context.channel
            context.writeAndFlush(wrapOutboundOut(.end(nil))).whenComplete { _ in channel.close(promise: nil) }
        }
    }

    func errorCaught(context: ChannelHandlerContext, error: Error) { context.close(promise: nil) }
}

/// The timeout and NIO callbacks execute on the same event loop.
private final class TLSResponseCollector: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = HTTPClientResponsePart
    private let promise: EventLoopPromise<TLSFixtureResponse>
    private var head: HTTPResponseHead?
    private var body = Data()
    private var completed = false

    init(promise: EventLoopPromise<TLSFixtureResponse>) { self.promise = promise }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        guard !completed else { return }
        switch unwrapInboundIn(data) {
        case .head(let head): self.head = head
        case .body(let bytes): body.append(contentsOf: bytes.readableBytesView)
        case .end:
            guard let head else {
                fail(TLSFixtureError.closed)
                return
            }
            completed = true
            promise.succeed(TLSFixtureResponse(head: head, body: body))
        }
    }

    func fail(_ error: Error) {
        guard !completed else { return }
        completed = true
        promise.fail(error)
    }

    func errorCaught(context: ChannelHandlerContext, error: Error) {
        fail(error)
        context.close(promise: nil)
    }

    func channelInactive(context: ChannelHandlerContext) {
        fail(TLSFixtureError.closed)
        context.fireChannelInactive()
    }
}

/// Reads only the plaintext CONNECT acknowledgement before installing independent client TLS codecs.
private final class ConnectAcknowledgement: ChannelInboundHandler, RemovableChannelHandler, @unchecked Sendable {
    typealias InboundIn = ByteBuffer
    private let promise: EventLoopPromise<Void>
    private var received = Data()
    private var completed = false

    init(promise: EventLoopPromise<Void>) { self.promise = promise }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        guard !completed else { return }
        received.append(contentsOf: unwrapInboundIn(data).readableBytesView)
        guard received.range(of: Data("\r\n\r\n".utf8)) != nil else { return }
        guard String(decoding: received, as: UTF8.self).hasPrefix("HTTP/1.1 200 ") else {
            fail(TLSFixtureError.unexpectedConnectResponse)
            return
        }
        completed = true
        promise.succeed(())
    }

    func fail(_ error: Error) {
        guard !completed else { return }
        completed = true
        promise.fail(error)
    }

    func errorCaught(context: ChannelHandlerContext, error: Error) { fail(error) }
    func channelInactive(context: ChannelHandlerContext) { fail(TLSFixtureError.closed) }
}
