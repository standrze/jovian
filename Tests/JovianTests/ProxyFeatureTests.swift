import Foundation
import XCTest

@testable import Jovian

#if canImport(Darwin)
    import Darwin
#else
    import Glibc
#endif

final class ProxyFeatureTests: XCTestCase {
    private struct SilentLogger: TrafficLogger {
        func record(_ entry: TrafficEntry) {}
    }

    private struct RewriteConnect: Modifier {
        let target: String

        func modify(request: inout RequestContext) {
            if request.method == "CONNECT" { request.target = target }
        }

        func modify(response: inout ResponseContext) {
            if response.requestMethod == "CONNECT" { response.head["X-Connect-Modifier"] = "applied" }
        }
    }

    private struct ThrowingModifier: Modifier {
        func modify(request: inout RequestContext) throws {
            request.head["X-Request-Before-Error"] = "retained"
            throw ProxyError.unsupported("request fixture failure")
        }

        func modify(response: inout ResponseContext) throws {
            response.head["X-Response-Before-Error"] = "retained"
            throw ProxyError.unsupported("response fixture failure")
        }
    }

    private func readToEnd(_ socket: Socket) throws -> Data {
        var result = Data()
        while let bytes = try socket.read() { result.append(bytes) }
        return result
    }

    private func assertNoPendingConnection(_ listener: Socket, file: StaticString = #filePath, line: UInt = #line) {
        var event = pollfd(fd: listener.descriptor, events: Int16(POLLIN), revents: 0)
        XCTAssertEqual(poll(&event, 1, 0), 0, "rejection must precede dialing the origin", file: file, line: line)
    }

    func testConnectAppliesTargetAndResponseModifiers() throws {
        let listener = try Socket.listen(host: "127.0.0.1", port: 0)
        defer { listener.close() }
        let originPort = try listener.localPort()
        let finished = expectation(description: "rewritten CONNECT target echoes the payload")
        Thread.detachNewThread {
            defer { finished.fulfill() }
            do {
                let origin = try listener.accept()
                defer { origin.close() }
                var body = Data()
                while let bytes = try origin.read() { body.append(bytes) }
                try origin.write(body)
            } catch {
                XCTFail("origin fixture failed: \(error)")
            }
        }
        let proxy = ProxyServer(
            port: 0, modifier: RewriteConnect(target: "127.0.0.1:\(originPort)"), logger: SilentLogger())
        let proxyPort = try proxy.start()
        defer { proxy.stop() }
        let client = try Socket.connect(host: "127.0.0.1", port: proxyPort)
        defer { client.close() }
        let payload = Data("rewritten destination".utf8)
        try client.write(Data("CONNECT 127.0.0.1:1 HTTP/1.1\r\nHost: 127.0.0.1:1\r\n\r\n".utf8) + payload)
        client.shutdownWrite()

        let (head, buffered) = try client.readHead()
        XCTAssertTrue(head.startLine.contains("200"), head.startLine)
        XCTAssertEqual(head["X-Connect-Modifier"], "applied")
        XCTAssertEqual(buffered + (try readToEnd(client)), payload)
        wait(for: [finished], timeout: 4)
    }

    func testConnectSyntheticRejectionRunsResponseModifiersBeforeAnyDial() throws {
        let listener = try Socket.listen(host: "127.0.0.1", port: 0)
        defer { listener.close() }
        let originPort = try listener.localPort()
        let proxy = ProxyServer(
            port: 0,
            modifier: ModifierGroup([
                FailureModifier(statusCode: 403, reason: "Forbidden", body: Data("declined".utf8)),
                HeaderModifier(scope: .response, name: "X-Decision", value: "local"),
            ]), logger: SilentLogger())
        let proxyPort = try proxy.start()
        defer { proxy.stop() }
        let client = try Socket.connect(host: "127.0.0.1", port: proxyPort)
        defer { client.close() }
        try client.write(
            Data("CONNECT 127.0.0.1:\(originPort) HTTP/1.1\r\nHost: 127.0.0.1:\(originPort)\r\n\r\n".utf8))

        let (head, buffered) = try client.readHead()
        XCTAssertTrue(head.startLine.contains("403 Forbidden"), head.startLine)
        XCTAssertEqual(head["X-Decision"], "local")
        XCTAssertEqual(buffered + (try readToEnd(client)), Data("declined".utf8))
        assertNoPendingConnection(listener)
    }

    func testConnectDialFailureRunsTheResponseModifier() throws {
        let unavailable = try Socket.listen(host: "127.0.0.1", port: 0)
        let originPort = try unavailable.localPort()
        unavailable.close()
        let proxy = ProxyServer(
            port: 0,
            modifier: HeaderModifier(scope: .response, name: "X-Failure-Hook", value: "observed"),
            logger: SilentLogger())
        let proxyPort = try proxy.start()
        defer { proxy.stop() }
        let client = try Socket.connect(host: "127.0.0.1", port: proxyPort)
        defer { client.close() }
        try client.write(
            Data("CONNECT 127.0.0.1:\(originPort) HTTP/1.1\r\nHost: 127.0.0.1:\(originPort)\r\n\r\n".utf8))

        let (head, _) = try client.readHead()
        XCTAssertTrue(head.startLine.contains("502"), head.startLine)
        XCTAssertEqual(head["X-Failure-Hook"], "observed")
        _ = try readToEnd(client)
    }

    func testDownstreamProxyReceivesAbsoluteTargetAndItsOwnCredentials() throws {
        let listener = try Socket.listen(host: "127.0.0.1", port: 0)
        defer { listener.close() }
        let downstreamPort = try listener.localPort()
        let target = "http://127.0.0.1:43210/example?q=value"
        let hopAuthorization = "Basic " + Data("hop:hop-password".utf8).base64EncodedString()
        let completed = expectation(description: "downstream proxy receives an absolute-form request")
        Thread.detachNewThread {
            defer { completed.fulfill() }
            do {
                let downstream = try listener.accept()
                defer { downstream.close() }
                let (head, _) = try downstream.readHead()
                XCTAssertEqual(head.startLine, "GET \(target) HTTP/1.1")
                XCTAssertEqual(head["Host"], "127.0.0.1:43210")
                XCTAssertEqual(head["Proxy-Authorization"], hopAuthorization)
                XCTAssertEqual(head["Authorization"], "Bearer fixture-origin")
                try downstream.write(Data("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok".utf8))
            } catch {
                XCTFail("downstream fixture failed: \(error)")
            }
        }
        let downstream = try DownstreamProxy(
            url: XCTUnwrap(URL(string: "http://hop:hop-password@127.0.0.1:\(downstreamPort)")))
        let proxy = ProxyServer(
            port: 0, logger: SilentLogger(),
            credentials: ProxyCredentials(username: "client", password: "client-password"),
            downstreamProxy: downstream)
        let proxyPort = try proxy.start()
        defer { proxy.stop() }
        let client = try Socket.connect(host: "127.0.0.1", port: proxyPort)
        defer { client.close() }
        let clientAuthorization = Data("client:client-password".utf8).base64EncodedString()
        try client.write(
            Data(
                ("GET \(target) HTTP/1.1\r\nHost: 127.0.0.1:43210\r\n"
                    + "Proxy-Authorization: Basic \(clientAuthorization)\r\n"
                    + "Authorization: Bearer fixture-origin\r\nConnection: close\r\n\r\n").utf8))
        let (head, buffered) = try client.readHead()
        XCTAssertTrue(head.startLine.contains("200"), head.startLine)
        XCTAssertEqual(buffered + (try readToEnd(client)), Data("ok".utf8))
        wait(for: [completed], timeout: 4)
    }

    func testProxyChainConsumesProxyCredentialsBeforeTheOrigin() throws {
        let listener = try Socket.listen(host: "127.0.0.1", port: 0)
        defer { listener.close() }
        let originPort = try listener.localPort()
        let completed = expectation(description: "origin receives no proxy credentials")
        Thread.detachNewThread {
            defer { completed.fulfill() }
            do {
                let origin = try listener.accept()
                defer { origin.close() }
                let (head, _) = try origin.readHead()
                XCTAssertEqual(head.startLine, "GET /chain HTTP/1.1")
                XCTAssertNil(head["Proxy-Authorization"])
                XCTAssertEqual(head["Authorization"], "Bearer fixture-origin")
                try origin.write(Data("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok".utf8))
            } catch {
                XCTFail("origin fixture failed: \(error)")
            }
        }
        let next = ProxyServer(
            port: 0, logger: SilentLogger(), credentials: ProxyCredentials(username: "hop", password: "hop-password"))
        let nextPort = try next.start()
        defer { next.stop() }
        let downstream = try DownstreamProxy(
            url: XCTUnwrap(URL(string: "http://hop:hop-password@127.0.0.1:\(nextPort)")))
        let proxy = ProxyServer(port: 0, logger: SilentLogger(), downstreamProxy: downstream)
        XCTAssertNotEqual(proxy.viaIdentity, next.viaIdentity)
        let proxyPort = try proxy.start()
        defer { proxy.stop() }
        let client = try Socket.connect(host: "127.0.0.1", port: proxyPort)
        defer { client.close() }
        try client.write(
            Data(
                ("GET http://127.0.0.1:\(originPort)/chain HTTP/1.1\r\nHost: 127.0.0.1:\(originPort)\r\n"
                    + "Authorization: Bearer fixture-origin\r\nConnection: close\r\n\r\n").utf8))
        let (head, buffered) = try client.readHead()
        XCTAssertTrue(head.startLine.contains("200"), head.startLine)
        XCTAssertEqual(buffered + (try readToEnd(client)), Data("ok".utf8))
        wait(for: [completed], timeout: 4)
    }

    func testChainedConnectPreservesEarlyBytesAndBothHalfCloses() throws {
        let listener = try Socket.listen(host: "127.0.0.1", port: 0)
        defer { listener.close() }
        let downstreamPort = try listener.localPort()
        let payload = Data([0, 255, 1, 2, 3])
        let greeting = Data("ready:".utf8)
        let completed = expectation(description: "downstream CONNECT handshake and echo")
        Thread.detachNewThread {
            defer { completed.fulfill() }
            do {
                let downstream = try listener.accept()
                defer { downstream.close() }
                let (head, earlyBytes) = try downstream.readHead()
                XCTAssertEqual(head.startLine, "CONNECT 127.0.0.1:443 HTTP/1.1")
                XCTAssertEqual(head["Proxy-Authorization"], "Basic " + Data("hop:secret".utf8).base64EncodedString())
                try downstream.write(
                    Data("HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 Connection Established\r\n\r\n".utf8) + greeting)
                var received = earlyBytes
                while let bytes = try downstream.read() { received.append(bytes) }
                XCTAssertEqual(received, payload)
                try downstream.write(received)
                downstream.shutdownWrite()
            } catch {
                XCTFail("downstream CONNECT fixture failed: \(error)")
            }
        }
        let downstream = try DownstreamProxy(
            url: XCTUnwrap(URL(string: "http://hop:secret@127.0.0.1:\(downstreamPort)")))
        let proxy = ProxyServer(port: 0, logger: SilentLogger(), downstreamProxy: downstream)
        let proxyPort = try proxy.start()
        defer { proxy.stop() }
        let client = try Socket.connect(host: "127.0.0.1", port: proxyPort)
        defer { client.close() }
        try client.write(Data("CONNECT 127.0.0.1:443 HTTP/1.1\r\nHost: 127.0.0.1:443\r\n\r\n".utf8) + payload)
        client.shutdownWrite()
        let (head, buffered) = try client.readHead()
        XCTAssertTrue(head.startLine.contains("200"), head.startLine)
        XCTAssertEqual(buffered + (try readToEnd(client)), greeting + payload)
        wait(for: [completed], timeout: 4)
    }

    func testChainedConnectForwardsRejectedResponseBodies() throws {
        let responses = [
            "HTTP/1.1 403 Forbidden\r\nContent-Length: 8\r\n\r\ndeclined",
            "HTTP/1.1 403 Forbidden\r\nTransfer-Encoding: chunked\r\n\r\n8\r\ndeclined\r\n0\r\n\r\n",
            "HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\ndeclined",
        ]
        for response in responses {
            let listener = try Socket.listen(host: "127.0.0.1", port: 0)
            defer { listener.close() }
            let port = try listener.localPort()
            let completed = expectation(description: "downstream rejects CONNECT")
            Thread.detachNewThread {
                defer { completed.fulfill() }
                do {
                    let downstream = try listener.accept()
                    defer { downstream.close() }
                    _ = try downstream.readHead()
                    try downstream.write(Data(response.utf8))
                } catch {
                    XCTFail("CONNECT rejection fixture failed: \(error)")
                }
            }
            let downstream = try DownstreamProxy(url: XCTUnwrap(URL(string: "http://127.0.0.1:\(port)")))
            let proxy = ProxyServer(port: 0, logger: SilentLogger(), downstreamProxy: downstream)
            let proxyPort = try proxy.start()
            defer { proxy.stop() }
            let client = try Socket.connect(host: "127.0.0.1", port: proxyPort)
            defer { client.close() }
            try client.write(Data("CONNECT example.test:443 HTTP/1.1\r\nHost: example.test:443\r\n\r\n".utf8))
            let (head, buffered) = try client.readHead()
            XCTAssertTrue(head.startLine.contains("403"), head.startLine)
            XCTAssertEqual(buffered + (try readToEnd(client)), Data("declined".utf8))
            wait(for: [completed], timeout: 4)
        }
    }

    func testRequestTimeoutClosesAnExchangeWaitingForOriginHeaders() throws {
        let listener = try Socket.listen(host: "127.0.0.1", port: 0)
        defer { listener.close() }
        let originPort = try listener.localPort()
        let completed = expectation(description: "request timeout closes the upstream socket")
        Thread.detachNewThread {
            defer { completed.fulfill() }
            do {
                let origin = try listener.accept()
                defer { origin.close() }
                _ = try origin.readHead()
                XCTAssertNil(try origin.read())
            } catch {
                XCTFail("timeout fixture failed: \(error)")
            }
        }
        let proxy = ProxyServer(port: 0, logger: SilentLogger(), requestTimeout: 0.15)
        let proxyPort = try proxy.start()
        defer { proxy.stop() }
        let client = try Socket.connect(host: "127.0.0.1", port: proxyPort)
        defer { client.close() }
        let started = ContinuousClock.now
        try client.write(
            Data(
                "GET http://127.0.0.1:\(originPort)/slow HTTP/1.1\r\nHost: 127.0.0.1:\(originPort)\r\nConnection: close\r\n\r\n"
                    .utf8))
        _ = try readToEnd(client)
        XCTAssertLessThan(started.duration(to: .now), .seconds(2))
        wait(for: [completed], timeout: 4)
    }

    func testViaLoopIsRejectedBeforeOriginDial() throws {
        let listener = try Socket.listen(host: "127.0.0.1", port: 0)
        defer { listener.close() }
        let originPort = try listener.localPort()
        let proxy = ProxyServer(port: 0, logger: SilentLogger())
        let proxyPort = try proxy.start()
        defer { proxy.stop() }
        let client = try Socket.connect(host: "127.0.0.1", port: proxyPort)
        defer { client.close() }
        try client.write(
            Data(
                ("GET http://127.0.0.1:\(originPort)/ HTTP/1.1\r\nHost: 127.0.0.1:\(originPort)\r\n"
                    + "Via: 1.0 fixture, 1.1 \(proxy.viaIdentity)\r\nConnection: close\r\n\r\n").utf8))
        let (head, _) = try client.readHead()
        XCTAssertTrue(head.startLine.contains("400"), head.startLine)
        _ = try readToEnd(client)
        assertNoPendingConnection(listener)
    }

    func testThrowingModifiersPreserveChangesAndAppendWarningsWhileForwarding() throws {
        let listener = try Socket.listen(host: "127.0.0.1", port: 0)
        defer { listener.close() }
        let originPort = try listener.localPort()
        let completed = expectation(description: "request forwards despite the modifier error")
        Thread.detachNewThread {
            defer { completed.fulfill() }
            do {
                let origin = try listener.accept()
                defer { origin.close() }
                let (head, _) = try origin.readHead()
                XCTAssertEqual(head.startLine, "GET /warnings HTTP/1.1")
                XCTAssertEqual(head["X-Request-Before-Error"], "retained")
                XCTAssertTrue(head.values(for: "Warning").contains("110 fixture \"request stale\""))
                XCTAssertTrue(head.values(for: "Warning").contains { $0.contains("request fixture failure") })
                try origin.write(
                    Data(
                        ("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n"
                            + "Warning: 110 fixture \"response stale\"\r\n\r\nok").utf8))
            } catch {
                XCTFail("warning fixture failed: \(error)")
            }
        }
        let proxy = ProxyServer(port: 0, modifier: ThrowingModifier(), logger: SilentLogger())
        let proxyPort = try proxy.start()
        defer { proxy.stop() }
        let client = try Socket.connect(host: "127.0.0.1", port: proxyPort)
        defer { client.close() }
        try client.write(
            Data(
                ("GET http://127.0.0.1:\(originPort)/warnings HTTP/1.1\r\nHost: 127.0.0.1:\(originPort)\r\n"
                    + "Warning: 110 fixture \"request stale\"\r\nConnection: close\r\n\r\n").utf8))

        let (head, buffered) = try client.readHead()
        XCTAssertTrue(head.startLine.contains("200"), head.startLine)
        XCTAssertEqual(head["X-Response-Before-Error"], "retained")
        XCTAssertTrue(head.values(for: "Warning").contains("110 fixture \"response stale\""))
        XCTAssertTrue(head.values(for: "Warning").contains { $0.contains("response fixture failure") })
        XCTAssertEqual(buffered + (try readToEnd(client)), Data("ok".utf8))
        wait(for: [completed], timeout: 4)
    }

    func testHTTPDialFailureRunsResponseModifiers() throws {
        let unavailable = try Socket.listen(host: "127.0.0.1", port: 0)
        let originPort = try unavailable.localPort()
        unavailable.close()
        let proxy = ProxyServer(
            port: 0,
            modifier: ModifierGroup([
                HeaderModifier(scope: .response, name: "X-Failure-Hook", value: "observed"),
                BodyModifier(scope: .response, content: Data("modified failure".utf8), contentType: "text/plain"),
            ]), logger: SilentLogger())
        let proxyPort = try proxy.start()
        defer { proxy.stop() }
        let client = try Socket.connect(host: "127.0.0.1", port: proxyPort)
        defer { client.close() }
        try client.write(
            Data(
                "GET http://127.0.0.1:\(originPort)/unavailable HTTP/1.1\r\nHost: 127.0.0.1:\(originPort)\r\nConnection: close\r\n\r\n"
                    .utf8))

        let (head, buffered) = try client.readHead()
        XCTAssertTrue(head.startLine.contains("502"), head.startLine)
        XCTAssertEqual(head["X-Failure-Hook"], "observed")
        XCTAssertEqual(head["Content-Length"], String("modified failure".utf8.count))
        XCTAssertEqual(buffered + (try readToEnd(client)), Data("modified failure".utf8))
    }
}
