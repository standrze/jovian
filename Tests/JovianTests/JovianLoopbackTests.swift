import Foundation
import XCTest

@testable import Jovian

final class JovianLoopbackTests: XCTestCase {
    private struct SilentLogger: TrafficLogger { func record(_ entry: TrafficEntry) {} }

    private func readToEnd(_ client: Socket) throws -> Data {
        var result = Data()
        while let data = try client.read() { result.append(data) }
        return result
    }

    func testConnectRetainsCoalescedOpaqueBytesBeforeClientHalfClose() throws {
        let listener = try Socket.listen(host: "127.0.0.1", port: 0)
        defer { listener.close() }
        let port = try listener.localPort()
        let completed = expectation(description: "opaque echo")
        Thread.detachNewThread {
            defer { completed.fulfill() }
            guard let upstream = try? listener.accept() else { return }
            defer { upstream.close() }
            var received = Data()
            while let bytes = try? upstream.read() { received.append(bytes) }
            try? upstream.write(received)
        }
        let proxy = ProxyServer(port: 0, logger: SilentLogger())
        let proxyPort = try proxy.start()
        defer { proxy.stop() }
        let client = try Socket.connect(host: "127.0.0.1", port: proxyPort)
        defer { client.close() }
        let payload = Data([0, 255, 3, 0, 5])
        try client.write(Data("CONNECT 127.0.0.1:\(port) HTTP/1.1\r\n\r\n".utf8) + payload)
        client.shutdownWrite()
        let (head, buffered) = try client.readHead()
        XCTAssertEqual(head.startLine, "HTTP/1.1 200 Connection Established")
        XCTAssertNil(head["Transfer-Encoding"])
        XCTAssertEqual(buffered + (try readToEnd(client)), payload)
        wait(for: [completed], timeout: 4)
    }

    func testUpgradePreservesBothDirectionsAndCoalescedUpstreamBytes() throws {
        let listener = try Socket.listen(host: "127.0.0.1", port: 0)
        defer { listener.close() }
        let port = try listener.localPort()
        let completed = expectation(description: "upgraded echo")
        Thread.detachNewThread {
            defer { completed.fulfill() }
            guard let upstream = try? listener.accept() else { return }
            defer { upstream.close() }
            guard let (_, buffered) = try? upstream.readHead() else { return }
            try? upstream.write(
                Data("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: fixture\r\n\r\nwelcome:".utf8)
            )
            var received = buffered
            while let bytes = try? upstream.read() { received.append(bytes) }
            try? upstream.write(received)
        }
        let proxy = ProxyServer(port: 0, logger: SilentLogger())
        let proxyPort = try proxy.start()
        defer { proxy.stop() }
        let client = try Socket.connect(host: "127.0.0.1", port: proxyPort)
        defer { client.close() }
        try client.write(
            Data(
                ("GET http://127.0.0.1:\(port)/ HTTP/1.1\r\nHost: 127.0.0.1:\(port)\r\n"
                    + "Connection: Upgrade\r\nUpgrade: fixture\r\n\r\nhello").utf8))
        client.shutdownWrite()
        let (head, buffered) = try client.readHead()
        XCTAssertTrue(head.startLine.contains("101"))
        XCTAssertEqual(buffered + (try readToEnd(client)), Data("welcome:hello".utf8))
        wait(for: [completed], timeout: 4)
    }

    func testPoolReusesFullyConsumedUpstreamAcrossDownstreamConnections() throws {
        let listener = try Socket.listen(host: "127.0.0.1", port: 0)
        defer { listener.close() }
        let port = try listener.localPort()
        let completed = expectation(description: "one upstream connection handles two requests")
        Thread.detachNewThread {
            defer { completed.fulfill() }
            guard let upstream = try? listener.accept() else { return }
            defer { upstream.close() }
            for index in 1...2 {
                guard (try? upstream.readHead()) != nil else { return }
                try? upstream.write(
                    Data("HTTP/1.1 200 OK\r\nContent-Length: 1\r\nConnection: keep-alive\r\n\r\n\(index)".utf8))
            }
        }
        let proxy = ProxyServer(port: 0, logger: SilentLogger())
        let proxyPort = try proxy.start()
        defer { proxy.stop() }
        for index in 1...2 {
            let client = try Socket.connect(host: "127.0.0.1", port: proxyPort)
            defer { client.close() }
            try client.write(
                Data(
                    "GET http://127.0.0.1:\(port)/\(index) HTTP/1.1\r\nHost: 127.0.0.1:\(port)\r\nConnection: close\r\n\r\n"
                        .utf8))
            let response = String(decoding: try readToEnd(client), as: UTF8.self)
            XCTAssertTrue(response.hasSuffix(String(index)), response)
        }
        wait(for: [completed], timeout: 4)
    }

    func testSmallChunkedResponsePreservesTrailersAndModified204SuppressesBody() throws {
        for suppressBody in [false, true] {
            let listener = try Socket.listen(host: "127.0.0.1", port: 0)
            defer { listener.close() }
            let port = try listener.localPort()
            let completed = expectation(description: "chunked upstream response")
            Thread.detachNewThread {
                defer { completed.fulfill() }
                guard let upstream = try? listener.accept() else { return }
                defer { upstream.close() }
                guard (try? upstream.readHead()) != nil else { return }
                try? upstream.write(
                    Data(
                        ("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTrailer: X-Checksum\r\nConnection: close\r\n\r\n"
                            + "3\r\nabc\r\n0\r\nX-Checksum: retained\r\n\r\n").utf8))
            }
            let modifier: any Modifier = suppressBody ? StatusModifier(statusCode: 204) : ModifierGroup([])
            let proxy = ProxyServer(port: 0, modifier: modifier, logger: SilentLogger())
            let proxyPort = try proxy.start()
            defer { proxy.stop() }
            let client = try Socket.connect(host: "127.0.0.1", port: proxyPort)
            defer { client.close() }
            try client.write(
                Data(
                    "GET http://127.0.0.1:\(port)/ HTTP/1.1\r\nHost: 127.0.0.1:\(port)\r\nConnection: close\r\n\r\n"
                        .utf8))
            let response = String(decoding: try readToEnd(client), as: UTF8.self)
            if suppressBody {
                XCTAssertTrue(response.contains("204 No Content"), response)
                XCTAssertFalse(response.contains("abc"), response)
                XCTAssertFalse(response.lowercased().contains("transfer-encoding"), response)
            } else {
                XCTAssertTrue(response.contains("X-Checksum: retained"), response)
                XCTAssertTrue(response.contains("abc"), response)
            }
            wait(for: [completed], timeout: 4)
        }
    }

    func testSyntheticUpgradeRejectionClosesTheDownstreamConnection() throws {
        struct DeclineUpgrade: RequestInterceptor {
            func intercept(_ request: RequestContext) -> InterceptionAction {
                .drop(SyntheticResponse(statusCode: 403, reason: "Forbidden", body: Data("declined".utf8)))
            }
        }
        let proxy = ProxyServer(port: 0, logger: SilentLogger(), interceptor: DeclineUpgrade())
        let port = try proxy.start()
        defer { proxy.stop() }
        let client = try Socket.connect(host: "127.0.0.1", port: port)
        defer { client.close() }
        try client.write(
            Data(
                ("GET http://127.0.0.1:1/ HTTP/1.1\r\nHost: 127.0.0.1:1\r\n"
                    + "Connection: Upgrade\r\nUpgrade: fixture\r\n\r\n").utf8))
        client.shutdownWrite()
        let response = String(decoding: try readToEnd(client), as: UTF8.self)
        XCTAssertTrue(response.contains("403 Forbidden"), response)
        XCTAssertTrue(response.hasSuffix("declined"), response)
        XCTAssertTrue(response.lowercased().contains("connection: close"), response)
    }

    func testStoppingCancelsLongPacingWaitAndReleasesTheSession() throws {
        let listener = try Socket.listen(host: "127.0.0.1", port: 0)
        defer { listener.close() }
        let upstreamPort = try listener.localPort()
        let completed = expectation(description: "upstream sends paced body")
        Thread.detachNewThread {
            defer { completed.fulfill() }
            guard let upstream = try? listener.accept() else { return }
            defer { upstream.close() }
            guard (try? upstream.readHead()) != nil else { return }
            try? upstream.write(
                Data(
                    ("HTTP/1.1 200 OK\r\nContent-Length: 64\r\nConnection: close\r\n\r\n"
                        + String(repeating: "x", count: 64)).utf8))
        }
        var proxy: ProxyServer? = ProxyServer(port: 0, logger: SilentLogger(), downloadBytesPerSecond: 1)
        weak let releasedProxy = proxy
        let port = try XCTUnwrap(proxy).start()
        let client = try Socket.connect(host: "127.0.0.1", port: port)
        defer { client.close() }
        try client.write(
            Data(
                "GET http://127.0.0.1:\(upstreamPort)/ HTTP/1.1\r\nHost: 127.0.0.1:\(upstreamPort)\r\nConnection: close\r\n\r\n"
                    .utf8))
        let (head, _) = try client.readHead()
        XCTAssertTrue(head.startLine.contains("200"))
        proxy?.stop()
        proxy = nil
        let deadline = ContinuousClock.now.advanced(by: .seconds(2))
        while releasedProxy != nil, ContinuousClock.now < deadline { Thread.sleep(forTimeInterval: 0.01) }
        XCTAssertNil(releasedProxy, "stop must cancel the 64-second pacing sleep and release its task")
        wait(for: [completed], timeout: 4)
    }
}
