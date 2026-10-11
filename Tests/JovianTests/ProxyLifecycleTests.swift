import Foundation
import XCTest

@testable import Jovian

final class ProxyLifecycleTests: XCTestCase {
    private struct SilentLogger: TrafficLogger { func record(_ entry: TrafficEntry) {} }

    /// Interception runs on a worker thread; shutdown must wake it before joining that worker.
    private final class PendingInterceptor: RequestInterceptor, @unchecked Sendable {
        let entered: XCTestExpectation
        private let condition = NSCondition()
        private var cancelled = false

        init(entered: XCTestExpectation) { self.entered = entered }

        func intercept(_ request: RequestContext) -> InterceptionAction {
            condition.lock()
            defer { condition.unlock() }
            entered.fulfill()
            while !cancelled { condition.wait() }
            return .drop(SyntheticResponse(statusCode: 503, reason: "Stopped"))
        }

        func cancelPending() {
            condition.lock()
            cancelled = true
            condition.broadcast()
            condition.unlock()
        }
    }

    func testConcurrentShutdownWaitsForPendingInterceptionAndReleasesListener() async throws {
        let entered = expectation(description: "request is waiting for interception")
        let proxy = ProxyServer(
            port: 0, logger: SilentLogger(), interceptor: PendingInterceptor(entered: entered))
        let port = try proxy.start()
        defer { proxy.stop() }
        let client = try Socket.connect(host: "127.0.0.1", port: port)
        defer { client.close() }
        try client.write(
            Data("GET http://127.0.0.1:1/ HTTP/1.1\r\nHost: 127.0.0.1:1\r\nConnection: close\r\n\r\n".utf8))
        await fulfillment(of: [entered], timeout: 3)

        proxy.stop()
        async let first: Void = proxy.shutdown()
        async let second: Void = proxy.shutdown()
        _ = await (first, second)

        XCTAssertThrowsError(try proxy.start())
        let replacement = try Socket.listen(host: "127.0.0.1", port: port)
        replacement.close()
    }

    func testShutdownClosesIdleUpstreamConnectionBeforeReturning() async throws {
        let listener = try Socket.listen(host: "127.0.0.1", port: 0)
        defer { listener.close() }
        let upstreamPort = try listener.localPort()
        let upstreamClosed = expectation(description: "pooled upstream receives end of stream")
        Thread.detachNewThread {
            do {
                let upstream = try listener.accept()
                defer { upstream.close() }
                _ = try upstream.readHead()
                try upstream.write(
                    Data("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\nok".utf8))
                XCTAssertNil(try upstream.read())
                upstreamClosed.fulfill()
            } catch {
                XCTFail("upstream fixture failed: \(error)")
                upstreamClosed.fulfill()
            }
        }
        let proxy = ProxyServer(port: 0, logger: SilentLogger())
        let port = try proxy.start()
        defer { proxy.stop() }
        let client = try Socket.connect(host: "127.0.0.1", port: port)
        defer { client.close() }
        try client.write(
            Data(
                "GET http://127.0.0.1:\(upstreamPort)/ HTTP/1.1\r\nHost: 127.0.0.1:\(upstreamPort)\r\nConnection: close\r\n\r\n"
                    .utf8))
        var response = Data()
        while let bytes = try client.read() { response.append(bytes) }
        XCTAssertTrue(String(decoding: response, as: UTF8.self).hasSuffix("ok"))

        await proxy.shutdown()
        await fulfillment(of: [upstreamClosed], timeout: 3)
    }

    func testShutdownBeforeStartIsIdempotentAndRejectsStartup() async throws {
        let proxy = ProxyServer(port: 0, logger: SilentLogger())
        await proxy.shutdown()
        await proxy.shutdown()
        proxy.stop()
        XCTAssertThrowsError(try proxy.start())
    }
}
