import Foundation
import XCTest

@testable import Jovian

final class ProxyDrainTests: XCTestCase {
    private struct SilentLogger: TrafficLogger { func record(_ entry: TrafficEntry) {} }

    func testGracefulShutdownFinishesCurrentResponseAndRejectsPipelinedRequest() async throws {
        let listener = try Socket.listen(host: "127.0.0.1", port: 0)
        defer { listener.close() }
        let originPort = try listener.localPort()
        let requestReceived = expectation(description: "origin receives the current request")
        let originClosed = expectation(description: "origin receives no second request")
        let releaseResponse = DispatchSemaphore(value: 0)
        Thread.detachNewThread {
            defer { originClosed.fulfill() }
            do {
                let origin = try listener.accept()
                defer { origin.close() }
                _ = try origin.readHead()
                requestReceived.fulfill()
                guard releaseResponse.wait(timeout: .now() + 3) == .success else {
                    XCTFail("response was never released")
                    return
                }
                try origin.write(
                    Data("HTTP/1.1 200 OK\r\nContent-Length: 8\r\nConnection: keep-alive\r\n\r\nfinished".utf8))
                XCTAssertNil(try origin.read(), "draining must not forward the queued request")
            } catch { XCTFail("origin fixture failed: \(error)") }
        }
        let proxy = ProxyServer(port: 0, logger: SilentLogger())
        let port = try proxy.start()
        defer { proxy.stop() }
        let client = try Socket.connect(host: "127.0.0.1", port: port)
        defer { client.close() }
        let request = "GET http://127.0.0.1:\(originPort)/ HTTP/1.1\r\nHost: 127.0.0.1:\(originPort)\r\n\r\n"
        try client.write(Data((request + request).utf8))
        await fulfillment(of: [requestReceived], timeout: 3)

        let draining = Task { await proxy.shutdown(gracePeriod: .seconds(2)) }
        try await waitForDrain(proxy)
        releaseResponse.signal()
        let response = String(decoding: try readToEnd(client), as: UTF8.self)
        await draining.value

        XCTAssertTrue(response.hasSuffix("finished"), response)
        XCTAssertEqual(response.components(separatedBy: "HTTP/1.1").count - 1, 1)
        await fulfillment(of: [originClosed], timeout: 3)
        let replacement = try Socket.listen(host: "127.0.0.1", port: port)
        replacement.close()
    }

    func testGraceDeadlineClosesAnActiveTunnel() async throws {
        let listener = try Socket.listen(host: "127.0.0.1", port: 0)
        defer { listener.close() }
        let originPort = try listener.localPort()
        let originClosed = expectation(description: "tunnel origin closes on grace deadline")
        Thread.detachNewThread {
            defer { originClosed.fulfill() }
            do {
                let origin = try listener.accept()
                defer { origin.close() }
                XCTAssertNil(try origin.read())
            } catch { XCTFail("tunnel fixture failed: \(error)") }
        }
        let proxy = ProxyServer(port: 0, logger: SilentLogger())
        let port = try proxy.start()
        defer { proxy.stop() }
        let client = try Socket.connect(host: "127.0.0.1", port: port)
        defer { client.close() }
        try client.write(Data("CONNECT 127.0.0.1:\(originPort) HTTP/1.1\r\n\r\n".utf8))
        let (head, _) = try client.readHead()
        XCTAssertTrue(head.startLine.contains("200"))

        let started = ContinuousClock.now
        await proxy.shutdown(gracePeriod: .milliseconds(30))

        XCTAssertLessThan(started.duration(to: .now), .seconds(2))
        XCTAssertNil(try client.read())
        await fulfillment(of: [originClosed], timeout: 3)
    }

    func testImmediateStopInterruptsAnExistingGracefulDrain() async throws {
        let listener = try Socket.listen(host: "127.0.0.1", port: 0)
        defer { listener.close() }
        let originPort = try listener.localPort()
        let originClosed = expectation(description: "forced drain closes origin")
        Thread.detachNewThread {
            defer { originClosed.fulfill() }
            do {
                let origin = try listener.accept()
                defer { origin.close() }
                XCTAssertNil(try origin.read())
            } catch { XCTFail("forced drain fixture failed: \(error)") }
        }
        let proxy = ProxyServer(port: 0, logger: SilentLogger())
        let port = try proxy.start()
        defer { proxy.stop() }
        let client = try Socket.connect(host: "127.0.0.1", port: port)
        defer { client.close() }
        try client.write(Data("CONNECT 127.0.0.1:\(originPort) HTTP/1.1\r\n\r\n".utf8))
        _ = try client.readHead()

        let draining = Task { await proxy.shutdown(gracePeriod: .seconds(30)) }
        try await waitForDrain(proxy)
        let started = ContinuousClock.now
        proxy.stop()
        await draining.value

        XCTAssertLessThan(started.duration(to: .now), .seconds(2))
        await fulfillment(of: [originClosed], timeout: 3)
    }

    func testGracefulShutdownClosesIdleClientWithoutWaitingForGraceDeadline() async throws {
        let proxy = ProxyServer(port: 0, logger: SilentLogger())
        let port = try proxy.start()
        defer { proxy.stop() }
        let client = try Socket.connect(host: "127.0.0.1", port: port)
        defer { client.close() }

        let started = ContinuousClock.now
        await proxy.shutdown(gracePeriod: .seconds(30))

        XCTAssertLessThan(started.duration(to: .now), .seconds(2))
    }

    private func waitForDrain(_ proxy: ProxyServer) async throws {
        let deadline = ContinuousClock.now.advanced(by: .seconds(2))
        while !proxy.transport.isClosing {
            guard ContinuousClock.now < deadline else { throw ProxyError.connection("drain did not start") }
            await Task.yield()
        }
    }

    private func readToEnd(_ client: Socket) throws -> Data {
        var result = Data()
        while let bytes = try client.read() { result.append(bytes) }
        return result
    }
}
