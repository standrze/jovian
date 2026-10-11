import Foundation
import XCTest

@testable import Jovian

final class JovianTests: XCTestCase {
    private struct SilentLogger: TrafficLogger {
        func record(_ entry: TrafficEntry) {}
    }

    private final class CapturingLogger: TrafficLogger, @unchecked Sendable {
        private let lock = NSLock()
        private var storage: [TrafficEntry] = []

        func record(_ entry: TrafficEntry) {
            lock.withLock { storage.append(entry) }
        }

        var last: TrafficEntry? {
            lock.withLock { storage.last }
        }
    }

    private struct HeaderReplacingInterceptor: RequestInterceptor {
        func intercept(_ request: RequestContext) -> InterceptionAction {
            var request = request
            request.head["X-Intercepted"] = "yes"
            return .forward(request)
        }
    }

    private struct DroppingInterceptor: RequestInterceptor {
        func intercept(_ request: RequestContext) -> InterceptionAction {
            .drop(
                SyntheticResponse(
                    statusCode: 451, reason: "Blocked by Test",
                    headers: [("Content-Type", "text/plain")],
                    body: Data("dropped".utf8)))
        }
    }

    private final class CapturedHead: @unchecked Sendable {
        private let lock = NSLock()
        private var value: HTTPHead?

        func set(_ head: HTTPHead) {
            lock.lock()
            value = head
            lock.unlock()
        }

        func get() -> HTTPHead? {
            lock.lock()
            defer { lock.unlock() }
            return value
        }
    }

    private func availablePort() throws -> UInt16 {
        let reservation = try Socket.listen(host: "127.0.0.1", port: 0)
        defer { reservation.close() }
        return try reservation.localPort()
    }

    private func connectEventually(port: UInt16) throws -> Socket {
        var lastError: Error = ProxyError.connection("proxy did not start")
        for _ in 0..<100 {
            do { return try Socket.connect(host: "127.0.0.1", port: port) } catch {
                lastError = error
                Thread.sleep(forTimeInterval: 0.01)
            }
        }
        throw lastError
    }

    private func readToEnd(_ socket: Socket) throws -> Data {
        var received = Data()
        while let chunk = try socket.read() { received.append(chunk) }
        return received
    }

    func testHTTPHeadCaseInsensitiveLookup() {
        let head = HTTPHead(startLine: "GET / HTTP/1.1", headers: [("Host", "example.com")])
        XCTAssertEqual(head["host"], "example.com")
    }

    func testModifierGroupUsesOrderAndScope() throws {
        let modifiers = ModifierGroup([
            HeaderModifier(scope: .request, name: "X-Test", value: "one"),
            HeaderModifier(scope: .request, name: "X-Test", value: "two"),
            HeaderModifier(scope: .response, name: "X-Proxy", value: "swift"),
        ])
        var request = RequestContext(
            method: "GET", target: "http://example.com/",
            head: HTTPHead(startLine: "GET / HTTP/1.1"))
        try modifiers.modify(request: &request)
        XCTAssertEqual(request.head["X-Test"], "two")
        var response = ResponseContext(
            requestMethod: "GET", target: request.target,
            head: HTTPHead(startLine: "HTTP/1.1 200 OK"))
        try modifiers.modify(response: &response)
        XCTAssertEqual(response.head["X-Proxy"], "swift")
        XCTAssertNil(response.head["X-Test"])
    }

    func testRuntimeConfigurationModifiesAndVerifies() throws {
        let runtime = RuntimeConfiguration()
        try runtime.replace(
            with: RuntimeConfigurationDocument(
                requestHeaders: ["X-Runtime": "request"],
                responseHeaders: ["X-Runtime": "response"],
                verifyStatus: ["example.com": 201]))
        var request = RequestContext(
            method: "GET", target: "http://example.com/",
            head: HTTPHead(startLine: "GET / HTTP/1.1"))
        runtime.modify(request: &request)
        XCTAssertEqual(request.head["X-Runtime"], "request")
        var response = ResponseContext(
            requestMethod: "GET", target: request.target,
            head: HTTPHead(startLine: "HTTP/1.1 200 OK"))
        runtime.modify(response: &response)
        XCTAssertEqual(response.head["X-Runtime"], "response")
        runtime.record(
            TrafficEntry(
                timestamp: Date(), method: "GET", target: request.target,
                status: 200, bytes: 10, durationMilliseconds: 1,
                transport: "http", error: nil))
        XCTAssertEqual(runtime.verificationFailures().count, 1)
        runtime.resetVerificationFailures()
        XCTAssertTrue(runtime.verificationFailures().isEmpty)
    }

    func testHARStoreProducesHARAndResets() throws {
        let store = HARStore(maximumEntries: 2)
        for status in [200, 201, 202] {
            store.record(
                TrafficEntry(
                    timestamp: Date(), method: "GET", target: "http://example.com/?page=2&empty=",
                    status: status, bytes: 12, durationMilliseconds: 3,
                    transport: "http", error: nil,
                    requestHeaders: [LoggedHeader(name: "Accept", value: "*/*")],
                    responseHeaders: [LoggedHeader(name: "Content-Type", value: "text/plain")]))
        }
        XCTAssertEqual(store.count(), 2)
        let root = try JSONSerialization.jsonObject(with: store.encodedHAR()) as? [String: Any]
        let log = root?["log"] as? [String: Any]
        let entries = log?["entries"] as? [[String: Any]]
        XCTAssertEqual(entries?.count, 2)
        XCTAssertEqual(entries?.compactMap { ($0["response"] as? [String: Any])?["status"] as? Int }, [201, 202])
        XCTAssertEqual(log?["version"] as? String, "1.2")
        let request = entries?.first?["request"] as? [String: Any]
        let response = entries?.first?["response"] as? [String: Any]
        XCTAssertEqual((request?["queryString"] as? [[String: String]])?.count, 2)
        XCTAssertGreaterThan(request?["headersSize"] as? Int ?? 0, 2)
        XCTAssertEqual((response?["content"] as? [String: Any])?["mimeType"] as? String, "text/plain")
        store.reset()
        XCTAssertEqual(store.count(), 0)
        let resetRoot = try JSONSerialization.jsonObject(with: store.encodedHAR()) as? [String: Any]
        let resetLog = resetRoot?["log"] as? [String: Any]
        XCTAssertEqual((resetLog?["entries"] as? [[String: Any]])?.count, 0)
    }

    func testHARFileLoggerKeepsGlobalAndWorkspaceRunsSeparate() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("jovian-har-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: root) }
        let global = root.appendingPathComponent("global/runs/one/traffic.har")
        let workspace = root.appendingPathComponent("ivory/runs/one/traffic.har")
        let logger = try HARFileLogger(url: global)
        func record(_ target: String) {
            logger.record(
                TrafficEntry(
                    timestamp: Date(), method: "GET", target: target, status: 200,
                    bytes: 2, durationMilliseconds: 1, transport: "http", error: nil))
        }
        func targets(in file: URL) throws -> [String] {
            let root = try JSONSerialization.jsonObject(with: Data(contentsOf: file)) as? [String: Any]
            let log = root?["log"] as? [String: Any]
            let entries = log?["entries"] as? [[String: Any]] ?? []
            return entries.compactMap { ($0["request"] as? [String: Any])?["url"] as? String }
        }

        record("http://global.test/first")
        try logger.setDestination(workspace)
        record("http://ivory.test/only")
        try logger.setDestination(global)
        record("http://global.test/second")

        XCTAssertEqual(try targets(in: global), ["http://global.test/first", "http://global.test/second"])
        XCTAssertEqual(try targets(in: workspace), ["http://ivory.test/only"])
        XCTAssertNil(logger.lastError)
        let attributes = try FileManager.default.attributesOfItem(atPath: workspace.path)
        XCTAssertEqual((attributes[.posixPermissions] as? NSNumber)?.intValue, 0o600)
    }

    func testNestedModifierDocumentDecodesAndFiltersByHost() throws {
        let json = Data(
            #"""
            {
              "modifier": {
                "type": "group",
                "modifiers": [
                  {"type":"header","scope":["request"],"name":"X-Global","value":"yes"},
                  {"type":"hostFilter","host":"example.com","modifier":
                    {"type":"header","scope":["request","response"],"name":"X-Filtered","value":"yes"}
                  }
                ]
              }
            }
            """#.utf8)
        let document = try JSONDecoder().decode(RuntimeConfigurationDocument.self, from: json)
        let runtime = RuntimeConfiguration()
        try runtime.replace(with: document)
        var matching = RequestContext(
            method: "GET", target: "https://example.com/path",
            head: HTTPHead(startLine: "GET /path HTTP/1.1"))
        runtime.modify(request: &matching)
        XCTAssertEqual(matching.head["X-Global"], "yes")
        XCTAssertEqual(matching.head["X-Filtered"], "yes")
        var other = RequestContext(
            method: "GET", target: "https://other.test/path",
            head: HTTPHead(startLine: "GET /path HTTP/1.1"))
        runtime.modify(request: &other)
        XCTAssertEqual(other.head["X-Global"], "yes")
        XCTAssertNil(other.head["X-Filtered"])
        let encoded = try JSONEncoder().encode(runtime.snapshot())
        XCTAssertNotNil(try JSONSerialization.jsonObject(with: encoded) as? [String: Any])
    }

    func testHeaderMutationRejectsResponseSplittingCharacters() throws {
        var head = HTTPHead(startLine: "GET / HTTP/1.1", headers: [("Safe", "original")])
        head["Safe"] = "changed\r\nInjected: yes"
        XCTAssertEqual(head["Safe"], "original")
        head["Bad Name"] = "value"
        XCTAssertNil(head["Bad Name"])
    }

    func testMethodAndURLFiltersStatusAndDelayModifiers() throws {
        let runtime = RuntimeConfiguration()
        let filteredStatus = ModifierSpec.methodFilter(
            methods: ["GET"],
            modifier:
                .urlFilter(
                    host: "example.com", pathPrefix: "/api",
                    modifier:
                        .status(statusCode: 418, reason: "Teapot")))
        try runtime.replace(
            with: RuntimeConfigurationDocument(
                modifier:
                    .group(modifiers: [filteredStatus, .delay(scope: ["response"], milliseconds: 5)])))
        var matching = ResponseContext(
            requestMethod: "GET", target: "https://example.com/api/items",
            head: HTTPHead(startLine: "HTTP/1.1 200 OK"))
        let start = ContinuousClock.now
        runtime.modify(response: &matching)
        XCTAssertEqual(matching.head.startLine, "HTTP/1.1 418 Teapot")
        XCTAssertGreaterThanOrEqual(start.duration(to: .now), .milliseconds(4))
        var wrongMethod = ResponseContext(
            requestMethod: "POST", target: matching.target,
            head: HTTPHead(startLine: "HTTP/1.1 200 OK"))
        runtime.modify(response: &wrongMethod)
        XCTAssertEqual(wrongMethod.head.startLine, "HTTP/1.1 200 OK")
        XCTAssertThrowsError(
            try RuntimeConfiguration().replace(
                with:
                    RuntimeConfigurationDocument(modifier: .delay(scope: ["response"], milliseconds: 60_001))))
    }

    func testProxyBasicAuthenticationAndRateLimiter() async throws {
        let credentials = ProxyCredentials(username: "tester", password: "correct horse")
        let token = Data("tester:correct horse".utf8).base64EncodedString()
        let authorized = HTTPHead(
            startLine: "GET / HTTP/1.1",
            headers: [("Proxy-Authorization", "Basic \(token)")])
        XCTAssertTrue(credentials.authorizes(authorized))
        let wrong = HTTPHead(
            startLine: "GET / HTTP/1.1",
            headers: [("Proxy-Authorization", "Basic \(Data("tester:wrong".utf8).base64EncodedString())")])
        XCTAssertFalse(credentials.authorizes(wrong))
        XCTAssertFalse(credentials.authorizes(HTTPHead(startLine: "GET / HTTP/1.1")))

        var limiter = TransferPacer(bytesPerSecond: 10_000)
        let start = ContinuousClock.now
        try await limiter.pace(1_000)
        XCTAssertGreaterThanOrEqual(start.duration(to: .now), .milliseconds(90))
    }

    func testQueryStringAndCookieModifiers() throws {
        let runtime = RuntimeConfiguration()
        try runtime.replace(
            with: RuntimeConfigurationDocument(
                modifier: .group(modifiers: [
                    .queryString(name: "page", value: "two words"),
                    .cookie(scope: ["request"], name: "session", value: "replacement"),
                    .cookie(scope: ["response"], name: "theme", value: "dark"),
                ])))
        var request = RequestContext(
            method: "GET", target: "http://example.com/path?page=old&keep=yes",
            head: HTTPHead(
                startLine: "GET /path HTTP/1.1",
                headers: [("Cookie", "session=old; untouched=value")]))
        runtime.modify(request: &request)
        let components = URLComponents(string: request.target)
        XCTAssertEqual(components?.queryItems?.first(where: { $0.name == "page" })?.value, "two words")
        XCTAssertEqual(components?.queryItems?.first(where: { $0.name == "keep" })?.value, "yes")
        XCTAssertEqual(request.head["Cookie"], "untouched=value; session=replacement")

        var response = ResponseContext(
            requestMethod: "GET", target: request.target,
            head: HTTPHead(
                startLine: "HTTP/1.1 200 OK",
                headers: [
                    ("Set-Cookie", "theme=light; Path=/; Secure"),
                    ("Set-Cookie", "other=preserved; HttpOnly"),
                ]))
        runtime.modify(response: &response)
        XCTAssertEqual(
            response.head.values(for: "Set-Cookie"),
            ["theme=dark; Path=/; Secure", "other=preserved; HttpOnly"])

        let removal = RuntimeConfiguration()
        try removal.replace(
            with: RuntimeConfigurationDocument(
                modifier: .group(modifiers: [
                    .queryString(name: "page", value: nil),
                    .cookie(scope: ["request", "response"], name: "session", value: nil),
                ])))
        removal.modify(request: &request)
        XCTAssertNil(URLComponents(string: request.target)?.queryItems?.first(where: { $0.name == "page" }))
        XCTAssertEqual(request.head["Cookie"], "untouched=value")
    }

    func testBodyModifierRespectsScopeAndStreamingFallback() throws {
        let runtime = RuntimeConfiguration()
        try runtime.replace(
            with: RuntimeConfigurationDocument(
                modifier:
                    .body(scope: ["request", "response"], content: "replacement", contentType: "text/plain")))
        var request = RequestContext(
            method: "POST", target: "http://example.com/",
            head: HTTPHead(startLine: "POST / HTTP/1.1"),
            body: Data("original".utf8))
        runtime.modify(request: &request)
        XCTAssertEqual(String(data: request.body!, encoding: .utf8), "replacement")
        XCTAssertEqual(request.head["Content-Type"], "text/plain")
        var response = ResponseContext(
            requestMethod: "POST", target: request.target,
            head: HTTPHead(startLine: "HTTP/1.1 200 OK"),
            body: Data("old response".utf8))
        runtime.modify(response: &response)
        XCTAssertEqual(String(data: response.body!, encoding: .utf8), "replacement")
        var streamed = ResponseContext(
            requestMethod: "GET", target: request.target,
            head: HTTPHead(startLine: "HTTP/1.1 200 OK"), body: nil)
        runtime.modify(response: &streamed)
        XCTAssertNil(streamed.body)
        var headResponse = ResponseContext(
            requestMethod: "HEAD", target: request.target,
            head: HTTPHead(startLine: "HTTP/1.1 200 OK"), body: Data())
        runtime.modify(response: &headResponse)
        XCTAssertEqual(headResponse.body, Data())
    }

    func testTargetedFailureAndRuntimeTrafficRates() throws {
        let runtime = RuntimeConfiguration()
        try runtime.replace(
            with: RuntimeConfigurationDocument(
                modifier: .urlFilter(
                    host: "example.com", pathPrefix: "/unavailable",
                    modifier:
                        .failure(
                            statusCode: 503, reason: "Planned Outage", content: "try later", contentType: "text/plain")),
                uploadBytesPerSecond: 2_000,
                downloadBytesPerSecond: 3_000))
        var matching = RequestContext(
            method: "GET", target: "https://example.com/unavailable/api",
            head: HTTPHead(startLine: "GET /unavailable/api HTTP/1.1"))
        runtime.modify(request: &matching)
        XCTAssertEqual(matching.syntheticResponse?.statusCode, 503)
        XCTAssertEqual(matching.syntheticResponse?.reason, "Planned Outage")
        XCTAssertEqual(String(data: matching.syntheticResponse!.body, encoding: .utf8), "try later")
        var other = RequestContext(
            method: "GET", target: "https://example.com/healthy",
            head: HTTPHead(startLine: "GET /healthy HTTP/1.1"))
        runtime.modify(request: &other)
        XCTAssertNil(other.syntheticResponse)
        XCTAssertEqual(runtime.trafficRates().upload, 2_000)
        XCTAssertEqual(runtime.trafficRates().download, 3_000)
        XCTAssertThrowsError(
            try RuntimeConfiguration().replace(
                with:
                    RuntimeConfigurationDocument(downloadBytesPerSecond: 0)))
    }

    func testIPFilterUsesRemoteSocketAddressAndCORSModifier() throws {
        let runtime = RuntimeConfiguration()
        try runtime.replace(
            with: RuntimeConfigurationDocument(
                modifier: .group(modifiers: [
                    .ipFilter(
                        networks: ["127.0.0.0/8", "2001:db8::/32"],
                        modifier:
                            .failure(statusCode: 403, reason: "Local Rule", content: nil, contentType: nil)),
                    .cors(
                        allowOrigin: "https://client.example", allowMethods: ["GET", "POST"],
                        allowHeaders: ["Content-Type"], exposeHeaders: ["X-Trace"],
                        allowCredentials: true, maxAge: 600),
                ])))
        var local = RequestContext(
            method: "GET", target: "http://example.com/",
            head: HTTPHead(startLine: "GET / HTTP/1.1"), remoteAddress: "127.0.0.1")
        runtime.modify(request: &local)
        XCTAssertEqual(local.syntheticResponse?.statusCode, 403)
        var remote = RequestContext(
            method: "GET", target: local.target,
            head: HTTPHead(startLine: "GET / HTTP/1.1"), remoteAddress: "10.0.0.1")
        runtime.modify(request: &remote)
        XCTAssertNil(remote.syntheticResponse)
        var ipv6 = RequestContext(
            method: "GET", target: local.target,
            head: HTTPHead(startLine: "GET / HTTP/1.1"), remoteAddress: "2001:db8::42")
        runtime.modify(request: &ipv6)
        XCTAssertEqual(ipv6.syntheticResponse?.statusCode, 403)

        var response = ResponseContext(
            requestMethod: "GET", target: local.target,
            head: HTTPHead(startLine: "HTTP/1.1 200 OK"),
            remoteAddress: "10.0.0.1")
        runtime.modify(response: &response)
        XCTAssertEqual(response.head["Access-Control-Allow-Origin"], "https://client.example")
        XCTAssertEqual(response.head["Access-Control-Allow-Credentials"], "true")
        XCTAssertEqual(response.head["Access-Control-Max-Age"], "600")
        XCTAssertEqual(response.head["Vary"], "Origin")
        XCTAssertThrowsError(
            try RuntimeConfiguration().replace(
                with:
                    RuntimeConfigurationDocument(
                        modifier: .ipFilter(
                            networks: ["127.0.0.0/99"],
                            modifier:
                                .status(statusCode: 500, reason: nil)))))
        XCTAssertThrowsError(
            try RuntimeConfiguration().replace(
                with:
                    RuntimeConfigurationDocument(
                        modifier: .cors(
                            allowOrigin: "*", allowMethods: [],
                            allowHeaders: [], exposeHeaders: [], allowCredentials: true, maxAge: nil))))
    }

    func testRequestAndResponseHeaderVerifiers() throws {
        let runtime = RuntimeConfiguration()
        try runtime.replace(
            with: RuntimeConfigurationDocument(
                verifyRequestHeaders: ["example.com": [HeaderExpectation(name: "X-Request", value: "expected")]],
                verifyResponseHeaders: [
                    "example.com": [
                        HeaderExpectation(name: "X-Present"),
                        HeaderExpectation(name: "X-Exact", value: "right"),
                    ]
                ]))
        runtime.record(
            TrafficEntry(
                timestamp: Date(), method: "GET", target: "https://example.com/path",
                status: 200, bytes: 0, durationMilliseconds: 1, transport: "http", error: nil,
                requestHeaders: [LoggedHeader(name: "x-request", value: "wrong")],
                responseHeaders: [LoggedHeader(name: "X-Exact", value: "right")]))
        let failures = runtime.verificationFailures()
        XCTAssertEqual(failures.count, 2)
        XCTAssertTrue(failures.contains { $0.message.contains("X-Request got wrong, want expected") })
        XCTAssertTrue(failures.contains { $0.message.contains("missing X-Present") })
        XCTAssertThrowsError(
            try RuntimeConfiguration().replace(
                with:
                    RuntimeConfigurationDocument(verifyResponseHeaders: [
                        "example.com": [
                            HeaderExpectation(name: "Bad Name")
                        ]
                    ])))
    }

    func testRequestInterceptorCanReplaceRequestBeforeUpstreamForwarding() throws {
        let upstreamListener = try Socket.listen(host: "127.0.0.1", port: 0)
        let upstreamPort = try upstreamListener.localPort()
        let capturedHead = CapturedHead()
        let upstreamHandled = expectation(description: "upstream handled request")
        Thread.detachNewThread {
            defer {
                upstreamListener.close()
                upstreamHandled.fulfill()
            }
            guard let connection = try? upstreamListener.accept() else { return }
            defer { connection.close() }
            if let (head, _) = try? connection.readHead() {
                capturedHead.set(head)
                try? connection.write(
                    Data(
                        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK".utf8))
            }
        }

        let proxyPort = try availablePort()
        let proxy = ProxyServer(
            port: proxyPort, logger: SilentLogger(),
            interceptor: HeaderReplacingInterceptor())
        Thread.detachNewThread { try? proxy.run() }
        defer { proxy.stop() }

        let client = try connectEventually(port: proxyPort)
        defer { client.close() }
        try client.write(
            Data(
                ("GET http://127.0.0.1:\(upstreamPort)/through HTTP/1.1\r\n"
                    + "Host: 127.0.0.1:\(upstreamPort)\r\nConnection: close\r\n\r\n").utf8))
        let response = try readToEnd(client)

        wait(for: [upstreamHandled], timeout: 2)
        XCTAssertEqual(capturedHead.get()?["X-Intercepted"], "yes")
        XCTAssertTrue(String(decoding: response, as: UTF8.self).contains("200 OK"))
    }

    func testConnectTunnelsOpaqueBytesWithoutTLSInterception() throws {
        let upstreamListener = try Socket.listen(host: "127.0.0.1", port: 0)
        let upstreamPort = try upstreamListener.localPort()
        let upstreamHandled = expectation(description: "upstream echoed tunnel bytes")
        Thread.detachNewThread {
            defer {
                upstreamListener.close()
                upstreamHandled.fulfill()
            }
            guard let connection = try? upstreamListener.accept() else { return }
            defer { connection.close() }
            if let payload = try? connection.read() { try? connection.write(payload) }
        }

        let proxy = ProxyServer(port: 0, logger: SilentLogger())
        let proxyPort = try proxy.start()
        defer { proxy.stop() }

        let client = try connectEventually(port: proxyPort)
        defer { client.close() }
        try client.write(Data("CONNECT 127.0.0.1:\(upstreamPort) HTTP/1.1\r\n\r\n".utf8))
        let (response, buffered) = try client.readHead()
        XCTAssertEqual(response.startLine, "HTTP/1.1 200 Connection Established")
        XCTAssertTrue(buffered.isEmpty)

        let payload = Data([0, 1, 2, 255])
        try client.write(payload)
        client.shutdownWrite()
        XCTAssertEqual(try readToEnd(client), payload)
        wait(for: [upstreamHandled], timeout: 2)
    }

    func testTrafficHistoryCapturesRequestAndChunkedResponseBodies() throws {
        let upstreamListener = try Socket.listen(host: "127.0.0.1", port: 0)
        let upstreamPort = try upstreamListener.localPort()
        let upstreamHandled = expectation(description: "upstream handled body request")
        Thread.detachNewThread {
            defer {
                upstreamListener.close()
                upstreamHandled.fulfill()
            }
            guard let connection = try? upstreamListener.accept() else { return }
            defer { connection.close() }
            guard let (head, buffered) = try? connection.readHead() else { return }
            let expectedLength = Int(head["Content-Length"] ?? "0") ?? 0
            var body = buffered
            while body.count < expectedLength, let chunk = try? connection.read(maximum: expectedLength - body.count) {
                body.append(chunk)
            }
            guard String(decoding: body.prefix(expectedLength), as: UTF8.self) == "{\"hello\":\"world\"}" else {
                return
            }
            try? connection.write(
                Data(
                    ("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n"
                        + "Content-Type: application/json\r\n\r\n8\r\n{\"ok\":1}\r\n0\r\n\r\n").utf8))
        }

        let logger = CapturingLogger()
        let proxyPort = try availablePort()
        let proxy = ProxyServer(port: proxyPort, logger: logger)
        Thread.detachNewThread { try? proxy.run() }
        defer { proxy.stop() }

        let client = try connectEventually(port: proxyPort)
        defer { client.close() }
        let requestBody = Data("{\"hello\":\"world\"}".utf8)
        try client.write(
            Data(
                ("POST http://127.0.0.1:\(upstreamPort)/body HTTP/1.1\r\n" + "Host: 127.0.0.1:\(upstreamPort)\r\n"
                    + "Content-Type: application/json\r\nContent-Length: \(requestBody.count)\r\nConnection: close\r\n\r\n")
                    .utf8) + requestBody)
        _ = try readToEnd(client)

        wait(for: [upstreamHandled], timeout: 2)
        XCTAssertEqual(logger.last?.requestBody, requestBody)
        XCTAssertEqual(logger.last?.responseBody, Data("{\"ok\":1}".utf8))
        XCTAssertEqual(logger.last?.requestBodyTruncated, false)
        XCTAssertEqual(logger.last?.responseBodyTruncated, false)
    }

    func testRequestInterceptorCanDropWithoutConnectingUpstream() throws {
        let proxyPort = try availablePort()
        let proxy = ProxyServer(
            port: proxyPort, logger: SilentLogger(),
            interceptor: DroppingInterceptor())
        Thread.detachNewThread { try? proxy.run() }
        defer { proxy.stop() }

        let client = try connectEventually(port: proxyPort)
        defer { client.close() }
        try client.write(
            Data(
                ("GET http://127.0.0.1:1/blocked HTTP/1.1\r\n" + "Host: 127.0.0.1:1\r\nConnection: close\r\n\r\n").utf8)
        )
        let response = String(decoding: try readToEnd(client), as: UTF8.self)

        XCTAssertTrue(response.contains("451 Blocked by Test"))
        XCTAssertTrue(response.hasSuffix("dropped"))
    }

    func testHopByHopHeaderSanitizationAndUpgradePreservation() {
        var ordinary = HTTPHead(
            startLine: "GET / HTTP/1.1",
            headers: [
                ("Connection", "keep-alive, X-Private"), ("Keep-Alive", "timeout=5"),
                ("X-Private", "remove"), ("Proxy-Connection", "keep-alive"),
                ("Proxy-Authorization", "secret"), ("TE", "trailers"),
                ("Transfer-Encoding", "chunked"), ("Trailer", "X-Checksum"),
                ("Upgrade", "websocket"),
            ])
        ordinary.removeHopByHopHeaders()
        for name in [
            "Connection", "Keep-Alive", "X-Private", "Proxy-Connection",
            "Proxy-Authorization", "TE", "Upgrade",
        ] {
            XCTAssertNil(ordinary[name], "expected \(name) to be removed")
        }
        XCTAssertEqual(ordinary["Transfer-Encoding"], "chunked")
        XCTAssertEqual(ordinary["Trailer"], "X-Checksum")

        var upgrade = HTTPHead(
            startLine: "GET /chat HTTP/1.1",
            headers: [
                ("Connection", "Upgrade, X-Remove"), ("Upgrade", "websocket"),
                ("X-Remove", "private"),
            ])
        upgrade.removeHopByHopHeaders(preservingUpgrade: true)
        XCTAssertEqual(upgrade["Upgrade"], "websocket")
        XCTAssertNil(upgrade["Connection"])
        XCTAssertNil(upgrade["X-Remove"])
    }

    func testCanonicalMartianFIFOHeaderAndStatusConfiguration() throws {
        let json = Data(
            #"""
            {
              "fifo.Group": {
                "scope": ["request", "response"],
                "modifiers": [
                  {"header.Modifier":{"scope":["request"],"name":"X-Martian-Test","value":"true"}},
                  {"status.Modifier":{"scope":["response"],"statusCode":201}},
                  {"header.Modifier":{"scope":["response"],"name":"X-Order","value":"last"}}
                ]
              }
            }
            """#.utf8)
        let modifier = try MartianConfigurationParser.parse(json)
        var request = RequestContext(
            method: "GET", target: "http://example.com/",
            head: HTTPHead(startLine: "GET / HTTP/1.1"))
        try modifier.modify(request: &request)
        XCTAssertEqual(request.head["X-Martian-Test"], "true")
        XCTAssertNil(request.head["X-Order"])
        var response = ResponseContext(
            requestMethod: "GET", target: request.target,
            head: HTTPHead(startLine: "HTTP/1.1 200 OK"))
        try modifier.modify(response: &response)
        XCTAssertEqual(response.head.startLine, "HTTP/1.1 201 Created")
        XCTAssertEqual(response.head["X-Order"], "last")
        XCTAssertNil(response.head["X-Martian-Test"])
    }

    func testCanonicalMartianBodyAndQueryStringConfiguration() throws {
        let bodyJSON = Data(
            #"{"body.Modifier":{"scope":["response"],"contentType":"application/octet-stream","body":"AP9iaW5hcnk="}}"#
                .utf8)
        let bodyModifier = try MartianConfigurationParser.parse(bodyJSON)
        var response = ResponseContext(
            requestMethod: "GET", target: "http://example.com/",
            head: HTTPHead(startLine: "HTTP/1.1 200 OK"), body: Data("old".utf8))
        try bodyModifier.modify(response: &response)
        XCTAssertEqual(response.body, Data([0x00, 0xff, 0x62, 0x69, 0x6e, 0x61, 0x72, 0x79]))
        XCTAssertEqual(response.head["Content-Type"], "application/octet-stream")

        let queryJSON = Data(#"{"querystring.Modifier":{"scope":["request"],"name":"q","value":"martian"}}"#.utf8)
        let queryModifier = try MartianConfigurationParser.parse(queryJSON)
        var request = RequestContext(
            method: "GET", target: "http://example.com/?q=old",
            head: HTTPHead(startLine: "GET / HTTP/1.1"))
        try queryModifier.modify(request: &request)
        XCTAssertEqual(URLComponents(string: request.target)?.queryItems?.first?.value, "martian")
    }

    func testCanonicalMartianParserRejectsUnknownAmbiguousAndInvalidScopes() {
        XCTAssertThrowsError(try MartianConfigurationParser.parse(Data(#"{"unknown.Modifier":{}}"#.utf8)))
        XCTAssertThrowsError(
            try MartianConfigurationParser.parse(Data(#"{"header.Modifier":{},"status.Modifier":{}}"#.utf8)))
        XCTAssertThrowsError(
            try MartianConfigurationParser.parse(
                Data(#"{"status.Modifier":{"scope":["request"],"statusCode":200}}"#.utf8)))
        XCTAssertThrowsError(
            try MartianConfigurationParser.parse(Data(#"{"fifo.Group":{"aggregateErrors":true,"modifiers":[]}}"#.utf8)))
    }

    func testRuntimeStoresCanonicalMartianConfigurationForGET() throws {
        let json = Data(#"{"header.Modifier":{"scope":["request"],"name":"X-Canonical","value":"yes"}}"#.utf8)
        let runtime = RuntimeConfiguration()
        try runtime.replace(martianJSON: json)
        let stored = try JSONSerialization.jsonObject(with: runtime.encodedConfiguration()) as? [String: Any]
        XCTAssertNotNil(stored?["header.Modifier"])
        var request = RequestContext(
            method: "GET", target: "http://example.com/",
            head: HTTPHead(startLine: "GET / HTTP/1.1"))
        runtime.modify(request: &request)
        XCTAssertEqual(request.head["X-Canonical"], "yes")
    }
}
