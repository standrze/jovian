import Foundation
import XCTest

@testable import Jovian

final class MartianCompletionTests: XCTestCase {
    private final class Messages: @unchecked Sendable {
        let lock = NSLock()
        var values: [String] = []
        func append(_ value: String) { lock.withLock { values.append(value) } }
    }

    private func parse(_ node: [String: Any], sink: @escaping @Sendable (String) -> Void = { _ in }) throws
        -> any Modifier
    {
        try MartianConfigurationParser.parse(JSONSerialization.data(withJSONObject: node), logSink: sink)
    }

    private func request() -> RequestContext {
        RequestContext(
            method: "POST", target: "http://fixture.test/original?x=1",
            head: HTTPHead(
                startLine: "POST /original?x=1 HTTP/1.1",
                headers: [
                    ("Cookie", "same=original"), ("Content-Type", "application/json"),
                    ("Authorization", "secret-header"),
                ]), body: Data(#"{"password":"secret-body","nested":[{"token":"nested-secret","ok":1}]}"#.utf8))
    }

    func testPrioritySortsDescendingAndLaterTiesFirstInBothDirections() throws {
        func child(_ priority: Int?, _ value: String) -> [String: Any] {
            var node: [String: Any] = ["modifier": ["header.Append": ["name": "X-Order", "value": value]]]
            node["priority"] = priority
            return node
        }
        let modifier = try parse([
            "priority.Group": [
                "modifiers": [
                    child(10, "first"), child(-1, "last"), child(10, "newer"), child(nil, "default"),
                ]
            ]
        ])
        var request = request()
        try modifier.modify(request: &request)
        var response = ResponseContext(
            requestMethod: "POST", target: request.target, head: HTTPHead(startLine: "HTTP/1.1 200 OK"))
        try modifier.modify(response: &response)
        XCTAssertEqual(request.head.values(for: "X-Order"), ["newer", "first", "default", "last"])
        XCTAssertEqual(response.head.values(for: "X-Order"), request.head.values(for: "X-Order"))
        for value: Any in [true, 1.5, "1"] {
            XCTAssertThrowsError(
                try parse([
                    "priority.Group": [
                        "modifiers": [
                            [
                                "priority": value, "modifier": ["noop.Modifier": [:]],
                            ]
                        ]
                    ]
                ]))
        }
    }

    func testStashPreservesURLBeforeRewriteAndUsesRequestHeaderOnResponse() throws {
        let modifier = try parse([
            "fifo.Group": [
                "modifiers": [
                    ["stash.Modifier": ["headerName": "X-Original", "scope": ["request", "response"]]],
                    ["url.Modifier": ["path": "/rewritten"]],
                ]
            ]
        ])
        var request = request()
        let original = request.target
        try modifier.modify(request: &request)
        XCTAssertTrue(request.target.contains("/rewritten"))
        XCTAssertEqual(request.head["X-Original"], original)
        var response = ResponseContext(
            requestMethod: "POST", target: request.target,
            head: HTTPHead(startLine: "HTTP/1.1 200 OK"), requestHead: request.head)
        try modifier.modify(response: &response)
        XCTAssertEqual(response.head["X-Original"], original)
        XCTAssertThrowsError(try parse(["stash.Modifier": ["headerName": "X-URL", "scope": ["response"]]]))
        XCTAssertThrowsError(try parse(["stash.Modifier": ["headerName": "bad\nname"]]))
    }

    func testCanonicalCookiesAppendAndSerializeAttributes() throws {
        let modifier = try parse([
            "cookie.Modifier": [
                "name": "same", "value": "new value", "path": "/test", "domain": ".fixture.test",
                "expires": "2027-04-12T23:20:50.52Z", "maxAge": 86400, "secure": true, "httpOnly": true,
            ]
        ])
        var request = request()
        try modifier.modify(request: &request)
        XCTAssertEqual(request.head["Cookie"], "same=original; same=\"new value\"")
        var response = ResponseContext(
            requestMethod: "POST", target: request.target,
            head: HTTPHead(startLine: "HTTP/1.1 200 OK", headers: [("Set-Cookie", "old=1")]))
        try modifier.modify(response: &response)
        XCTAssertEqual(
            response.head.values(for: "Set-Cookie"),
            [
                "old=1",
                "same=\"new value\"; Path=/test; Domain=fixture.test; Expires=Mon, 12 Apr 2027 23:20:50 GMT; Max-Age=86400; HttpOnly; Secure",
            ])
        let deletion = try MartianCookieModifier(name: "same", maxAge: -1)
        XCTAssertEqual(deletion.responseValue, "same=; Max-Age=0")
        XCTAssertEqual(try MartianCookieModifier(name: "same").responseValue, "same=")
    }

    func testCookieInvalidInputIsRejectedAtomicallyAndScopeWorks() throws {
        let runtime = RuntimeConfiguration()
        try runtime.replace(
            martianJSON: JSONSerialization.data(withJSONObject: [
                "cookie.Modifier": [
                    "name": "only-response", "value": "1", "scope": ["response"],
                ]
            ]))
        for fields: [String: Any] in [
            ["name": "bad name"], ["name": "x", "value": "x;bad=1"], ["name": "x", "domain": "x\r\ny"],
            ["name": "x", "expires": "tomorrow"], ["name": "x", "maxAge": true], ["name": "x", "secure": "true"],
        ] {
            XCTAssertThrowsError(
                try runtime.replace(martianJSON: JSONSerialization.data(withJSONObject: ["cookie.Modifier": fields])))
        }
        var request = request()
        try runtime.modify(request: &request)
        XCTAssertEqual(request.head["Cookie"], "same=original")
        var response = ResponseContext(
            requestMethod: "POST", target: request.target, head: HTTPHead(startLine: "HTTP/1.1 200 OK"))
        try runtime.modify(response: &response)
        XCTAssertEqual(response.head["Set-Cookie"], "only-response=1")
    }

    func testFilteredLoggingRedactsWithoutMutatingAndHeadersOnlyOmitsBody() throws {
        let messages = Messages()
        let modifier = try parse(
            ["url.Filter": ["path": "/original", "modifier": ["log.Logger": ["scope": ["request"]]]]],
            sink: { messages.append($0) })
        var request = request()
        let original = request.body
        try modifier.modify(request: &request)
        XCTAssertEqual(messages.values.count, 1)
        XCTAssertFalse(messages.values[0].contains("secret-header"))
        XCTAssertFalse(messages.values[0].contains("secret-body"))
        XCTAssertFalse(messages.values[0].contains("nested-secret"))
        XCTAssertTrue(messages.values[0].contains("[REDACTED]"))
        XCTAssertEqual(request.body, original)
        XCTAssertEqual(request.head["Authorization"], "secret-header")
        request.target = "http://fixture.test/unmatched"
        try modifier.modify(request: &request)
        XCTAssertEqual(messages.values.count, 1)
        try parse(["log.Logger": ["headersOnly": true]], sink: { messages.append($0) }).modify(request: &request)
        XCTAssertFalse(messages.values.last!.contains("nested"))
    }

    func testLoggerDecodesGzipAndEnforcesDecodedSizeLimit() throws {
        // gzip of {"hello":"world"}, generated independently of the decoder.
        let compressed = Data(base64Encoded: "H4sIAAAAAAAC/6tWykjNyclXslIqzy/KSVGqBQDRQQnYEQAAAA==")!
        XCTAssertEqual(
            try DiagnosticBodyDecoder.decode(compressed, encoding: "gzip", limit: 100), Data(#"{"hello":"world"}"#.utf8)
        )
        XCTAssertThrowsError(try DiagnosticBodyDecoder.decode(compressed, encoding: "gzip", limit: 5))
        XCTAssertThrowsError(try DiagnosticBodyDecoder.decode(Data([1, 2]), encoding: "gzip", limit: 100))
        let messages = Messages()
        let modifier = MessageLoggerModifier(decode: true, sink: { messages.append($0) })
        var response = ResponseContext(
            requestMethod: "GET", target: "http://fixture.test/",
            head: HTTPHead(
                startLine: "HTTP/1.1 200 OK",
                headers: [("Content-Encoding", "gzip"), ("Content-Type", "application/json")]), body: compressed)
        modifier.modify(response: &response)
        XCTAssertTrue(messages.values[0].contains("world"))
        XCTAssertEqual(response.body, compressed)
        XCTAssertEqual(response.head["Content-Encoding"], "gzip")
    }

    func testLoggerStreamingBodyDefersUntilTransferCompletes() {
        let messages = Messages()
        var request = request()
        request.body = nil
        MessageLoggerModifier(sink: { messages.append($0) }).modify(request: &request)
        XCTAssertTrue(messages.values.isEmpty)
        request.streamingLog?.append(Data(#"{"message":"streamed"}"#.utf8))
        request.streamingLog?.finish(complete: true)
        XCTAssertEqual(messages.values.count, 1)
        XCTAssertTrue(messages.values[0].contains("streamed"))
    }

    private func entry(body: Data = Data("abcdef".utf8), headers: [LoggedHeader] = [], truncated: Bool = false)
        -> TrafficEntry
    {
        TrafficEntry(
            timestamp: Date(), method: "POST", target: "http://fixture.test/", status: 200, bytes: body.count,
            durationMilliseconds: 1, transport: "http", error: nil,
            requestHeaders: headers, responseHeaders: headers, requestBody: body, responseBody: body,
            requestBodyTruncated: truncated, responseBodyTruncated: truncated)
    }

    private func entries(_ store: HARStore) throws -> [[String: Any]] {
        let root = try JSONSerialization.jsonObject(with: store.encodedHAR()) as! [String: Any]
        return (root["log"] as! [String: Any])["entries"] as! [[String: Any]]
    }

    func testHARBodiesAreOptInAndBoundedAndBinaryIsBase64() throws {
        let disabled = HARStore()
        disabled.record(entry())
        let noBody = try entries(disabled)[0]
        XCTAssertNil((noBody["request"] as! [String: Any])["postData"])
        XCTAssertNil(((noBody["response"] as! [String: Any])["content"] as! [String: Any])["text"])
        let enabled = HARStore(capturePolicy: BodyCapturePolicy(maximumBytes: 3))
        enabled.record(entry(body: Data([0, 255, 128, 65])))
        let captured = try entries(enabled)[0]
        let content = (captured["response"] as! [String: Any])["content"] as! [String: Any]
        XCTAssertEqual(content["encoding"] as? String, "base64")
        XCTAssertEqual(Data(base64Encoded: content["text"] as! String), Data([0, 255, 128]))
        XCTAssertEqual(content["_truncated"] as? Bool, true)
    }

    func testHARRedactsJSONAndFormAndDoesNotRetainUnsafeStructuredPrefixes() throws {
        for (type, body, secret) in [
            ("application/json", #"{"token":"json-secret","ok":1}"#, "json-secret"),
            ("application/x-www-form-urlencoded", "password=form-secret&ok=1", "form-secret"),
        ] {
            let store = HARStore(capturePolicy: BodyCapturePolicy())
            store.record(entry(body: Data(body.utf8), headers: [LoggedHeader(name: "Content-Type", value: type)]))
            let captured = try entries(store)[0]
            let content = (captured["response"] as! [String: Any])["content"] as! [String: Any]
            let text = String(decoding: Data(base64Encoded: content["text"] as! String)!, as: UTF8.self)
            XCTAssertFalse(text.contains(secret))
            XCTAssertTrue(text.contains("REDACTED"))
        }
        let policy = BodyCapturePolicy()
        let headers = [LoggedHeader(name: "Content-Type", value: "application/json")]
        XCTAssertTrue(
            String(
                decoding: policy.capture(Data(#"{"token":"sec"#.utf8), headers: headers, truncated: true).data!,
                as: UTF8.self
            ).contains("REDACTED"))
    }

    func testEmptyStructuredBodyStaysEmptyAndEncodedStructuredBodyIsOmitted() {
        let policy = BodyCapturePolicy()
        let headers = [LoggedHeader(name: "Content-Type", value: "application/json")]
        XCTAssertEqual(policy.capture(Data(), headers: headers, truncated: false).data, Data())
        let encoded = policy.capture(
            Data([1, 2, 3]),
            headers: headers + [
                LoggedHeader(name: "Content-Encoding", value: "gzip")
            ], truncated: false)
        XCTAssertTrue(encoded.truncated)
        XCTAssertTrue(String(decoding: encoded.data!, as: UTF8.self).contains("REDACTED"))
    }

    func testHARRetentionEvictsOldBodiesAndResetReleasesBudget() throws {
        let store = HARStore(maximumEntries: 10, capturePolicy: BodyCapturePolicy(), maximumRetainedBodyBytes: 12)
        store.record(entry())
        store.record(entry())
        XCTAssertEqual(store.count(), 1)
        store.reset()
        XCTAssertEqual(store.count(), 0)
        store.record(entry())
        XCTAssertEqual(store.count(), 1)
    }
}
