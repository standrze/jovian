import Foundation
import XCTest

@testable import Jovian

final class ProxyUpgradeTests: XCTestCase {
    private struct Broken: Modifier {
        let name: String
        func modify(request: inout RequestContext) throws { throw ProxyError.unsupported(name) }
        func modify(response: inout ResponseContext) throws { throw ProxyError.unsupported(name) }
    }

    private final class Messages: @unchecked Sendable {
        var values: [String] = []
    }

    private func request(body: Data? = Data()) -> RequestContext {
        RequestContext(
            method: "POST", target: "http://fixture.test/path",
            head: HTTPHead(startLine: "POST /path HTTP/1.1"), body: body)
    }

    private func parse(_ node: [String: Any]) throws -> any Modifier {
        try MartianConfigurationParser.parse(JSONSerialization.data(withJSONObject: node))
    }

    func testViaAppendsAllExistingValuesAndUsesDistinctStableIdentities() throws {
        let first = ViaModifier()
        let second = ViaModifier()
        XCTAssertNotEqual(first.identity, second.identity)
        var request = request()
        request.head.add(name: "Via", value: "1.0 upstream (comment)")
        request.head.add(name: "via", value: "HTTP/1.1 other")
        try first.modify(request: &request)
        try second.modify(request: &request)
        XCTAssertEqual(request.head.values(for: "Via").count, 1)
        XCTAssertEqual(
            request.head["Via"], "1.0 upstream (comment), HTTP/1.1 other, 1.1 \(first.identity), 1.1 \(second.identity)"
        )
        XCTAssertThrowsError(try first.modify(request: &request)) { XCTAssertTrue($0 is ProxyLoopError) }
    }

    func testViaRejectsIdentityInDuplicateFieldWithWhitespaceWithoutSubstringMatches() throws {
        let via = ViaModifier()
        var request = request()
        request.head["Via"] = "1.1 prefix-\(via.identity)"
        try via.modify(request: &request)
        request.head.add(name: "Via", value: "1.0\t\(via.identity) (already crossed)")
        XCTAssertThrowsError(try via.modify(request: &request))
    }

    func testGroupsDefaultToFailFastAndAggregateInOrderInBothDirections() throws {
        let marker = HeaderModifier(scope: .both, name: "X-After", value: "ran")
        let children: [any Modifier] = [Broken(name: "first"), marker, Broken(name: "last")]
        var request = request()
        XCTAssertThrowsError(try ModifierGroup(children).modify(request: &request))
        XCTAssertNil(request.head["X-After"])
        let group = ModifierGroup(children, aggregateErrors: true)
        XCTAssertThrowsError(try group.modify(request: &request)) {
            let error = $0 as? ModifierErrors
            XCTAssertEqual(error?.errors.count, 2)
            XCTAssertEqual(error?.description, "unsupported: first; unsupported: last")
        }
        XCTAssertEqual(request.head["X-After"], "ran")
        var response = ResponseContext(
            requestMethod: "POST", target: request.target,
            head: HTTPHead(startLine: "HTTP/1.1 200 OK"))
        XCTAssertThrowsError(try group.modify(response: &response)) {
            XCTAssertEqual(($0 as? ModifierErrors)?.errors.count, 2)
        }
        XCTAssertEqual(response.head["X-After"], "ran")
        XCTAssertNoThrow(try ModifierGroup([marker], aggregateErrors: true).modify(request: &request))
    }

    func testCanonicalAggregationRunsLaterVerifiersAndRejectsNonBooleanAtomically() throws {
        let runtime = RuntimeConfiguration()
        let node: [String: Any] = [
            "fifo.Group": [
                "aggregateErrors": true,
                "modifiers": [
                    ["header.Append": ["name": "Host", "value": "duplicate"]],
                    ["failure.Verifier": ["message": "after error"]],
                ],
            ]
        ]
        try runtime.replace(martianJSON: JSONSerialization.data(withJSONObject: node))
        var request = request()
        XCTAssertThrowsError(try runtime.modify(request: &request)) { XCTAssertTrue($0 is ModifierErrors) }
        XCTAssertEqual(runtime.verificationFailures().count, 1)
        XCTAssertThrowsError(try parse(["fifo.Group": ["aggregateErrors": 1, "modifiers": []]]))
        XCTAssertNoThrow(
            try parse(["fifo.Group": ["aggregateErrors": true, "modifiers": []]]).modify(request: &request))
    }

    func testSpecialHostAppendCopyDeleteAndResponseNoop() throws {
        var request = request()
        XCTAssertEqual(request.head["Host"], "fixture.test")
        XCTAssertThrowsError(
            try HeaderOperationModifier(.append(name: "HOST", value: "other")).modify(request: &request))
        try HeaderOperationModifier(.copy(from: "Host", to: "X-Host")).modify(request: &request)
        XCTAssertEqual(request.head["X-Host"], "fixture.test")
        try HeaderOperationModifier(.blacklist(names: ["Host"])).modify(request: &request)
        try HeaderOperationModifier(.append(name: "Host", value: "virtual.test")).modify(request: &request)
        XCTAssertEqual(request.head["Host"], "virtual.test")
        XCTAssertEqual(request.target, "http://fixture.test/path")
        var response = ResponseContext(
            requestMethod: "POST", target: request.target,
            head: HTTPHead(startLine: "HTTP/1.1 200 OK"))
        try HeaderModifier(scope: .response, name: "Host", value: "ignored").modify(response: &response)
        try HeaderOperationModifier(.copy(from: "Host", to: "X-Host")).modify(response: &response)
        XCTAssertNil(response.head["Host"])
        XCTAssertEqual(response.head["X-Host"], "")
    }

    func testContentLengthZeroGetVersusPresenceAndSignedUnknownLength() throws {
        var request = request()
        try HeaderOperationModifier(.copy(from: "Content-Length", to: "X-Length")).modify(request: &request)
        XCTAssertEqual(request.head["X-Length"], "0")
        XCTAssertTrue(MessageHeaders.values("Content-Length", head: request.head, response: false).isEmpty)
        try HeaderOperationModifier(.append(name: "Content-Length", value: "12")).modify(request: &request)
        XCTAssertThrowsError(
            try HeaderOperationModifier(.append(name: "Content-Length", value: "12")).modify(request: &request))
        XCTAssertEqual(MessageHeaders.values("Content-Length", head: request.head, response: false), ["12"])
        try HeaderModifier(scope: .request, name: "Content-Length", value: "-1").modify(request: &request)
        XCTAssertNil(request.head["Content-Length"])
        XCTAssertEqual(MessageHeaders.first("Content-Length", head: request.head, response: false), "")
        for value in ["bad", "1 2", "9223372036854775808"] {
            XCTAssertThrowsError(
                try HeaderModifier(scope: .request, name: "Content-Length", value: value).modify(request: &request))
        }
    }

    func testSpecialTransferEncodingValuesAndFiltersAndVerifiers() throws {
        var request = request()
        try HeaderModifier(scope: .request, name: "Transfer-Encoding", value: "gzip").modify(request: &request)
        try HeaderOperationModifier(.append(name: "Transfer-Encoding", value: "chunked")).modify(request: &request)
        XCTAssertEqual(
            MessageHeaders.values("Transfer-Encoding", head: request.head, response: false), ["gzip", "chunked"])
        try parse([
            "header.Filter": [
                "name": "Host", "value": "fixture.test", "scope": ["request"],
                "modifier": ["header.Modifier": ["name": "X-Matched", "value": "yes"]],
            ]
        ])
        .modify(request: &request)
        XCTAssertEqual(request.head["X-Matched"], "yes")
        let store = VerificationStore()
        try VerifierModifier(spec: VerificationSpec(kind: .header, name: "Content-Length"), store: store)
            .modify(request: &request)
        XCTAssertEqual(store.snapshot().count, 1)
    }

    func testFramingRejectsAmbiguousMalformedAndUnsupportedInputs() throws {
        for headers in [
            [("Content-Length", "1"), ("content-length", "1")], [("Content-Length", "bad")],
            [("Content-Length", "-1")], [("Content-Length", "0"), ("Transfer-Encoding", "chunked")],
            [("Transfer-Encoding", "gzip, chunked")], [("Transfer-Encoding", "chunked, chunked")],
        ] {
            XCTAssertThrowsError(try HTTPHead(startLine: "POST / HTTP/1.1", headers: headers).validatedFraming())
        }
        XCTAssertTrue(
            try HTTPHead(startLine: "", headers: [("Transfer-Encoding", "Chunked")]).validatedFraming().chunked)
    }

    func testStreamingLoggerBoundsPlainBodiesAndEmitsOnceWithFrozenHeaders() {
        let messages = Messages()
        var request = request(body: nil)
        request.head["X-Position"] = "before"
        MessageLoggerModifier(capture: BodyCapturePolicy(maximumBytes: 8), sink: { messages.values.append($0) })
            .modify(request: &request)
        request.head["X-Position"] = "after"
        XCTAssertTrue(messages.values.isEmpty)
        request.streamingLog?.append(Data("12345".utf8))
        request.streamingLog?.append(Data("678901234".utf8))
        request.streamingLog?.finish(complete: true)
        request.streamingLog?.finish(complete: false)
        XCTAssertEqual(messages.values.count, 1)
        XCTAssertTrue(messages.values[0].contains("12345678\n[body truncated]"))
        XCTAssertTrue(messages.values[0].contains("X-Position: before"))
        XCTAssertFalse(messages.values[0].contains("after"))
    }

    func testStreamingLoggerRedactsStructuredPrefixesAndMarksInterruptedTransfers() {
        let messages = Messages()
        var request = request(body: nil)
        request.head["Content-Type"] = "application/json"
        request.head["Authorization"] = "header-secret"
        MessageLoggerModifier(capture: BodyCapturePolicy(maximumBytes: 64), sink: { messages.values.append($0) })
            .modify(request: &request)
        request.streamingLog?.append(Data(#"{"password":"body-secret","ok":""#.utf8))
        request.streamingLog?.finish(complete: false)
        XCTAssertEqual(messages.values.count, 1)
        XCTAssertTrue(messages.values[0].contains("stream interrupted"))
        XCTAssertTrue(messages.values[0].contains("REDACTED"))
        XCTAssertFalse(messages.values[0].contains("body-secret"))
        XCTAssertFalse(messages.values[0].contains("header-secret"))
    }

    func testBodyReplacementSupportsSingleSuffixMultipartAndUnsatisfiableRanges() throws {
        let modifier = BodyModifier(scope: .response, content: Data("0123456789".utf8), contentType: "text/plain")
        for (range, status, expected) in [
            ("bytes=2-4", 206, "234"), ("bytes=-3", 206, "789"), ("bytes=8-999", 206, "89"),
            ("bytes=99-", 416, ""), ("bytes=9-2", 416, ""),
        ] {
            let head = HTTPHead(startLine: "GET / HTTP/1.1", headers: [("Range", range)])
            var response = ResponseContext(
                requestMethod: "GET", target: "http://fixture.test/",
                head: HTTPHead(startLine: "HTTP/1.1 200 OK"), body: nil, requestHead: head)
            modifier.modify(response: &response)
            XCTAssertTrue(response.head.startLine.contains(" \(status) "))
            XCTAssertEqual(String(decoding: response.body!, as: UTF8.self), expected)
        }
        let plan = ByteRangePlan(size: 10, range: "bytes=0-1,8-", contentType: "text/plain")
        let data = plan.data(from: Data("0123456789".utf8))
        XCTAssertEqual(data.count, plan.length)
        let text = String(decoding: data, as: UTF8.self)
        XCTAssertTrue(text.contains("Content-Range: bytes 0-1/10\r\n\r\n01\r\n"))
        XCTAssertTrue(text.contains("Content-Range: bytes 8-9/10\r\n\r\n89\r\n"))
        XCTAssertNil(plan.contentRange)
        XCTAssertEqual(
            ByteRangePlan(
                size: 10, range: "bytes=" + Array(repeating: "0-1", count: 17).joined(separator: ","),
                contentType: "text/plain"
            ).status, 416)
    }

    func testLargeStaticStreamRetainsOpenedFileAfterPathReplacement() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let path = root.appendingPathComponent("large.txt")
        let original = Data(repeating: 65, count: StaticFileModifier.maximumFileBytes + 1)
        try original.write(to: path)
        let modifier = try StaticFileModifier(rootPath: root.path)
        var response = ResponseContext(
            requestMethod: "GET", target: "http://fixture.test/large.txt",
            head: HTTPHead(startLine: "HTTP/1.1 200 OK"))
        modifier.modify(response: &response)
        let stream = try XCTUnwrap(response.bodyStream)
        try FileManager.default.removeItem(at: path)
        try Data("replacement at same path".utf8).write(to: path)
        var result = Data()
        while let chunk = try stream.read(maximum: 32_768) {
            XCTAssertLessThanOrEqual(chunk.count, 32_768)
            result.append(chunk)
        }
        XCTAssertEqual(result, original)
        response.body = Data("later modifier".utf8)
        XCTAssertNil(response.bodyStream)
    }
}
