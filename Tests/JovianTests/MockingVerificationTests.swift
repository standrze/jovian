import Foundation
import XCTest

@testable import Jovian

final class MockingVerificationTests: XCTestCase {
    private func request(_ target: String = "http://api.example.test/ready?q=one&q=two") -> RequestContext {
        RequestContext(
            method: "GET", target: target,
            head: HTTPHead(startLine: "GET / HTTP/1.1", headers: [("X-Test", "one"), ("X-Test", "two")]))
    }

    private func configure(_ runtime: RuntimeConfiguration, _ node: [String: Any]) throws {
        try runtime.replace(martianJSON: JSONSerialization.data(withJSONObject: node))
    }

    private func withRoot(_ body: (URL) throws -> Void) throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("jovian-static-\(UUID())")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        try Data("0123456789".utf8).write(to: root.appendingPathComponent("fixture.txt"))
        try body(root)
    }

    func testPingbackInitialStateStickySuccessAndReset() throws {
        let runtime = RuntimeConfiguration()
        try configure(
            runtime, ["pingback.Verifier": ["host": "api.example.test", "path": "/ready", "query": "q=one&q=two"]])
        XCTAssertEqual(runtime.verificationFailures().count, 1)
        var other = request("http://api.example.test/else?q=one&q=two")
        try runtime.modify(request: &other)
        XCTAssertEqual(runtime.verificationFailures().count, 1)
        var matching = request()
        try runtime.modify(request: &matching)
        XCTAssertTrue(runtime.verificationFailures().isEmpty)
        try runtime.modify(request: &other)
        XCTAssertTrue(runtime.verificationFailures().isEmpty)
        runtime.resetVerificationFailures()
        XCTAssertEqual(runtime.verificationFailures().count, 1)
    }

    func testUnreachedPingbackRemainsPendingAndFailedReplacementIsAtomic() throws {
        let runtime = RuntimeConfiguration()
        try configure(
            runtime, ["method.Filter": ["method": "POST", "modifier": ["pingback.Verifier": ["path": "/ready"]]]])
        var matching = request()
        try runtime.modify(request: &matching)
        XCTAssertEqual(runtime.verificationFailures().count, 1)
        XCTAssertThrowsError(try configure(runtime, ["pingback.Verifier": ["scope": ["response"]]]))
        matching.method = "POST"
        try runtime.modify(request: &matching)
        XCTAssertTrue(runtime.verificationFailures().isEmpty)
        XCTAssertThrowsError(try configure(runtime, ["unknown.Modifier": [:]]))
        XCTAssertTrue(runtime.verificationFailures().isEmpty)
    }

    func testVerifiersObserveCompositionOrderAndDuplicateHeadersWithoutExposingValues() throws {
        let runtime = RuntimeConfiguration()
        try configure(
            runtime,
            [
                "fifo.Group": [
                    "modifiers": [
                        ["header.Verifier": ["name": "x-test", "value": "two", "scope": ["request"]]],
                        ["method.Verifier": ["method": "GET"]],
                        ["url.Verifier": ["scheme": "http", "host": "*.example.test", "path": "/ready"]],
                        ["querystring.Verifier": ["name": "q", "value": "two"]],
                        ["status.Modifier": ["statusCode": 201]],
                        ["status.Verifier": ["statusCode": 201]],
                        [
                            "header.Verifier": [
                                "name": "Authorization", "value": "expected-secret", "scope": ["response"],
                            ]
                        ],
                    ]
                ]
            ])
        var matching = request()
        try runtime.modify(request: &matching)
        XCTAssertTrue(runtime.verificationFailures().isEmpty)
        var response = ResponseContext(
            requestMethod: "GET", target: matching.target,
            head: HTTPHead(startLine: "HTTP/1.1 200 OK", headers: [("Authorization", "actual-secret")]))
        response.configurationModifiers = matching.configurationModifiers
        try runtime.modify(response: &response)
        XCTAssertEqual(runtime.verificationFailures().count, 1)
        XCTAssertFalse(runtime.verificationFailures()[0].message.contains("secret"))
        runtime.resetVerificationFailures()
        XCTAssertTrue(runtime.verificationFailures().isEmpty)
    }

    func testQueryVerifierParsesRepeatedFormValuesAndRejectsUnavailableBodies() throws {
        let runtime = RuntimeConfiguration()
        try configure(runtime, ["querystring.Verifier": ["name": "full name", "value": "A B"]])
        var query = request("http://api.example.test/?full+name=other&full%20name=A+B")
        try runtime.modify(request: &query)
        var form = request("http://api.example.test/")
        form.method = "POST"
        form.head["Content-Type"] = "application/x-www-form-urlencoded; charset=utf-8"
        form.body = Data("full+name=other&full+name=A%20B".utf8)
        try runtime.modify(request: &form)
        XCTAssertTrue(runtime.verificationFailures().isEmpty)
        form.body = nil
        try runtime.modify(request: &form)
        XCTAssertEqual(runtime.verificationFailures().count, 1)
        form.body = Data("full+name=%GG".utf8)
        try runtime.modify(request: &form)
        XCTAssertEqual(runtime.verificationFailures().count, 2)
    }

    func testReplacementKeepsInflightResponseOnOriginalConfiguration() throws {
        let runtime = RuntimeConfiguration()
        try configure(runtime, ["status.Verifier": ["statusCode": 201]])
        var old = request()
        try runtime.modify(request: &old)
        try configure(runtime, ["status.Verifier": ["statusCode": 200]])
        var response = ResponseContext(
            requestMethod: "GET", target: old.target, head: HTTPHead(startLine: "HTTP/1.1 201 Created"))
        response.configurationModifiers = old.configurationModifiers
        try runtime.modify(response: &response)
        XCTAssertTrue(runtime.verificationFailures().isEmpty)
        var new = request()
        try runtime.modify(request: &new)
        response.configurationModifiers = new.configurationModifiers
        try runtime.modify(response: &response)
        XCTAssertEqual(runtime.verificationFailures().count, 1)
        try configure(runtime, ["noop.Modifier": [:]])
        try runtime.modify(response: &response)
        XCTAssertTrue(runtime.verificationFailures().isEmpty, "detached verifiers cannot contaminate the replacement")
    }

    func testCanonicalReplacementClearsNativeRatesAndLegacyRules() throws {
        let runtime = RuntimeConfiguration()
        try runtime.replace(
            with: RuntimeConfigurationDocument(verifyStatus: ["example.test": 500], uploadBytesPerSecond: 1))
        try configure(runtime, ["noop.Modifier": [:]])
        XCTAssertNil(runtime.trafficRates().upload)
        XCTAssertNil(runtime.snapshot().verifyStatus)
    }

    func testFailureVerifierRetentionIsBoundedAndResettable() throws {
        let runtime = RuntimeConfiguration()
        try configure(runtime, ["failure.Verifier": ["message": "fixture reached"]])
        var matching = request()
        for _ in 0..<(VerificationStore.maximumFailures + 3) { try runtime.modify(request: &matching) }
        let errors = runtime.verificationFailures()
        XCTAssertEqual(errors.count, VerificationStore.maximumFailures + 1)
        XCTAssertTrue(errors.last!.message.contains("omitted"))
        XCTAssertNil(matching.syntheticResponse)
        XCTAssertFalse(matching.skipRoundTrip)
        runtime.resetVerificationFailures()
        XCTAssertTrue(runtime.verificationFailures().isEmpty)
    }

    func testNativeMockingAndVerifierRulesRoundTrip() throws {
        try withRoot { root in
            let spec = ModifierSpec.group(modifiers: [
                .staticFiles(rootPath: root.path, explicitPaths: ["/ready": "fixture.txt"]),
                .verify(scope: nil, expectation: VerificationSpec(kind: .pingback, path: "/ready")),
                .skipRoundTrip,
            ])
            let document = RuntimeConfigurationDocument(modifier: spec)
            let data = try JSONEncoder().encode(document)
            let runtime = RuntimeConfiguration()
            try runtime.replace(with: JSONDecoder().decode(RuntimeConfigurationDocument.self, from: data))
            XCTAssertEqual(runtime.verificationFailures().count, 1)
            var matching = request()
            try runtime.modify(request: &matching)
            XCTAssertTrue(matching.skipRoundTrip)
            XCTAssertTrue(runtime.verificationFailures().isEmpty)
            let encoded = try JSONSerialization.jsonObject(with: runtime.encodedConfiguration()) as! NSDictionary
            let original = try JSONSerialization.jsonObject(with: data) as! NSDictionary
            XCTAssertEqual(encoded["modifier"] as? NSDictionary, original["modifier"] as? NSDictionary)
        }
    }

    func testStaticMappingRangesAndMissingFiles() throws {
        try withRoot { root in
            let modifier = try StaticFileModifier(rootPath: root.path, explicitPaths: ["/ready": "fixture.txt"])
            for (range, status, expected) in [
                (nil, 200, "0123456789"), ("bytes=2-4", 206, "234"),
                ("bytes=8-", 206, "89"), ("bytes=-3", 206, "789"),
                ("bytes=99-", 416, ""),
            ] {
                var head = HTTPHead(startLine: "GET /ready HTTP/1.1")
                head["Range"] = range
                var response = ResponseContext(
                    requestMethod: "GET", target: "http://fixture.test/ready",
                    head: HTTPHead(startLine: "HTTP/1.1 200 OK"), requestHead: head)
                modifier.modify(response: &response)
                XCTAssertTrue(response.head.startLine.contains(" \(status) "))
                XCTAssertEqual(String(data: response.body!, encoding: .utf8), expected)
                if status == 206 { XCTAssertNotNil(response.head["Content-Range"]) }
            }
            var missing = ResponseContext(
                requestMethod: "GET", target: "http://fixture.test/missing",
                head: HTTPHead(startLine: "HTTP/1.1 200 OK"))
            modifier.modify(response: &missing)
            XCTAssertTrue(missing.head.startLine.contains(" 404 "))
        }
    }

    func testStaticRejectsTraversalSymlinksDirectoriesAndStreamsLargeFiles() throws {
        try withRoot { root in
            try FileManager.default.createSymbolicLink(
                atPath: root.appendingPathComponent("link").path,
                withDestinationPath: root.appendingPathComponent("fixture.txt").path)
            try FileManager.default.createDirectory(
                at: root.appendingPathComponent("dir"), withIntermediateDirectories: true)
            try Data(repeating: 0, count: StaticFileModifier.maximumFileBytes + 1).write(
                to: root.appendingPathComponent("large"))
            let modifier = try StaticFileModifier(rootPath: root.path)
            for (path, status) in [("/%2e%2e/fixture.txt", 403), ("/link", 403), ("/dir", 403)] {
                var response = ResponseContext(
                    requestMethod: "GET", target: "http://fixture.test\(path)",
                    head: HTTPHead(startLine: "HTTP/1.1 200 OK"))
                modifier.modify(response: &response)
                XCTAssertTrue(response.head.startLine.contains(" \(status) "), path)
                XCTAssertEqual(response.body, Data())
            }
            var large = ResponseContext(
                requestMethod: "GET", target: "http://fixture.test/large",
                head: HTTPHead(startLine: "HTTP/1.1 200 OK"))
            modifier.modify(response: &large)
            XCTAssertNil(large.body)
            XCTAssertEqual(large.bodyStream?.length, StaticFileModifier.maximumFileBytes + 1)
            XCTAssertEqual(try large.bodyStream?.read(maximum: 100)?.count, 100)
            XCTAssertThrowsError(try StaticFileModifier(rootPath: root.path, explicitPaths: ["/bad": "../outside"]))
            XCTAssertThrowsError(try StaticFileModifier(rootPath: "."))
            XCTAssertThrowsError(try StaticFileModifier(rootPath: root.path, explicitPaths: ["/bad": "/etc/passwd"]))
        }
    }

    func testInvalidVerifierScopesAndFieldsDoNotActivate() throws {
        let runtime = RuntimeConfiguration()
        for node: [String: Any] in [
            ["header.Verifier": ["name": "Bad\r\nName"]], ["method.Verifier": ["method": ""]],
            ["status.Verifier": ["statusCode": true]], ["status.Verifier": ["statusCode": 600]],
            ["url.Verifier": ["scope": ["response"]]], ["querystring.Verifier": [:]],
            ["skip.RoundTrip": ["scope": ["response"]]],
        ] {
            XCTAssertThrowsError(try configure(runtime, node))
        }
    }

    func testStaticRootRemainsAnchoredWhenItsPathIsReplaced() throws {
        try withRoot { root in
            let files = root.appendingPathComponent("files")
            let outside = root.appendingPathComponent("outside")
            try FileManager.default.createDirectory(at: files, withIntermediateDirectories: true)
            try FileManager.default.createDirectory(at: outside, withIntermediateDirectories: true)
            try Data("original".utf8).write(to: files.appendingPathComponent("fixture.txt"))
            try Data("replacement".utf8).write(to: outside.appendingPathComponent("fixture.txt"))
            let modifier = try StaticFileModifier(rootPath: files.path)
            try FileManager.default.moveItem(at: files, to: root.appendingPathComponent("moved"))
            try FileManager.default.createSymbolicLink(atPath: files.path, withDestinationPath: outside.path)
            var response = ResponseContext(
                requestMethod: "GET", target: "http://fixture.test/fixture.txt",
                head: HTTPHead(startLine: "HTTP/1.1 200 OK"))
            modifier.modify(response: &response)
            XCTAssertEqual(response.body, Data("original".utf8))
        }
    }
}
