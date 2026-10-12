import Foundation
import XCTest

@testable import Jovian

final class HeaderOperationsTests: XCTestCase {
    private func request() -> RequestContext {
        RequestContext(
            method: "GET", target: "http://fixture.test/",
            head: HTTPHead(startLine: "GET / HTTP/1.1", headers: [("X-From", "first"), ("x-from", "second")]))
    }

    private func parse(_ type: String, _ fields: [String: Any]) throws -> any Modifier {
        try MartianConfigurationParser.parse(JSONSerialization.data(withJSONObject: [type: fields]))
    }

    func testCanonicalAppendPreservesDuplicatesAndRespectsScope() throws {
        let modifier = try parse("header.Append", ["name": "X-From", "value": "third", "scope": ["request"]])
        var request = request()
        try modifier.modify(request: &request)
        XCTAssertEqual(request.head.values(for: "x-from"), ["first", "second", "third"])
        var response = ResponseContext(requestMethod: "GET", target: request.target, head: request.head)
        try modifier.modify(response: &response)
        XCTAssertEqual(response.head.values(for: "x-from"), ["first", "second", "third"])
    }

    func testCopyUsesFirstValueReplacesDestinationAndCopiesMissingAsEmpty() throws {
        var request = request()
        request.head.add(name: "X-To", value: "old")
        request.head.add(name: "X-To", value: "older")
        try parse("header.Copy", ["from": "X-From", "to": "X-To"]).modify(request: &request)
        XCTAssertEqual(request.head.values(for: "x-to"), ["first"])
        try parse("header.Copy", ["from": "Missing", "to": "X-To"]).modify(request: &request)
        XCTAssertEqual(request.head.values(for: "x-to"), [""])
        try parse("header.Copy", ["from": "X-From", "to": "X-From"]).modify(request: &request)
        XCTAssertEqual(request.head.values(for: "x-from"), ["first"])
    }

    func testBlacklistRemovesAllCaseInsensitiveValuesFromBothDirections() throws {
        let modifier = try parse("header.Blacklist", ["names": ["x-from", "not-present"]])
        var request = request()
        var response = ResponseContext(requestMethod: "GET", target: request.target, head: request.head)
        try modifier.modify(request: &request)
        try modifier.modify(response: &response)
        XCTAssertTrue(request.head.values(for: "X-From").isEmpty)
        XCTAssertTrue(response.head.values(for: "X-From").isEmpty)
    }

    func testCanonicalIDUsesExchangeIdentityAndPreservesExistingNonemptyID() throws {
        let modifier = try parse("header.Id", [:])
        var request = request()
        try modifier.modify(request: &request)
        XCTAssertEqual(request.head["X-Martian-ID"], request.id.uuidString.lowercased())
        request.head["X-Martian-ID"] = "caller-provided"
        try modifier.modify(request: &request)
        XCTAssertEqual(request.head["X-Martian-ID"], "caller-provided")
        request.head["X-Martian-ID"] = ""
        try modifier.modify(request: &request)
        XCTAssertNotNil(UUID(uuidString: request.head["X-Martian-ID"]!))
        XCTAssertThrowsError(try parse("header.Id", ["scope": ["response"]]))
    }

    func testNativeIDCanEchoTheSameValueIntoSyntheticResponse() throws {
        let runtime = RuntimeConfiguration()
        try runtime.replace(
            with: RuntimeConfigurationDocument(
                modifier: .group(modifiers: [
                    .headerID(echoResponse: true), .skipRoundTrip,
                ])))
        var request = request()
        try runtime.modify(request: &request)
        var response = ResponseContext(
            requestMethod: "GET", target: request.target,
            head: HTTPHead(startLine: "HTTP/1.1 200 OK"), requestHead: request.head)
        try runtime.modify(response: &response)
        XCTAssertEqual(response.head["X-Martian-ID"], request.head["X-Martian-ID"])
        XCTAssertTrue(request.skipRoundTrip)
    }

    func testNativeHeaderOperationsRoundTripAndValidationIsAtomic() throws {
        let runtime = RuntimeConfiguration()
        let spec = ModifierSpec.group(modifiers: [
            .headerAppend(scope: ["request"], name: "X-From", value: "third"),
            .headerCopy(scope: ["request"], from: "X-From", to: "X-To"),
            .headerBlacklist(scope: ["request"], names: ["X-From"]), .headerID(echoResponse: true),
        ])
        let original = try JSONEncoder().encode(spec)
        let decoded = try JSONDecoder().decode(ModifierSpec.self, from: original)
        XCTAssertEqual(
            try JSONSerialization.jsonObject(with: original) as! NSDictionary,
            try JSONSerialization.jsonObject(with: JSONEncoder().encode(decoded)) as! NSDictionary)
        try runtime.replace(with: RuntimeConfigurationDocument(modifier: decoded))
        for node: [String: Any] in [
            ["header.Append": ["name": "Bad\r\nName", "value": "x"]],
            ["header.Blacklist": ["names": ["X-From", ":status"]]],
            ["header.Copy": ["from": "", "to": "X-To"]],
            ["header.Append": ["name": "X-From", "value": "x\nInjected"]],
        ] {
            XCTAssertThrowsError(try runtime.replace(martianJSON: JSONSerialization.data(withJSONObject: node)))
        }
        var request = request()
        try runtime.modify(request: &request)
        XCTAssertEqual(request.head["X-To"], "first")
        XCTAssertNil(request.head["X-From"])
    }
}
