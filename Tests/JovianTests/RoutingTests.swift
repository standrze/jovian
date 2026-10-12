import Foundation
import XCTest

@testable import Jovian

final class RoutingTests: XCTestCase {
    private func request(_ target: String = "https://api.example.test:8443/v1/items?q=first&q=second") -> RequestContext
    {
        RequestContext(
            method: "GET", target: target,
            head: HTTPHead(
                startLine: "GET / HTTP/1.1",
                headers: [
                    ("Host", "api.example.test:8443"), ("X-Mode", "preview"), ("X-Mode", "live"),
                    ("Cookie", "session=one; flag=\"two\""),
                ]))
    }

    private func parse(_ type: String, _ fields: [String: Any]) throws -> any Modifier {
        try MartianConfigurationParser.parse(JSONSerialization.data(withJSONObject: [type: fields]))
    }

    private func branch(_ value: String) -> [String: Any] {
        ["header.Modifier": ["name": "X-Branch", "value": value]]
    }

    func testCanonicalFiltersSelectBothBranchesAndRespectScope() throws {
        let fixtures: [(String, [String: Any])] = [
            ("header.Filter", ["name": "x-mode", "value": "live"]),
            ("querystring.Filter", ["name": "q", "value": "second"]),
            ("cookie.Filter", ["name": "flag", "value": "two"]),
            ("method.Filter", ["method": "get"]),
            (
                "url.Filter",
                [
                    "scheme": "https", "host": "*.example.test:8443", "path": "/v1/items",
                    "query": "q=first&q=second",
                ]
            ),
            ("url.RegexFilter", ["regex": "^https://api\\.example\\.test:8443/v1/"]),
        ]
        for (type, var fields) in fixtures {
            fields["modifier"] = branch("true")
            fields["else"] = branch("false")
            fields["scope"] = ["request"]
            let modifier = try parse(type, fields)
            var matching = request()
            try modifier.modify(request: &matching)
            XCTAssertEqual(matching.head["X-Branch"], "true", type)

            var other = RequestContext(
                method: "POST", target: "http://else.test/", head: HTTPHead(startLine: "POST / HTTP/1.1"))
            try modifier.modify(request: &other)
            XCTAssertEqual(other.head["X-Branch"], "false", type)
            var response = ResponseContext(
                requestMethod: "GET", target: matching.target,
                head: HTTPHead(startLine: "HTTP/1.1 200 OK"))
            try modifier.modify(response: &response)
            XCTAssertNil(response.head["X-Branch"], type)
        }
    }

    func testResponseConditionsUseResponseCookiesHeadersAndRequestURL() throws {
        for (type, fields) in [
            ("cookie.Filter", ["name": "token", "value": "secret"]),
            ("header.Filter", ["name": "content-type", "value": "application/json"]),
            ("querystring.Filter", ["name": "q", "value": "second"]),
        ] {
            var fields: [String: Any] = fields
            fields["scope"] = ["response"]
            fields["modifier"] = branch("true")
            fields["else"] = branch("false")
            let modifier = try parse(type, fields)
            var response = ResponseContext(
                requestMethod: "GET", target: request().target,
                head: HTTPHead(
                    startLine: "HTTP/1.1 200 OK",
                    headers: [
                        ("Set-Cookie", "other=no; Path=/"),
                        ("Set-Cookie", "token=secret; Secure; HttpOnly"),
                        ("Content-Type", "application/json"),
                    ]))
            try modifier.modify(response: &response)
            XCTAssertEqual(response.head["X-Branch"], "true", type)
        }
    }

    func testCanonicalHeaderRegexUsesOriginalRequestHeadersForResponse() throws {
        let modifier = try parse(
            "header.RegexFilter", ["header": "X-Mode", "regex": "^preview$", "modifier": branch("true")])
        var response = ResponseContext(
            requestMethod: "GET", target: request().target,
            head: HTTPHead(startLine: "HTTP/1.1 200 OK"), requestHead: request().head)
        try modifier.modify(response: &response)
        XCTAssertEqual(response.head["X-Branch"], "true")
    }

    func testPresenceAndEmptyValuesAreExplicit() throws {
        let native = try MatchModifier(
            condition: MatchCondition(kind: .header, name: "X-Mode"),
            modifier: HeaderModifier(scope: .request, name: "X-Found", value: "yes"))
        var value = request()
        try native.modify(request: &value)
        XCTAssertEqual(value.head["X-Found"], "yes")
        // The pinned Martian header matcher treats omitted value as an exact empty value.
        let canonical = try parse(
            "header.Filter", ["name": "X-Mode", "modifier": branch("true"), "else": branch("false")])
        try canonical.modify(request: &value)
        XCTAssertEqual(value.head["X-Branch"], "false")
        value.head["X-Mode"] = ""
        try canonical.modify(request: &value)
        XCTAssertEqual(value.head["X-Branch"], "true")
    }

    func testURLAndPortRewritingPreserveUntouchedEncodedFields() throws {
        let modifier = try parse(
            "url.Modifier",
            [
                "scheme": "http", "host": "[::1]:9090",
                "path": "/new path", "query": "q=a%2Fb&flag=",
            ])
        var value = request()
        try modifier.modify(request: &value)
        XCTAssertEqual(value.target, "http://[::1]:9090/new%20path?q=a%2Fb&flag=")
        XCTAssertEqual(value.head["Host"], "[::1]:9090")

        let remove = try parse("port.Modifier", ["remove": true])
        try remove.modify(request: &value)
        XCTAssertEqual(value.head["Host"], "[::1]")
        let schemeDefault = try parse("port.Modifier", ["defaultForScheme": true])
        try schemeDefault.modify(request: &value)
        XCTAssertEqual(value.head["Host"], "[::1]:80")
        let port = try parse("port.Modifier", ["port": 8123])
        try port.modify(request: &value)
        XCTAssertEqual(value.target, "http://[::1]:8123/new%20path?q=a%2Fb&flag=")
    }

    func testPortFilterMatchesImplicitSchemeDefaults() throws {
        for (target, port) in [
            ("http://example.test/", 80), ("https://example.test/", 443),
            ("http://[::1]:8123/", 8123),
        ] {
            let modifier = try parse("port.Filter", ["port": port, "modifier": branch("true")])
            var value = request(target)
            try modifier.modify(request: &value)
            XCTAssertEqual(value.head["X-Branch"], "true")
        }
    }

    func testNativeRulesRoundTripAndComposeWithExistingRules() throws {
        let json = Data(
            #"""
            {"modifier":{"type":"match","scope":["request"],
              "condition":{"kind":"headerRegex","name":"X-Mode","regex":"^live$"},
              "modifier":{"type":"group","modifiers":[
                {"type":"url","host":"localhost","path":"/rewritten"},
                {"type":"port","port":9000}]},
              "else":{"type":"header","scope":["request"],"name":"X-Skipped","value":"yes"}}}
            """#.utf8)
        let document = try JSONDecoder().decode(RuntimeConfigurationDocument.self, from: json)
        let roundTrip = try JSONDecoder().decode(
            RuntimeConfigurationDocument.self, from: JSONEncoder().encode(document))
        let runtime = RuntimeConfiguration()
        try runtime.replace(with: roundTrip)
        var value = request()
        try runtime.modify(request: &value)
        XCTAssertEqual(value.target, "https://localhost:9000/rewritten?q=first&q=second")
        value.head.remove("X-Mode")
        try runtime.modify(request: &value)
        XCTAssertEqual(value.head["X-Skipped"], "yes")
    }

    func testNestedFiltersAndResponseElseBranch() throws {
        let inner: [String: Any] = [
            "querystring.Filter": ["name": "q", "value": "second", "modifier": branch("nested")]
        ]
        let modifier = try parse(
            "url.Filter", ["host": "api.example.test:8443", "modifier": inner, "else": branch("else")])
        var response = ResponseContext(
            requestMethod: "GET", target: request().target, head: HTTPHead(startLine: "HTTP/1.1 200 OK"))
        try modifier.modify(response: &response)
        XCTAssertEqual(response.head["X-Branch"], "nested")
        response = ResponseContext(
            requestMethod: "GET", target: "https://other.test/", head: HTTPHead(startLine: "HTTP/1.1 200 OK"))
        try modifier.modify(response: &response)
        XCTAssertEqual(response.head["X-Branch"], "else")
    }

    func testInvalidRulesLeavePreviousRuntimeConfigurationActive() throws {
        let runtime = RuntimeConfiguration()
        try runtime.replace(martianJSON: JSONSerialization.data(withJSONObject: branch("original")))
        let invalid: [(String, [String: Any])] = [
            ("port.Modifier", ["port": 0]), ("port.Modifier", ["port": 65536]),
            ("port.Modifier", ["port": 80, "remove": true]), ("port.Modifier", ["port": true]),
            ("url.Modifier", ["host": "user:password@localhost"]),
            ("url.Modifier", ["host": "localhost/path"]), ("url.Modifier", ["scheme": "file"]),
            ("url.Modifier", ["query": "q=x#fragment"]), ("url.Modifier", ["path": "relative"]),
            ("url.RegexFilter", ["regex": "(", "modifier": branch("bad")]),
            ("url.Filter", ["scope": "request", "modifier": branch("bad")]),
            ("method.Filter", ["method": "GET\r\nInjected: yes", "modifier": branch("bad")]),
            ("header.Filter", ["name": "X", "modifier": branch("ok"), "else": ["bad.Modifier": [:]]]),
        ]
        for (type, fields) in invalid {
            let data = try JSONSerialization.data(withJSONObject: [type: fields])
            XCTAssertThrowsError(try runtime.replace(martianJSON: data), type)
            var value = request()
            try runtime.modify(request: &value)
            XCTAssertEqual(value.head["X-Branch"], "original")
        }
    }

    func testRegexTimeLimitPropagatesThroughRuntime() throws {
        let runtime = RuntimeConfiguration()
        let json = try JSONSerialization.data(withJSONObject: [
            "header.RegexFilter": [
                "scope": ["request"], "header": "X-Long", "regex": "(a+)+$", "modifier": branch("bad"),
            ]
        ])
        try runtime.replace(martianJSON: json)
        var value = request()
        value.head["X-Long"] = String(repeating: "a", count: 20_000) + "!"
        let start = ContinuousClock.now
        XCTAssertThrowsError(try runtime.modify(request: &value))
        XCTAssertLessThan(start.duration(to: .now), .seconds(2))
    }

    func testUpstreamProxyRejectsUnsupportedURLsAndEmbeddedSecrets() throws {
        for url in [
            "socks4://localhost:8888", "ftp://localhost:8888", "http://u:p@localhost:8888",
            "http://localhost:8888/path", "http://localhost:0", "http://localhost:65536",
            "http://localhost:8888/?q=x", "http://localhost:8888/#fragment",
        ] {
            XCTAssertThrowsError(try UpstreamProxy(url: url), url)
        }
        let proxy = try UpstreamProxy(
            url: "http://[::1]:8888", credentials: ProxyCredentials(username: "next", password: "secret"))
        XCTAssertEqual(proxy.host, "::1")
        XCTAssertEqual(proxy.port, 8888)
        XCTAssertEqual(proxy.authorization, "Basic " + Data("next:secret".utf8).base64EncodedString())
    }
}
