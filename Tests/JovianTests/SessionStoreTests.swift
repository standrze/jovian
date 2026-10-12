import XCTest

@testable import Jovian

final class SessionStoreTests: XCTestCase {
    private func fixture() throws -> (URL, JovianSessionStore) {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(
            "jovian-session-tests-" + UUID().uuidString)
        return (directory, try JovianSessionStore(directory: directory))
    }
    private func exchange(_ body: String = "private payload") -> JovianExchange {
        JovianExchange(
            id: UUID().uuidString, url: "https://example.test/item", method: "GET", status: 200,
            headers: [:], body: body, bodyEncoding: "utf8", truncated: false, durationMilliseconds: 1)
    }
    func testRestartRetentionLifecycleAndPermissions() throws {
        let (directory, store) = try fixture()
        defer { try? FileManager.default.removeItem(at: directory) }
        let value = try store.create(name: "development", origin: "https://example.test")
        try store.append(exchange(), sessionID: value.id)
        let restarted = try JovianSessionStore(directory: directory)
        XCTAssertEqual(try restarted.resolve("development").id, value.id)
        XCTAssertEqual(try restarted.load(value.id).exchanges.first?.body, "")
        XCTAssertEqual(try restarted.load(value.id).exchanges.first?.bodyOmitted, true)
        try restarted.setBodyRetention(value.id, enabled: true)
        try restarted.append(exchange("retained"), sessionID: value.id)
        XCTAssertEqual(try store.load(value.id).exchanges.last?.body, "retained")
        try store.setBodyRetention(value.id, enabled: false)
        XCTAssertTrue(try store.load(value.id).exchanges.allSatisfy { $0.body.isEmpty })
        try store.close(value.id)
        XCTAssertTrue(try restarted.load(value.id).closed)
        XCTAssertThrowsError(try JovianProxySession(store: store, id: value.id))
        try restarted.resume(value.id)
        XCTAssertFalse(try store.load(value.id).closed)
        let file = directory.appendingPathComponent(value.id.uuidString.lowercased() + ".json")
        XCTAssertEqual(
            (try FileManager.default.attributesOfItem(atPath: file.path)[.posixPermissions] as? NSNumber)?.intValue,
            0o600)
        XCTAssertEqual(
            (try FileManager.default.attributesOfItem(atPath: directory.path)[.posixPermissions] as? NSNumber)?
                .intValue, 0o700)
        try store.delete(value.id)
        XCTAssertThrowsError(try store.load(value.id))
        XCTAssertThrowsError(try store.append(exchange(), sessionID: value.id))
    }
    func testCookieIsolationExpiryAndPath() throws {
        let (directory, store) = try fixture()
        defer { try? FileManager.default.removeItem(at: directory) }
        let a = try store.create(name: "a", origin: "https://example.test")
        let b = try store.create(name: "b", origin: "https://example.test")
        let source = URL(string: "https://example.test/account")!
        let native = HTTPCookie(properties: [
            .name: "login", .value: "secret", .domain: "example.test", .path: "/account", .secure: "TRUE",
        ])!
        let cookie = JovianCookie(native, source: source)!
        try store.saveCookies([cookie], sessionID: a.id)
        XCTAssertEqual(try store.load(a.id).cookies.count, 1)
        XCTAssertTrue(try store.load(b.id).cookies.isEmpty)
        XCTAssertTrue(cookie.matches(URL(string: "https://example.test/account/item")!))
        XCTAssertFalse(cookie.matches(URL(string: "https://example.test/accounting")!))
        XCTAssertFalse(cookie.matches(URL(string: "http://example.test/account")!))
        XCTAssertFalse(cookie.matches(URL(string: "https://other.test/account")!))
        let expired = HTTPCookie(properties: [
            .name: "login", .value: "", .domain: "example.test", .path: "/account",
            .expires: Date(timeIntervalSince1970: 1),
        ])!
        try store.saveCookies([JovianCookie(expired, source: source)!], sessionID: a.id)
        XCTAssertTrue(try store.load(a.id).cookies.isEmpty)
    }
    func testHistoryBoundAndSeparateStoresMerge() throws {
        let (directory, store) = try fixture()
        defer { try? FileManager.default.removeItem(at: directory) }
        let value = try store.create(name: "bounded", origin: "http://example.test", retainBodies: true)
        let other = try JovianSessionStore(directory: directory)
        for index in 0..<45 {
            try (index % 2 == 0 ? store : other).append(exchange(String(index)), sessionID: value.id)
        }
        let loaded = try store.load(value.id)
        XCTAssertEqual(loaded.exchanges.count, 40)
        XCTAssertEqual(loaded.exchanges.first?.body, "5")
        XCTAssertEqual(loaded.exchanges.last?.body, "44")
        XCTAssertThrowsError(try store.create(name: "bounded", origin: "http://example.test"))
        XCTAssertThrowsError(try store.resolve("../../etc/passwd"))
    }
    func testProxyScopeAndClosedSession() throws {
        let (directory, store) = try fixture()
        defer { try? FileManager.default.removeItem(at: directory) }
        let value = try store.create(name: "scope", origin: "https://example.test")
        let session = try JovianProxySession(store: store, id: value.id)
        XCTAssertNoThrow(try session.validate(method: "CONNECT", target: "example.test:443"))
        XCTAssertThrowsError(try session.validate(method: "CONNECT", target: "example.test:80"))
        XCTAssertThrowsError(try session.validate(method: "GET", target: "https://other.test"))
        try store.close(value.id)
        XCTAssertThrowsError(try session.validate(method: "GET", target: "https://example.test"))
    }
    func testConcurrentWritersDoNotLoseHistory() throws {
        let (directory, store) = try fixture()
        defer { try? FileManager.default.removeItem(at: directory) }
        let value = try store.create(name: "concurrent", origin: "http://example.test")
        let other = try JovianSessionStore(directory: directory)
        DispatchQueue.concurrentPerform(iterations: 20) { index in
            try? (index % 2 == 0 ? store : other).append(exchange(String(index)), sessionID: value.id)
        }
        let history = try store.load(value.id).exchanges
        XCTAssertEqual(history.count, 20)
        XCTAssertEqual(Set(history.map(\.id)).count, 20)
    }
}
