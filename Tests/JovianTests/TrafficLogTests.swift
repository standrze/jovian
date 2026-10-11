import Foundation
import Logging
import XCTest

@testable import Jovian

final class TrafficLogTests: XCTestCase {
    private struct Record: Sendable {
        let level: Logger.Level
        let message: String
        let metadata: Logger.Metadata
    }

    // A handler may be called concurrently; all captured records are protected by this lock.
    private final class Records: @unchecked Sendable {
        private let lock = NSLock()
        private var storage: [Record] = []

        func append(_ record: Record) { lock.withLock { storage.append(record) } }
        var values: [Record] { lock.withLock { storage } }
    }

    private struct RecordingHandler: LogHandler {
        let records: Records
        var metadata: Logger.Metadata = [:]
        var logLevel: Logger.Level = .info

        subscript(metadataKey key: String) -> Logger.Metadata.Value? {
            get { metadata[key] }
            set { metadata[key] = newValue }
        }

        func log(event: LogEvent) {
            records.append(
                Record(
                    level: event.level, message: event.message.description,
                    metadata: metadata.merging(event.metadata ?? [:], uniquingKeysWith: { _, value in value })))
        }
    }

    func testConsoleTrafficUsesInjectedBackendWithoutHeadersOrBodies() throws {
        let records = Records()
        var logger = Logger(label: "test.traffic") { _ in RecordingHandler(records: records) }
        logger[metadataKey: "application"] = "test"
        let traffic = ConsoleTrafficLogger(logger: logger)
        for error in [nil, "connection closed"] as [String?] {
            traffic.record(
                TrafficEntry(
                    timestamp: Date(), method: "GET", target: "http://example.test/path",
                    status: error == nil ? 200 : 502, bytes: 23, durationMilliseconds: 7,
                    transport: "http", error: error,
                    requestHeaders: [LoggedHeader(name: "Authorization", value: "secret-request-header")],
                    responseHeaders: [LoggedHeader(name: "Set-Cookie", value: "secret-response-header")],
                    requestBody: Data("secret-request-body".utf8), responseBody: Data("secret-response-body".utf8)))
        }

        let captured = records.values
        XCTAssertEqual(captured.map(\.level), [.info, .error])
        let success = try XCTUnwrap(captured.first)
        XCTAssertEqual(success.message, "request completed")
        XCTAssertEqual(success.metadata["application"]?.description, "test")
        XCTAssertEqual(success.metadata["method"]?.description, "GET")
        XCTAssertEqual(success.metadata["target"]?.description, "http://example.test/path")
        XCTAssertEqual(success.metadata["status"]?.description, "200")
        XCTAssertEqual(success.metadata["bytes"]?.description, "23")
        XCTAssertEqual(success.metadata["duration_ms"]?.description, "7")
        XCTAssertEqual(success.metadata["transport"]?.description, "http")
        XCTAssertNil(success.metadata["error"])
        XCTAssertEqual(captured.last?.metadata["error"]?.description, "connection closed")
        for record in captured {
            XCTAssertFalse(record.message.contains("secret-"))
            XCTAssertFalse(String(describing: record.metadata).contains("secret-"))
        }
    }

    func testConsoleTargetsOmitCredentialsQueryAndFragmentWithoutChangingTrafficHistory() throws {
        let records = Records()
        let logger = Logger(label: "test.traffic") { _ in RecordingHandler(records: records) }
        let history = HARStore()
        let traffic = CompositeTrafficLogger([ConsoleTrafficLogger(logger: logger), history])
        let cases = [
            (
                "GET", "https://fixture-user:secret-password@example.test/path?token=secret-query#secret-fragment",
                "https://example.test/path"
            ),
            ("GET", "/relative?token=secret-query#secret-fragment", "/relative"),
            ("CONNECT", "127.0.0.1:443", "127.0.0.1:443"),
            ("CONNECT", "[::1]:8443", "[::1]:8443"),
            ("CONNECT", "fixture-user:secret-password@localhost:443", "localhost:443"),
            ("GET", "http://[invalid?token=secret-query", "[invalid target]"),
        ]
        for (method, target, _) in cases {
            traffic.record(
                TrafficEntry(
                    timestamp: Date(), method: method, target: target,
                    status: 200, bytes: 0, durationMilliseconds: 1, transport: "fixture", error: nil))
        }

        XCTAssertEqual(records.values.compactMap { $0.metadata["target"]?.description }, cases.map { $0.2 })
        for record in records.values {
            XCTAssertFalse(String(describing: record.metadata).contains("secret-"))
        }
        let document = try XCTUnwrap(try JSONSerialization.jsonObject(with: history.encodedHAR()) as? [String: Any])
        let log = try XCTUnwrap(document["log"] as? [String: Any])
        let entries = try XCTUnwrap(log["entries"] as? [[String: Any]])
        let targets = entries.compactMap { ($0["request"] as? [String: Any])?["url"] as? String }
        XCTAssertEqual(targets, cases.map { $0.1 })
    }
}
