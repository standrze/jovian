import Foundation
import Logging

/// A captured HTTP header field preserving its name and value.
public struct LoggedHeader: Codable, Sendable {
    public let name: String
    public let value: String
    /// Creates a captured field; redaction is the caller's responsibility.
    public init(name: String, value: String) {
        self.name = name
        self.value = value
    }
}

/// A completed exchange summary with optional captured headers and buffered bodies.
public struct TrafficEntry: Codable, Sendable {
    public let timestamp: Date
    public let method: String
    public let target: String
    public let status: Int
    /// Response payload bytes, including only upstream-to-client bytes for a raw tunnel.
    public let bytes: Int
    public let durationMilliseconds: Int
    public let transport: String
    public let error: String?
    public let requestHeaders: [LoggedHeader]
    public let responseHeaders: [LoggedHeader]
    public let requestBody: Data?
    public let responseBody: Data?
    public let requestBodyTruncated: Bool
    public let responseBodyTruncated: Bool

    /// Creates a traffic record with a duration in milliseconds and byte counts excluding HTTP framing.
    ///
    /// Callers provide redacted headers as needed and mark bodies omitted or limited by buffering.
    public init(
        timestamp: Date, method: String, target: String, status: Int, bytes: Int,
        durationMilliseconds: Int, transport: String, error: String?,
        requestHeaders: [LoggedHeader] = [], responseHeaders: [LoggedHeader] = [],
        requestBody: Data? = nil, responseBody: Data? = nil,
        requestBodyTruncated: Bool = false, responseBodyTruncated: Bool = false
    ) {
        self.timestamp = timestamp
        self.method = method
        self.target = target
        self.status = status
        self.bytes = bytes
        self.durationMilliseconds = durationMilliseconds
        self.transport = transport
        self.error = error
        self.requestHeaders = requestHeaders
        self.responseHeaders = responseHeaders
        self.requestBody = requestBody
        self.responseBody = responseBody
        self.requestBodyTruncated = requestBodyTruncated
        self.responseBodyTruncated = responseBodyTruncated
    }
}

/// A synchronous traffic sink that may be called concurrently by proxy workers.
public protocol TrafficLogger: Sendable {
    /// Records one completed exchange; implementations define persistence and failure handling.
    func record(_ entry: TrafficEntry)
}

/// Emits traffic summaries through the application's SwiftLog backend.
///
/// Headers and bodies remain in dedicated traffic stores; they are never added to log metadata.
/// Diagnostic targets omit URL credentials, query strings, and fragments. Traffic entries stay intact.
public final class ConsoleTrafficLogger: TrafficLogger {
    private let logger: Logger

    /// Uses the supplied SwiftLog backend for exchange summaries.
    public init(logger: Logger = Logger(label: "jovian.traffic")) {
        self.logger = logger
    }

    /// Emits summary metadata with a sanitized target, without captured headers or bodies.
    public func record(_ entry: TrafficEntry) {
        var metadata: Logger.Metadata = [
            "method": .string(entry.method),
            "target": .string(Self.diagnosticTarget(entry.target, method: entry.method)),
            "status": .stringConvertible(entry.status),
            "bytes": .stringConvertible(entry.bytes),
            "duration_ms": .stringConvertible(entry.durationMilliseconds),
            "transport": .string(entry.transport),
        ]
        if let error = entry.error { metadata["error"] = .string(error) }
        logger.log(
            level: entry.error == nil ? .info : .error,
            "request completed", metadata: metadata)
    }

    private static func diagnosticTarget(_ target: String, method: String) -> String {
        // CONNECT carries an authority rather than an absolute URI; parse it with a temporary scheme.
        let authority = method == "CONNECT"
        guard var components = URLComponents(string: authority ? "http://\(target)" : target),
            components.scheme == nil || components.host != nil
        else { return "[invalid target]" }
        components.user = nil
        components.password = nil
        components.query = nil
        components.fragment = nil
        guard let sanitized = components.string else { return "[invalid target]" }
        return authority ? String(sanitized.dropFirst("http://".count)) : sanitized
    }
}

/// Appends traffic records as JSON Lines, silently dropping encoding or write failures.
///
/// The lock serializes the shared JSON encoder and file handle. Deinitialization closes the handle
/// after callers release the logger. Captured content is written exactly as supplied.
public final class JSONLinesTrafficLogger: TrafficLogger, @unchecked Sendable {
    private let lock = NSLock()
    private let handle: FileHandle
    private let encoder = JSONEncoder()

    /// Creates the destination file, opens it for writing, and throws if opening or seeking fails.
    public init(url: URL) throws {
        FileManager.default.createFile(atPath: url.path, contents: nil)
        handle = try FileHandle(forWritingTo: url)
        try handle.seekToEnd()
        encoder.dateEncodingStrategy = .iso8601
    }

    deinit { try? handle.close() }

    /// Appends one UTF-8 JSON record followed by a newline.
    public func record(_ entry: TrafficEntry) {
        lock.withLock {
            guard var data = try? encoder.encode(entry) else { return }
            data.append(0x0A)
            try? handle.write(contentsOf: data)
        }
    }
}

/// Delivers each traffic record to a fixed list of sinks in order.
public struct CompositeTrafficLogger: TrafficLogger {
    public let loggers: [any TrafficLogger]
    /// Creates a composite retaining the supplied sinks.
    public init(_ loggers: [any TrafficLogger]) { self.loggers = loggers }
    /// Calls each sink synchronously in the configured order.
    public func record(_ entry: TrafficEntry) { loggers.forEach { $0.record(entry) } }
}
