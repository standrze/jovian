import DequeModule
import Foundation

/// Bounded HAR history.
///
/// Body retention is disabled unless a capture policy is supplied.
public final class HARStore: TrafficLogger, @unchecked Sendable {
    private let lock = NSLock()
    private let maximumEntries: Int
    private let capturePolicy: BodyCapturePolicy?
    private let maximumRetainedBodyBytes: Int
    private var retainedBodyBytes = 0
    private var entries: Deque<TrafficEntry> = []

    public init(
        maximumEntries: Int = 10_000, capturePolicy: BodyCapturePolicy? = nil,
        maximumRetainedBodyBytes: Int = 32 * 1_024 * 1_024
    ) {
        self.maximumEntries = max(1, maximumEntries)
        self.capturePolicy = capturePolicy
        self.maximumRetainedBodyBytes = max(0, maximumRetainedBodyBytes)
    }

    public func record(_ entry: TrafficEntry) {
        let request = capturePolicy?.capture(
            entry.requestBody, headers: entry.requestHeaders,
            truncated: entry.requestBodyTruncated)
        let response = capturePolicy?.capture(
            entry.responseBody, headers: entry.responseHeaders,
            truncated: entry.responseBodyTruncated)
        let retained = TrafficEntry(
            timestamp: entry.timestamp, method: entry.method, target: entry.target, status: entry.status,
            bytes: entry.bytes, durationMilliseconds: entry.durationMilliseconds, transport: entry.transport,
            error: entry.error, requestHeaders: entry.requestHeaders, responseHeaders: entry.responseHeaders,
            requestBody: request?.data, responseBody: response?.data,
            requestBodyTruncated: request?.truncated ?? entry.requestBodyTruncated,
            responseBodyTruncated: response?.truncated ?? entry.responseBodyTruncated)
        lock.withLock {
            entries.append(retained)
            retainedBodyBytes += Self.bodyBytes(retained)
            while entries.count > maximumEntries || retainedBodyBytes > maximumRetainedBodyBytes {
                retainedBodyBytes -= Self.bodyBytes(entries.removeFirst())
            }
        }
    }

    public func reset() {
        lock.withLock {
            entries.removeAll(keepingCapacity: true)
            retainedBodyBytes = 0
        }
    }
    public func count() -> Int { lock.withLock { entries.count } }

    public func encodedHAR() throws -> Data {
        let snapshot = lock.withLock { entries }
        let harEntries: [[String: Any]] = snapshot.map { entry in
            let queryItems =
                URLComponents(string: entry.target)?.queryItems?.map {
                    ["name": $0.name, "value": $0.value ?? ""]
                } ?? []
            var request: [String: Any] = [
                "method": entry.method, "url": entry.target, "httpVersion": "HTTP/1.1",
                "headers": entry.requestHeaders.map { ["name": $0.name, "value": $0.value] },
                "queryString": queryItems, "cookies": [],
                "headersSize": Self.headerSize(entry.requestHeaders), "bodySize": -1,
            ]
            if let body = entry.requestBody {
                var postData: [String: Any] = [
                    "mimeType": Self.mimeType(entry.requestHeaders),
                    "_truncated": entry.requestBodyTruncated,
                ]
                if let text = String(data: body, encoding: .utf8) {
                    postData["text"] = text
                } else {
                    postData["text"] = body.base64EncodedString()
                    postData["_encoding"] = "base64"
                }
                request["postData"] = postData
            }
            var content: [String: Any] = ["size": entry.bytes, "mimeType": Self.mimeType(entry.responseHeaders)]
            if let body = entry.responseBody {
                content["text"] = body.base64EncodedString()
                content["encoding"] = "base64"
                content["_truncated"] = entry.responseBodyTruncated
            }
            return [
                "startedDateTime": ISO8601DateFormatter().string(from: entry.timestamp),
                "time": entry.durationMilliseconds, "request": request,
                "response": [
                    "status": entry.status, "statusText": entry.error ?? "", "httpVersion": "HTTP/1.1",
                    "headers": entry.responseHeaders.map { ["name": $0.name, "value": $0.value] },
                    "cookies": [], "content": content, "redirectURL": "",
                    "headersSize": Self.headerSize(entry.responseHeaders), "bodySize": entry.bytes,
                ],
                "cache": [:], "timings": ["send": 0, "wait": entry.durationMilliseconds, "receive": 0],
                "comment": entry.transport,
            ]
        }
        return try JSONSerialization.data(
            withJSONObject: [
                "log": [
                    "version": "1.2", "creator": ["name": "jovian", "version": "0.3.0"], "entries": harEntries,
                ]
            ], options: [.sortedKeys])
    }

    private static func bodyBytes(_ entry: TrafficEntry) -> Int {
        (entry.requestBody?.count ?? 0) + (entry.responseBody?.count ?? 0)
    }
    private static func mimeType(_ headers: [LoggedHeader]) -> String {
        headers.first { $0.name.caseInsensitiveCompare("Content-Type") == .orderedSame }?.value
            ?? "application/octet-stream"
    }
    private static func headerSize(_ headers: [LoggedHeader]) -> Int {
        headers.reduce(2) { $0 + $1.name.utf8.count + $1.value.utf8.count + 4 }
    }
}

/// Keeps a bounded HAR on disk so traffic remains inspectable after the proxy stops.
///
/// One lock serializes destinations, stores, file writes, and error state. Each store also
/// protects its own entry history, with the file logger lock always acquired first.
public final class HARFileLogger: TrafficLogger, @unchecked Sendable {
    private let maximumEntries: Int
    private let lock = NSLock()
    private var activeURL: URL
    private var stores: [URL: HARStore]
    private var fileError: String?

    /// Creates a new HAR file and parent directories; throws if the file already exists or creation fails.
    ///
    /// Each destination retains at least one entry and otherwise uses `maximumEntries` as its limit.
    public init(url: URL, maximumEntries: Int = 1_000) throws {
        self.maximumEntries = maximumEntries
        activeURL = url
        let store = HARStore(maximumEntries: maximumEntries)
        stores = [url: store]
        try FileManager.default.createDirectory(
            at: url.deletingLastPathComponent(), withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700])
        try store.encodedHAR().write(to: url, options: .withoutOverwriting)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
    }

    /// The active destination for subsequent traffic records.
    public var url: URL { lock.withLock { activeURL } }

    /// Switches to a run file, creating it on first use and preserving its earlier history on return.
    ///
    /// Throws on file creation failure; an existing file is never adopted implicitly.
    public func setDestination(_ url: URL) throws {
        try lock.withLock {
            if stores[url] == nil {
                let store = HARStore(maximumEntries: maximumEntries)
                try FileManager.default.createDirectory(
                    at: url.deletingLastPathComponent(), withIntermediateDirectories: true,
                    attributes: [.posixPermissions: 0o700])
                try store.encodedHAR().write(to: url, options: .withoutOverwriting)
                try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
                stores[url] = store
            }
            activeURL = url
            fileError = nil
        }
    }

    /// Records traffic and rewrites the active HAR atomically, retaining write failures in `lastError`.
    public func record(_ entry: TrafficEntry) {
        lock.withLock {
            guard let store = stores[activeURL] else { return }
            store.record(entry)
            do {
                try store.encodedHAR().write(to: activeURL, options: .atomic)
                try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: activeURL.path)
                fileError = nil
            } catch {
                fileError = error.localizedDescription
            }
        }
    }

    /// The most recent write failure, cleared after a successful write or destination change.
    public var lastError: String? { lock.withLock { fileError } }
}
