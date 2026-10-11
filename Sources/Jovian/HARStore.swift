import DequeModule
import Foundation

/// An in-memory, bounded traffic history exported as HAR 1.2 metadata.
///
/// The lock protects every access to the entry deque. Encoding uses an independent snapshot.
public final class HARStore: TrafficLogger, @unchecked Sendable {
    private let lock = NSLock()
    private let maximumEntries: Int
    private var entries: Deque<TrafficEntry> = []

    /// Creates an empty history, retaining at least one entry even for a nonpositive limit.
    public init(maximumEntries: Int = 10_000) { self.maximumEntries = max(1, maximumEntries) }

    /// Appends an entry and discards the oldest entries when the capacity is exceeded.
    public func record(_ entry: TrafficEntry) {
        lock.withLock {
            entries.append(entry)
            if entries.count > maximumEntries { entries.removeFirst(entries.count - maximumEntries) }
        }
    }

    /// Removes all retained traffic entries.
    public func reset() { lock.withLock { entries.removeAll(keepingCapacity: true) } }
    /// Returns the number of currently retained entries.
    public func count() -> Int { lock.withLock { entries.count } }

    /// Encodes a snapshot of traffic metadata; bodies and parsed cookies are not included.
    ///
    /// Throws if the generated document cannot be serialized as JSON.
    public func encodedHAR() throws -> Data {
        let snapshot = lock.withLock { entries }
        let harEntries: [[String: Any]] = snapshot.map { entry in
            let queryItems =
                URLComponents(string: entry.target)?.queryItems?.map {
                    ["name": $0.name, "value": $0.value ?? ""]
                } ?? []
            let requestHeaderSize = Self.headerSize(entry.requestHeaders)
            let responseHeaderSize = Self.headerSize(entry.responseHeaders)
            let mimeType =
                entry.responseHeaders.first {
                    $0.name.caseInsensitiveCompare("Content-Type") == .orderedSame
                }?.value ?? "application/octet-stream"
            return [
                "startedDateTime": ISO8601DateFormatter().string(from: entry.timestamp),
                "time": entry.durationMilliseconds,
                "request": [
                    "method": entry.method,
                    "url": entry.target,
                    "httpVersion": "HTTP/1.1",
                    "headers": entry.requestHeaders.map { ["name": $0.name, "value": $0.value] },
                    "queryString": queryItems, "cookies": [],
                    "headersSize": requestHeaderSize, "bodySize": -1,
                ],
                "response": [
                    "status": entry.status,
                    "statusText": entry.error ?? "",
                    "httpVersion": "HTTP/1.1",
                    "headers": entry.responseHeaders.map { ["name": $0.name, "value": $0.value] },
                    "cookies": [],
                    "content": ["size": entry.bytes, "mimeType": mimeType],
                    "redirectURL": "", "headersSize": responseHeaderSize, "bodySize": entry.bytes,
                ],
                "cache": [:],
                "timings": ["send": 0, "wait": entry.durationMilliseconds, "receive": 0],
                "comment": entry.transport,
            ]
        }
        let root: [String: Any] = [
            "log": [
                "version": "1.2",
                "creator": ["name": "jovian", "version": "0.2.0"],
                "entries": harEntries,
            ]
        ]
        return try JSONSerialization.data(withJSONObject: root, options: [.sortedKeys, .prettyPrinted])
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
