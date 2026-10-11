import Foundation
import NIOHTTP1

/// Protocol, connection, and unsupported-feature failures reported by the proxy.
public enum ProxyError: Error, CustomStringConvertible {
    case invalidHTTP(String)
    case connection(String)
    case unsupported(String)

    /// A diagnostic summary of the failure category and detail.
    public var description: String {
        switch self {
        case .invalidHTTP(let message): "invalid HTTP: \(message)"
        case .connection(let message): "connection error: \(message)"
        case .unsupported(let message): "unsupported: \(message)"
        }
    }
}

/// An HTTP start line and ordered headers, preserving duplicate field names.
public struct HTTPHead: Sendable {
    public var startLine: String
    public var headers: [(name: String, value: String)]

    /// Creates a head; header syntax is checked when it is converted to a wire message.
    public init(startLine: String, headers: [(String, String)] = []) {
        self.startLine = startLine
        self.headers = headers
    }

    /// Reads the first case-insensitive match or replaces all matches with one value.
    ///
    /// Assigning `nil` removes all matches. Invalid names or values are ignored.
    public subscript(_ name: String) -> String? {
        get { headers.first { $0.name.caseInsensitiveCompare(name) == .orderedSame }?.value }
        set {
            if let newValue, !Self.isValidHeader(name: name, value: newValue) { return }
            headers.removeAll { $0.name.caseInsensitiveCompare(name) == .orderedSame }
            if let newValue { headers.append((name, newValue)) }
        }
    }

    /// Removes every header matching the name, ignoring case.
    public mutating func remove(_ name: String) { self[name] = nil }

    /// Returns all matching values in their original order, ignoring name case.
    public func values(for name: String) -> [String] {
        headers.compactMap { $0.name.caseInsensitiveCompare(name) == .orderedSame ? $0.value : nil }
    }

    /// Replaces all matching fields, preserving value order; invalid replacements are ignored.
    public mutating func replaceValues(for name: String, with values: [String]) {
        guard values.allSatisfy({ Self.isValidHeader(name: name, value: $0) }) else { return }
        headers.removeAll { $0.name.caseInsensitiveCompare(name) == .orderedSame }
        headers.append(contentsOf: values.map { (name, $0) })
    }

    /// Appends a field without replacing duplicates; invalid names or values are ignored.
    public mutating func add(name: String, value: String) {
        guard Self.isValidHeader(name: name, value: value) else { return }
        headers.append((name, value))
    }

    /// Returns normalized, nonempty tokens from all `Connection` fields.
    public func connectionTokens() -> [String] {
        values(for: "Connection").flatMap { value in
            value.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces).lowercased() }
        }.filter { !$0.isEmpty }
    }

    /// Removes headers scoped to a single transport connection.
    ///
    /// Framing headers remain as metadata for the NIO request/response normalization boundary.
    public mutating func removeHopByHopHeaders(preservingUpgrade: Bool = false) {
        let nominated = connectionTokens()
        for name in nominated where !(preservingUpgrade && name == "upgrade") { remove(name) }
        remove("Connection")
        remove("Proxy-Connection")
        remove("Keep-Alive")
        remove("Proxy-Authenticate")
        remove("Proxy-Authorization")
        remove("TE")
        if !preservingUpgrade { remove("Upgrade") }
    }

    static func isValidHeader(name: String, value: String) -> Bool {
        let tokenPunctuation = Set("!#$%&'*+-.^_`|~".unicodeScalars.map(\.value))
        let validName =
            !name.isEmpty
            && name.unicodeScalars.allSatisfy { scalar in
                let code = scalar.value
                return (code >= 48 && code <= 57) || (code >= 65 && code <= 90) || (code >= 97 && code <= 122)
                    || tokenPunctuation.contains(code)
            }
        let validValue = value.unicodeScalars.allSatisfy { scalar in
            scalar.value == 9 || (scalar.value >= 32 && scalar.value != 127)
        }
        return validName && validValue
    }
}

/// Mutable request data supplied to modifiers and interceptors before forwarding.
public struct RequestContext: Sendable {
    public let method: String
    public var target: String
    public var head: HTTPHead
    /// The complete buffered body, or `nil` when the proxy streams it without body modification.
    public var body: Data?
    /// A local response that replaces the upstream exchange when set.
    public var syntheticResponse: SyntheticResponse?
    /// The downstream client IP address, without its port, when available.
    public let remoteAddress: String?

    /// Creates a request context; the default body is empty and fully buffered.
    public init(
        method: String, target: String, head: HTTPHead, body: Data? = Data(),
        syntheticResponse: SyntheticResponse? = nil, remoteAddress: String? = nil
    ) {
        self.method = method
        self.target = target
        self.head = head
        self.body = body
        self.syntheticResponse = syntheticResponse
        self.remoteAddress = remoteAddress
    }
}

/// A complete response returned locally without contacting the upstream server.
public struct SyntheticResponse: Sendable {
    public let statusCode: Int
    public let reason: String
    public let headers: [(String, String)]
    public let body: Data

    /// Creates a local response; the proxy normalizes framing before sending it.
    public init(statusCode: Int, reason: String, headers: [(String, String)] = [], body: Data = Data()) {
        self.statusCode = statusCode
        self.reason = reason
        self.headers = headers
        self.body = body
    }
}

/// Mutable response data supplied to modifiers before delivery to the client.
public struct ResponseContext: Sendable {
    public let requestMethod: String
    public let target: String
    public var head: HTTPHead
    /// The complete buffered body, or `nil` when the proxy streams it without body modification.
    public var body: Data?
    /// The downstream client IP address, without its port, when available.
    public let remoteAddress: String?

    /// Creates a response context retaining the associated request method and target.
    public init(
        requestMethod: String, target: String, head: HTTPHead, body: Data? = Data(),
        remoteAddress: String? = nil
    ) {
        self.requestMethod = requestMethod
        self.target = target
        self.head = head
        self.body = body
        self.remoteAddress = remoteAddress
    }
}

extension HTTPHead {
    init(_ head: HTTPRequestHead) {
        self.init(
            startLine: "\(head.method.rawValue) \(head.uri) HTTP/\(head.version.major).\(head.version.minor)",
            headers: head.headers.map { ($0.name, $0.value) })
    }

    init(_ head: HTTPResponseHead) {
        self.init(
            startLine:
                "HTTP/\(head.version.major).\(head.version.minor) \(head.status.code) \(head.status.reasonPhrase)",
            headers: head.headers.map { ($0.name, $0.value) })
    }

    func requestHead(method: String, uri: String, version: HTTPVersion) throws -> HTTPRequestHead {
        try validateHeaders()
        return HTTPRequestHead(
            version: version, method: HTTPMethod(rawValue: method), uri: uri,
            headers: HTTPHeaders(headers.map { ($0.name, $0.value) }))
    }

    func responseHead(version: HTTPVersion = .http1_1) throws -> HTTPResponseHead {
        try validateHeaders()
        let parts = startLine.split(separator: " ", maxSplits: 2)
        guard parts.count >= 2, let status = Int(parts[1]), (100...599).contains(status), !startLine.contains("\r"),
            !startLine.contains("\n")
        else {
            throw ProxyError.invalidHTTP("invalid response status")
        }
        return HTTPResponseHead(
            version: version,
            status: HTTPResponseStatus.custom(
                code: UInt(status), reasonPhrase: parts.count == 3 ? String(parts[2]) : ""),
            headers: HTTPHeaders(headers.map { ($0.name, $0.value) }))
    }

    private func validateHeaders() throws {
        guard headers.allSatisfy({ Self.isValidHeader(name: $0.name, value: $0.value) }) else {
            throw ProxyError.invalidHTTP("invalid modified header")
        }
    }
}
