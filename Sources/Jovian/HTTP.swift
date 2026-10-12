import Foundation
import NIOHTTP1

public enum ProxyError: Error, CustomStringConvertible {
    case invalidHTTP(String)
    case connection(String)
    case unsupported(String)
    case certificate(String)

    public var description: String {
        switch self {
        case .invalidHTTP(let message): "invalid HTTP: \(message)"
        case .connection(let message): "connection error: \(message)"
        case .unsupported(let message): "unsupported: \(message)"
        case .certificate(let message): "certificate error: \(message)"
        }
    }
}

public struct HTTPHead: Sendable {
    public var startLine: String
    public var headers: [(name: String, value: String)]
    // Distinguishes an explicitly unknown/deleted length from a default zero-length request.
    var modifierContentLength: Int64?

    public init(startLine: String, headers: [(String, String)] = []) {
        self.startLine = startLine
        self.headers = headers
    }

    public subscript(_ name: String) -> String? {
        get { headers.first { $0.name.caseInsensitiveCompare(name) == .orderedSame }?.value }
        set {
            if let newValue, !Self.isValidHeader(name: name, value: newValue) { return }
            headers.removeAll { $0.name.caseInsensitiveCompare(name) == .orderedSame }
            if let newValue { headers.append((name, newValue)) }
            if name.lowercased() == "content-length" {
                modifierContentLength = newValue.flatMap(Int64.init) ?? -1
            }
        }
    }

    public mutating func remove(_ name: String) { self[name] = nil }

    public func values(for name: String) -> [String] {
        headers.compactMap { $0.name.caseInsensitiveCompare(name) == .orderedSame ? $0.value : nil }
    }

    public mutating func replaceValues(for name: String, with values: [String]) {
        guard values.allSatisfy({ Self.isValidHeader(name: name, value: $0) }) else { return }
        headers.removeAll { $0.name.caseInsensitiveCompare(name) == .orderedSame }
        headers.append(contentsOf: values.map { (name, $0) })
    }

    public mutating func add(name: String, value: String) {
        guard Self.isValidHeader(name: name, value: value) else { return }
        headers.append((name, value))
    }

    public func connectionTokens() -> [String] {
        values(for: "Connection").flatMap { value in
            value.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces).lowercased() }
        }.filter { !$0.isEmpty }
    }

    /// Removes headers scoped to a single transport connection.
    ///
    /// Message-framing
    /// headers remain because jovian forwards the corresponding framing itself.
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

    /// Validate framing before consuming bytes or opening an upstream connection.
    func validatedFraming() throws -> (chunked: Bool, length: Int?) {
        let lengths = values(for: "Content-Length")
        let encodings = values(for: "Transfer-Encoding").flatMap {
            $0.lowercased().split(separator: ",", omittingEmptySubsequences: false)
                .map { $0.trimmingCharacters(in: .whitespaces) }
        }
        guard lengths.count <= 1, encodings.isEmpty || encodings == ["chunked"],
            lengths.isEmpty || encodings.isEmpty
        else {
            throw ProxyError.invalidHTTP("ambiguous or unsupported message framing")
        }
        if let text = lengths.first {
            guard !text.isEmpty, text.utf8.allSatisfy({ (48...57).contains($0) }), let length = Int(text) else {
                throw ProxyError.invalidHTTP("invalid Content-Length")
            }
            return (false, length)
        }
        return (!encodings.isEmpty, nil)
    }

    public func encoded() -> Data {
        var result = startLine + "\r\n"
        for header in headers { result += "\(header.name): \(header.value)\r\n" }
        return Data((result + "\r\n").utf8)
    }

    public static func parse(_ data: Data) throws -> HTTPHead {
        guard let text = String(data: data, encoding: .isoLatin1) else {
            throw ProxyError.invalidHTTP("headers are not ISO-8859-1")
        }
        let lines = text.components(separatedBy: "\r\n")
        guard let startLine = lines.first, !startLine.isEmpty else {
            throw ProxyError.invalidHTTP("missing start line")
        }
        var headers: [(String, String)] = []
        for line in lines.dropFirst() where !line.isEmpty {
            guard let colon = line.firstIndex(of: ":") else {
                throw ProxyError.invalidHTTP("malformed header")
            }
            let name = String(line[..<colon]).trimmingCharacters(in: .whitespaces)
            let value = String(line[line.index(after: colon)...]).trimmingCharacters(in: .whitespaces)
            guard isValidHeader(name: name, value: value) else {
                throw ProxyError.invalidHTTP("header contains invalid name or control characters")
            }
            headers.append((name, value))
        }
        return HTTPHead(startLine: startLine, headers: headers)
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

public struct RequestContext: Sendable {
    public var id = UUID()
    public var method: String
    public var target: String
    public var head: HTTPHead
    public var body: Data?
    public var syntheticResponse: SyntheticResponse?
    public var skipRoundTrip = false
    var streamingLog: StreamingMessageCapture?
    var configurationModifiers: [UUID: any Modifier] = [:]
    public let remoteAddress: String?

    public init(
        method: String, target: String, head: HTTPHead, body: Data? = Data(),
        syntheticResponse: SyntheticResponse? = nil, remoteAddress: String? = nil
    ) {
        self.method = method
        self.target = target
        self.head = head
        self.body = body
        if self.head["Host"] == nil { self.head["Host"] = (try? RoutingTarget(target))?.authority }
        self.head.modifierContentLength =
            head.modifierContentLength ?? head["Content-Length"].flatMap(Int64.init)
            ?? (head["Transfer-Encoding"] == nil ? Int64(body?.count ?? 0) : -1)
        self.syntheticResponse = syntheticResponse
        self.remoteAddress = remoteAddress
    }
}

public struct SyntheticResponse: Sendable {
    public let statusCode: Int
    public let reason: String
    public let headers: [(String, String)]
    public let body: Data

    public init(statusCode: Int, reason: String, headers: [(String, String)] = [], body: Data = Data()) {
        self.statusCode = statusCode
        self.reason = reason
        self.headers = headers
        self.body = body
    }
}

public struct ResponseContext: Sendable {
    public let requestMethod: String
    public let target: String
    public var head: HTTPHead
    public var body: Data? {
        didSet { if body != nil { bodyStream = nil } }
    }
    /// A single-use, known-length replacement body.
    ///
    /// Setting `body` clears this stream.
    public var bodyStream: (any ResponseBodyStream)?
    var streamingLog: StreamingMessageCapture?
    public let remoteAddress: String?
    public let requestHead: HTTPHead?
    var configurationModifiers: [UUID: any Modifier] = [:]

    public init(
        requestMethod: String, target: String, head: HTTPHead, body: Data? = Data(),
        remoteAddress: String? = nil, requestHead: HTTPHead? = nil
    ) {
        self.requestMethod = requestMethod
        self.target = target
        self.head = head
        self.body = body
        self.head.modifierContentLength =
            head.modifierContentLength ?? head["Content-Length"].flatMap(Int64.init)
            ?? (head["Transfer-Encoding"] == nil ? body.map { Int64($0.count) } ?? -1 : -1)
        self.remoteAddress = remoteAddress
        self.requestHead = requestHead
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
