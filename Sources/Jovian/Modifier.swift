import Foundation

#if canImport(Darwin)
    import Darwin
#else
    import Glibc
#endif

/// A Swift equivalent of Martian's request/response modifier interfaces.
///
/// The proxy invokes these synchronous operations on workers, potentially for concurrent exchanges.
/// Throwing aborts the current modifier chain; runtime configuration may suppress that error.
public protocol Modifier: Sendable {
    /// Modifies request metadata and any buffered body before forwarding.
    func modify(request: inout RequestContext) throws
    /// Modifies response metadata and any buffered body before delivery.
    func modify(response: inout ResponseContext) throws
}

public extension Modifier {
    /// Leaves requests unchanged when a modifier implements only response behavior.
    func modify(request: inout RequestContext) throws {}
    /// Leaves responses unchanged when a modifier implements only request behavior.
    func modify(response: inout ResponseContext) throws {}
}

/// Applies a fixed sequence of modifiers in insertion order.
public struct ModifierGroup: Modifier {
    public let modifiers: [any Modifier]
    /// Retains the supplied modifiers in their execution order.
    public init(_ modifiers: [any Modifier]) { self.modifiers = modifiers }

    /// Applies request modifiers in order, stopping at the first thrown error.
    public func modify(request: inout RequestContext) throws {
        for modifier in modifiers { try modifier.modify(request: &request) }
    }

    /// Applies response modifiers in order, stopping at the first thrown error.
    public func modify(response: inout ResponseContext) throws {
        for modifier in modifiers { try modifier.modify(response: &response) }
    }
}

/// Replaces all matching headers with one value in the selected directions.
public struct HeaderModifier: Modifier {
    /// Selects the request, response, or both modification directions.
    public enum Scope: Sendable { case request, response, both }
    public let scope: Scope
    public let name: String
    public let value: String

    /// Creates a header replacement; invalid header names or values are ignored when applied.
    public init(scope: Scope, name: String, value: String) {
        self.scope = scope
        self.name = name
        self.value = value
    }

    /// Replaces the request header when the configured scope includes requests.
    public func modify(request: inout RequestContext) {
        if scope == .request || scope == .both { request.head[name] = value }
    }

    /// Replaces the response header when the configured scope includes responses.
    public func modify(response: inout ResponseContext) {
        if scope == .response || scope == .both { response.head[name] = value }
    }
}

/// Runs a nested modifier when the request target matches a host, ignoring case.
public struct HostFilter: Modifier {
    public let host: String
    public let modifier: any Modifier

    /// Creates an exact host filter around the supplied modifier.
    public init(host: String, modifier: any Modifier) {
        self.host = host
        self.modifier = modifier
    }

    /// Matches the target host, falling back to the Host header, before modifying the request.
    public func modify(request: inout RequestContext) throws {
        let requestHost =
            URL(string: request.target)?.host ?? request.head["Host"]?.split(separator: ":").first.map(String.init)
        if requestHost?.caseInsensitiveCompare(host) == .orderedSame {
            try modifier.modify(request: &request)
        }
    }

    /// Matches the original target host before modifying the response.
    public func modify(response: inout ResponseContext) throws {
        if URL(string: response.target)?.host?.caseInsensitiveCompare(host) == .orderedSame {
            try modifier.modify(response: &response)
        }
    }
}

/// Runs a nested modifier for selected HTTP methods, ignoring case.
public struct MethodFilter: Modifier {
    public let methods: Set<String>
    public let modifier: any Modifier

    /// Normalizes method names to uppercase and retains the nested modifier.
    public init(methods: [String], modifier: any Modifier) {
        self.methods = Set(methods.map { $0.uppercased() })
        self.modifier = modifier
    }

    /// Modifies requests whose method belongs to the configured set.
    public func modify(request: inout RequestContext) throws {
        if methods.contains(request.method.uppercased()) { try modifier.modify(request: &request) }
    }

    /// Modifies responses whose associated request method belongs to the configured set.
    public func modify(response: inout ResponseContext) throws {
        if methods.contains(response.requestMethod.uppercased()) { try modifier.modify(response: &response) }
    }
}

/// Runs a nested modifier when all supplied host and path-prefix conditions match.
public struct URLFilter: Modifier {
    public let host: String?
    public let pathPrefix: String?
    public let modifier: any Modifier

    /// Creates a filter; omitted host or path conditions impose no restriction.
    public init(host: String? = nil, pathPrefix: String? = nil, modifier: any Modifier) {
        self.host = host
        self.pathPrefix = pathPrefix
        self.modifier = modifier
    }

    /// Modifies a request if its target URL satisfies the configured conditions.
    public func modify(request: inout RequestContext) throws {
        if matches(request.target) { try modifier.modify(request: &request) }
    }

    /// Modifies a response if the associated target URL satisfies the configured conditions.
    public func modify(response: inout ResponseContext) throws {
        if matches(response.target) { try modifier.modify(response: &response) }
    }

    private func matches(_ target: String) -> Bool {
        guard let components = URLComponents(string: target) else { return false }
        if let host, components.host?.caseInsensitiveCompare(host) != .orderedSame { return false }
        if let pathPrefix, !components.path.hasPrefix(pathPrefix) { return false }
        return true
    }
}

/// Replaces the HTTP response status and reason phrase.
public struct StatusModifier: Modifier {
    public let statusCode: Int
    public let reason: String

    /// Uses the supplied reason or a built-in phrase; wire serialization validates the status.
    public init(statusCode: Int, reason: String? = nil) {
        self.statusCode = statusCode
        self.reason = reason ?? Self.defaultReason(statusCode)
    }

    /// Replaces the status line while preserving its HTTP version.
    public func modify(response: inout ResponseContext) {
        let version = response.head.startLine.split(separator: " ").first.map(String.init) ?? "HTTP/1.1"
        response.head.startLine = "\(version) \(statusCode) \(reason)"
    }

    private static func defaultReason(_ code: Int) -> String {
        switch code {
        case 200: "OK"
        case 201: "Created"
        case 204: "No Content"
        case 301: "Moved Permanently"
        case 302: "Found"
        case 304: "Not Modified"
        case 400: "Bad Request"
        case 401: "Unauthorized"
        case 403: "Forbidden"
        case 404: "Not Found"
        case 429: "Too Many Requests"
        case 500: "Internal Server Error"
        case 502: "Bad Gateway"
        case 503: "Service Unavailable"
        default: "Modified"
        }
    }
}

/// Blocks the calling worker thread for a configured duration.
///
/// Do not invoke this modifier from a NIO event loop.
public struct DelayModifier: Modifier {
    /// Selects the request, response, or both modification directions.
    public enum Scope: Sendable { case request, response, both }
    public let scope: Scope
    public let milliseconds: Int

    /// Creates a delay in milliseconds; callers must supply a nonnegative duration.
    public init(scope: Scope, milliseconds: Int) {
        self.scope = scope
        self.milliseconds = milliseconds
    }

    /// Sleeps on the calling thread when the scope includes requests.
    public func modify(request: inout RequestContext) {
        if scope == .request || scope == .both { pause() }
    }

    /// Sleeps on the calling thread when the scope includes responses.
    public func modify(response: inout ResponseContext) {
        if scope == .response || scope == .both { pause() }
    }

    private func pause() { Thread.sleep(forTimeInterval: Double(milliseconds) / 1_000) }
}

/// Replaces or removes a named query item in the request target.
public struct QueryStringModifier: Modifier {
    public let name: String
    public let value: String?

    /// Uses `nil` to remove matching query items, otherwise replacing them with one value.
    public init(name: String, value: String?) {
        self.name = name
        self.value = value
    }

    /// Rewrites the query when the target can be parsed as URL components.
    public func modify(request: inout RequestContext) {
        guard var components = URLComponents(string: request.target) else { return }
        var items = components.queryItems ?? []
        items.removeAll { $0.name == name }
        if let value { items.append(URLQueryItem(name: name, value: value)) }
        components.queryItems = items.isEmpty ? nil : items
        if let updated = components.string { request.target = updated }
    }
}

/// Replaces or removes a cookie in the selected request and response directions.
public struct CookieModifier: Modifier {
    /// Selects the request, response, or both modification directions.
    public enum Scope: Sendable { case request, response, both }
    public let scope: Scope
    public let name: String
    public let value: String?

    /// Uses `nil` to remove the named cookie; name comparisons ignore case.
    public init(scope: Scope, name: String, value: String?) {
        self.scope = scope
        self.name = name
        self.value = value
    }

    /// Updates Cookie fields while preserving unrelated cookie pairs.
    public func modify(request: inout RequestContext) {
        guard scope == .request || scope == .both else { return }
        var pairs = request.head.values(for: "Cookie")
            .flatMap { $0.split(separator: ";").map { $0.trimmingCharacters(in: .whitespaces) } }
        pairs.removeAll { pair in
            pair.split(separator: "=", maxSplits: 1).first.map(String.init)?
                .caseInsensitiveCompare(name) == .orderedSame
        }
        if let value { pairs.append("\(name)=\(value)") }
        request.head.replaceValues(for: "Cookie", with: pairs.isEmpty ? [] : [pairs.joined(separator: "; ")])
    }

    /// Updates Set-Cookie fields while retaining attributes of matching cookies.
    public func modify(response: inout ResponseContext) {
        guard scope == .response || scope == .both else { return }
        var found = false
        let updated = response.head.values(for: "Set-Cookie").compactMap { line -> String? in
            let pieces = line.split(separator: ";", omittingEmptySubsequences: false)
            guard let first = pieces.first else { return line }
            let cookieName =
                first.split(separator: "=", maxSplits: 1).first
                .map { $0.trimmingCharacters(in: .whitespaces) } ?? ""
            guard cookieName.caseInsensitiveCompare(name) == .orderedSame else { return line }
            found = true
            guard let value else { return nil }
            let attributes = pieces.dropFirst().map(String.init).joined(separator: ";")
            return "\(name)=\(value)" + (attributes.isEmpty ? "" : ";" + attributes)
        }
        var values = updated
        if !found, let value { values.append("\(name)=\(value)") }
        response.head.replaceValues(for: "Set-Cookie", with: values)
    }
}

/// Replaces complete buffered bodies in the selected directions.
///
/// Streamed bodies represented by `nil` remain unchanged.
public struct BodyModifier: Modifier {
    /// Selects the request, response, or both modification directions.
    public enum Scope: Sendable { case request, response, both }
    public let scope: Scope
    public let content: Data
    public let contentType: String?

    /// Retains replacement bytes and an optional Content-Type value.
    public init(scope: Scope, content: Data, contentType: String? = nil) {
        self.scope = scope
        self.content = content
        self.contentType = contentType
    }

    /// Replaces a buffered request body and removes its previous Content-Encoding.
    public func modify(request: inout RequestContext) {
        guard scope == .request || scope == .both, request.body != nil else { return }
        request.body = content
        request.head.remove("Content-Encoding")
        if let contentType { request.head["Content-Type"] = contentType }
    }

    /// Replaces a buffered response body and removes its previous Content-Encoding.
    public func modify(response: inout ResponseContext) {
        guard scope == .response || scope == .both, response.requestMethod != "HEAD",
            response.body != nil
        else { return }
        response.body = content
        response.head.remove("Content-Encoding")
        if let contentType { response.head["Content-Type"] = contentType }
    }
}

/// Replaces the upstream exchange with a synthetic response.
public struct FailureModifier: Modifier {
    public let statusCode: Int
    public let reason: String
    public let body: Data
    public let contentType: String

    /// Creates the local response returned when this modifier runs.
    public init(
        statusCode: Int = 503, reason: String = "Service Unavailable",
        body: Data = Data(), contentType: String = "text/plain; charset=utf-8"
    ) {
        self.statusCode = statusCode
        self.reason = reason
        self.body = body
        self.contentType = contentType
    }

    /// Sets the synthetic response that the proxy will send without contacting the upstream.
    public func modify(request: inout RequestContext) {
        request.syntheticResponse = SyntheticResponse(
            statusCode: statusCode, reason: reason,
            headers: [("Content-Type", contentType)], body: body)
    }
}

/// Runs a nested modifier when the downstream client IP belongs to a configured network.
public struct IPFilter: Modifier {
    private let networks: [IPNetwork]
    public let modifier: any Modifier

    /// Parses IPv4 or IPv6 addresses and CIDR ranges, throwing for invalid notation or prefixes.
    public init(networks: [String], modifier: any Modifier) throws {
        self.networks = try networks.map(IPNetwork.init)
        self.modifier = modifier
    }

    /// Modifies requests from matching client addresses; absent addresses do not match.
    public func modify(request: inout RequestContext) throws {
        if matches(request.remoteAddress) { try modifier.modify(request: &request) }
    }

    /// Modifies responses associated with matching client addresses.
    public func modify(response: inout ResponseContext) throws {
        if matches(response.remoteAddress) { try modifier.modify(response: &response) }
    }

    private func matches(_ address: String?) -> Bool {
        guard let address else { return false }
        return networks.contains { $0.contains(address) }
    }
}

private struct IPNetwork: Sendable {
    let bytes: [UInt8]
    let prefixLength: Int

    init(_ notation: String) throws {
        let pieces = notation.split(separator: "/", maxSplits: 1).map(String.init)
        guard let address = pieces.first, let parsed = Self.parse(address) else {
            throw ProxyError.invalidHTTP("invalid IP network \(notation)")
        }
        let maximum = parsed.count * 8
        let prefix = pieces.count == 2 ? Int(pieces[1]) : maximum
        guard let prefix, (0...maximum).contains(prefix) else {
            throw ProxyError.invalidHTTP("invalid IP prefix \(notation)")
        }
        bytes = parsed
        prefixLength = prefix
    }

    func contains(_ address: String) -> Bool {
        guard let candidate = Self.parse(address), candidate.count == bytes.count else { return false }
        let complete = prefixLength / 8
        if complete > 0 && candidate.prefix(complete) != bytes.prefix(complete) { return false }
        let remainder = prefixLength % 8
        guard remainder > 0 else { return true }
        let mask = UInt8(0xFF << (8 - remainder))
        return candidate[complete] & mask == bytes[complete] & mask
    }

    private static func parse(_ address: String) -> [UInt8]? {
        var ipv4 = in_addr()
        if inet_pton(AF_INET, address, &ipv4) == 1 {
            return withUnsafeBytes(of: &ipv4) { Array($0) }
        }
        var ipv6 = in6_addr()
        if inet_pton(AF_INET6, address, &ipv6) == 1 {
            return withUnsafeBytes(of: &ipv6) { Array($0) }
        }
        return nil
    }
}

/// Sets configured CORS response headers; it does not synthesize preflight responses.
public struct CORSModifier: Modifier {
    public let allowOrigin: String
    public let allowMethods: [String]
    public let allowHeaders: [String]
    public let exposeHeaders: [String]
    public let allowCredentials: Bool
    public let maxAge: Int?

    /// Creates CORS response settings; `maxAge` is a duration in seconds.
    public init(
        allowOrigin: String, allowMethods: [String] = [], allowHeaders: [String] = [],
        exposeHeaders: [String] = [], allowCredentials: Bool = false, maxAge: Int? = nil
    ) {
        self.allowOrigin = allowOrigin
        self.allowMethods = allowMethods
        self.allowHeaders = allowHeaders
        self.exposeHeaders = exposeHeaders
        self.allowCredentials = allowCredentials
        self.maxAge = maxAge
    }

    /// Writes configured CORS headers, setting Vary to Origin for a non-wildcard origin.
    public func modify(response: inout ResponseContext) {
        response.head["Access-Control-Allow-Origin"] = allowOrigin
        if !allowMethods.isEmpty {
            response.head["Access-Control-Allow-Methods"] = allowMethods.joined(separator: ", ")
        }
        if !allowHeaders.isEmpty {
            response.head["Access-Control-Allow-Headers"] = allowHeaders.joined(separator: ", ")
        }
        if !exposeHeaders.isEmpty {
            response.head["Access-Control-Expose-Headers"] = exposeHeaders.joined(separator: ", ")
        }
        if allowCredentials { response.head["Access-Control-Allow-Credentials"] = "true" }
        if let maxAge { response.head["Access-Control-Max-Age"] = String(maxAge) }
        if allowOrigin != "*" { response.head["Vary"] = "Origin" }
    }
}
