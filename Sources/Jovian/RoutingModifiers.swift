import Foundation

/// Validated HTTP destination shared by rewriting and transport selection.
struct RoutingTarget {
    let components: URLComponents
    let host: String
    let port: UInt16
    let secure: Bool

    init(_ target: String) throws {
        guard !target.unicodeScalars.contains(where: { $0.value <= 32 || $0.value == 127 }),
            let components = URLComponents(string: target),
            let scheme = components.scheme?.lowercased(), ["http", "https"].contains(scheme),
            let rawHost = components.host, !rawHost.isEmpty,
            !rawHost.unicodeScalars.contains(where: { $0.value <= 32 || $0.value == 127 }),
            components.user == nil, components.password == nil, components.fragment == nil,
            let port = UInt16(exactly: components.port ?? (scheme == "https" ? 443 : 80)), port > 0
        else {
            throw ProxyError.invalidHTTP("invalid routing destination")
        }
        self.components = components
        host = rawHost.trimmingCharacters(in: CharacterSet(charactersIn: "[]"))
        self.port = port
        secure = scheme == "https"
    }

    var authority: String {
        let name = host.contains(":") ? "[\(host)]" : host
        return components.port == nil ? name : "\(name):\(port)"
    }

    var connectAuthority: String {
        let name = host.contains(":") ? "[\(host)]" : host
        return "\(name):\(port)"
    }

    var absoluteForm: String {
        var normalized = components
        if normalized.path.isEmpty { normalized.path = "/" }
        return normalized.string!
    }
}

/// Replaces selected nonempty URL fields.
///
/// Host includes an optional port.
public struct URLRewriteModifier: Modifier {
    private let scheme: String?
    private let authority: URLComponents?
    private let path: String?
    private let query: String?

    public init(scheme: String? = nil, host: String? = nil, path: String? = nil, query: String? = nil) throws {
        guard scheme == nil || scheme == "" || ["http", "https"].contains(scheme!),
            path == nil || path == "" || path!.hasPrefix("/"),
            [host, path, query].compactMap({ $0 }).allSatisfy({ value in
                !value.unicodeScalars.contains { $0.value < 32 || $0.value == 127 }
            })
        else {
            throw ProxyError.invalidHTTP("invalid URL rewrite fields")
        }
        self.scheme = scheme.flatMap { $0.isEmpty ? nil : $0 }
        if let host, !host.isEmpty {
            let target = try RoutingTarget("http://\(host)/")
            guard target.components.path == "/", target.components.query == nil else {
                throw ProxyError.invalidHTTP("URL rewrite host must be an authority")
            }
            authority = target.components
        } else {
            authority = nil
        }
        self.path = path.flatMap { $0.isEmpty ? nil : $0 }
        if let query, !query.isEmpty {
            guard let encoded = URLComponents(string: "http://rewrite.invalid/?" + query),
                encoded.fragment == nil
            else { throw ProxyError.invalidHTTP("invalid URL rewrite query") }
            self.query = encoded.percentEncodedQuery
        } else {
            self.query = nil
        }
    }

    public func modify(request: inout RequestContext) throws {
        var components = try RoutingTarget(request.target).components
        if let scheme { components.scheme = scheme }
        if let authority {
            components.host = authority.host
            components.port = authority.port
        }
        if let path { components.path = path }
        if let query { components.percentEncodedQuery = query }
        guard let updated = components.string else { throw ProxyError.invalidHTTP("invalid rewritten URL") }
        let destination = try RoutingTarget(updated)
        request.target = updated
        request.head["Host"] = destination.authority
    }
}

/// Sets, removes, or explicitly selects the scheme's default destination port.
public struct PortRewriteModifier: Modifier {
    private let port: Int?
    private let defaultForScheme: Bool
    private let remove: Bool

    public init(port: Int? = nil, defaultForScheme: Bool = false, remove: Bool = false) throws {
        guard (port == nil ? 0 : 1) + (defaultForScheme ? 1 : 0) + (remove ? 1 : 0) == 1,
            port == nil || (1...65_535).contains(port!)
        else {
            throw ProxyError.invalidHTTP("specify one valid port, defaultForScheme, or remove")
        }
        self.port = port
        self.defaultForScheme = defaultForScheme
        self.remove = remove
    }

    public func modify(request: inout RequestContext) throws {
        let destination = try RoutingTarget(request.target)
        var components = destination.components
        if remove {
            components.port = nil
        } else {
            components.port = defaultForScheme ? (destination.secure ? 443 : 80) : port
        }
        guard let updated = components.string else { throw ProxyError.invalidHTTP("invalid rewritten port") }
        request.target = updated
        request.head["Host"] = try RoutingTarget(updated).authority
    }
}

/// A condition for a scoped `match` rule.
///
/// URL fields are combined with AND.
public struct MatchCondition: Codable, Sendable {
    public enum Kind: String, Codable, Sendable {
        case url, urlRegex, header, headerRegex, queryString, cookie, method, port
    }

    public var kind: Kind
    public var name: String?
    public var value: String?
    public var regex: String?
    public var scheme: String?
    public var host: String?
    public var path: String?
    public var pathPrefix: String?
    public var query: String?
    public var methods: [String]?
    public var port: Int?

    public init(
        kind: Kind, name: String? = nil, value: String? = nil, regex: String? = nil,
        scheme: String? = nil, host: String? = nil, path: String? = nil,
        pathPrefix: String? = nil, query: String? = nil, methods: [String]? = nil, port: Int? = nil
    ) {
        self.kind = kind
        self.name = name
        self.value = value
        self.regex = regex
        self.scheme = scheme
        self.host = host
        self.path = path
        self.pathPrefix = pathPrefix
        self.query = query
        self.methods = methods
        self.port = port
    }
}

/// Applies the true or else branch independently for each selected message scope.
public struct MatchModifier: Modifier {
    private let condition: MatchCondition
    private let regex: NSRegularExpression?
    private let modifier: any Modifier
    private let elseModifier: (any Modifier)?
    private let scopes: Set<String>
    private let responseUsesRequestHeaders: Bool

    public init(
        condition: MatchCondition, scope: [String] = ["request", "response"],
        modifier: any Modifier, elseModifier: (any Modifier)? = nil,
        responseUsesRequestHeaders: Bool = false
    ) throws {
        let scopes = Set(scope)
        guard !scopes.isEmpty, scopes.isSubset(of: ["request", "response"]) else {
            throw ProxyError.invalidHTTP("match scope must contain request and/or response")
        }
        switch condition.kind {
        case .header, .headerRegex:
            guard let name = condition.name, HTTPHead.isValidHeader(name: name, value: condition.value ?? "") else {
                throw ProxyError.invalidHTTP("header filter requires a valid name and value")
            }
        case .cookie, .queryString:
            guard let name = condition.name, !name.isEmpty,
                !name.contains(where: { $0.isWhitespace || $0 == ";" || $0 == "=" })
            else {
                throw ProxyError.invalidHTTP("cookie/query filter requires a valid name")
            }
        case .method:
            guard let methods = condition.methods, !methods.isEmpty,
                methods.allSatisfy({ HTTPHead.isValidHeader(name: $0, value: "") })
            else {
                throw ProxyError.invalidHTTP("method filter requires HTTP method tokens")
            }
        case .port:
            guard let port = condition.port, (1...65_535).contains(port) else {
                throw ProxyError.invalidHTTP("port filter requires port from 1 through 65535")
            }
        case .url:
            guard condition.scheme == nil || condition.scheme == "" || ["http", "https"].contains(condition.scheme!),
                condition.path == nil || condition.path == "" || condition.path!.hasPrefix("/"),
                condition.pathPrefix == nil || condition.pathPrefix!.hasPrefix("/")
            else {
                throw ProxyError.invalidHTTP("invalid URL filter fields")
            }
        case .urlRegex:
            break
        }
        if condition.kind == .urlRegex || condition.kind == .headerRegex {
            guard let pattern = condition.regex, pattern.utf8.count <= 4096 else {
                throw ProxyError.invalidHTTP("regex filter requires a pattern no larger than 4096 bytes")
            }
            regex = try NSRegularExpression(pattern: pattern)
        } else {
            regex = nil
        }
        self.condition = condition
        self.modifier = modifier
        self.elseModifier = elseModifier
        self.scopes = scopes
        self.responseUsesRequestHeaders = responseUsesRequestHeaders
    }

    public func modify(request: inout RequestContext) throws {
        guard scopes.contains("request") else { return }
        let selected =
            try matches(target: request.target, method: request.method, head: request.head, response: false)
            ? modifier : elseModifier
        try selected?.modify(request: &request)
    }

    public func modify(response: inout ResponseContext) throws {
        guard scopes.contains("response") else { return }
        let head = responseUsesRequestHeaders ? response.requestHead ?? HTTPHead(startLine: "") : response.head
        let selected =
            try matches(
                target: response.target, method: response.requestMethod,
                head: head, response: !responseUsesRequestHeaders) ? modifier : elseModifier
        try selected?.modify(response: &response)
    }

    private func matches(target: String, method: String, head: HTTPHead, response: Bool) throws -> Bool {
        switch condition.kind {
        case .header:
            return MessageHeaders.values(condition.name!, head: head, response: response).contains {
                condition.value == nil || $0 == condition.value
            }
        case .headerRegex:
            return try MessageHeaders.values(condition.name!, head: head, response: response).contains {
                try regexMatches($0)
            }
        case .cookie:
            let lines = head.values(for: response ? "Set-Cookie" : "Cookie")
            let pairs = lines.flatMap { line -> [Substring] in
                let pieces = line.split(separator: ";")
                return response ? Array(pieces.prefix(1)) : pieces
            }
            return pairs.contains { pair in
                let parts = pair.trimmingCharacters(in: .whitespaces).split(
                    separator: "=", maxSplits: 1,
                    omittingEmptySubsequences: false)
                guard parts.count == 2, parts[0] == condition.name! else { return false }
                var value = String(parts[1])
                if value.hasPrefix("\""), value.hasSuffix("\""), value.count >= 2 {
                    value = String(value.dropFirst().dropLast())
                }
                return condition.value == nil || condition.value == "" || value == condition.value
            }
        case .queryString:
            return URLComponents(string: target)?.queryItems?.contains {
                $0.name == condition.name
                    && (condition.value == nil || condition.value == "" || $0.value == condition.value)
            } == true
        case .method:
            return condition.methods!.contains { $0.caseInsensitiveCompare(method) == .orderedSame }
        case .port:
            return Int(try RoutingTarget(target).port) == condition.port
        case .urlRegex:
            return try regexMatches(target)
        case .url:
            let destination = try RoutingTarget(target)
            let url = destination.components
            if let scheme = condition.scheme, !scheme.isEmpty, scheme != url.scheme { return false }
            if let host = condition.host, !host.isEmpty, !matchesHost(destination.authority, pattern: host) {
                return false
            }
            if let path = condition.path, !path.isEmpty, path != url.path { return false }
            if let prefix = condition.pathPrefix, !url.path.hasPrefix(prefix) { return false }
            if let query = condition.query, !query.isEmpty, query != url.percentEncodedQuery { return false }
            return true
        }
    }

    private func matchesHost(_ host: String, pattern: String) -> Bool {
        let actual = host.lowercased().split(separator: ".", omittingEmptySubsequences: false)
        let expected = pattern.lowercased().split(separator: ".", omittingEmptySubsequences: false)
        return actual.count == expected.count && zip(actual, expected).allSatisfy { $1 == "*" || $0 == $1 }
    }

    private func regexMatches(_ text: String) throws -> Bool {
        guard let regex else { return false }
        let deadline = ContinuousClock.now.advanced(by: .milliseconds(50))
        var matched = false
        var timedOut = false
        regex.enumerateMatches(in: text, options: [.reportProgress], range: NSRange(text.startIndex..., in: text)) {
            match, _, stop in
            if ContinuousClock.now >= deadline {
                timedOut = true
                stop.pointee = true
            } else if match != nil {
                matched = true
                stop.pointee = true
            }
        }
        if timedOut { throw ProxyError.invalidHTTP("regex filter exceeded its time budget") }
        return matched
    }
}
