import Darwin
import Foundation

/// A Swift equivalent of Martian's request/response modifier interfaces.
public protocol Modifier: Sendable {
    func modify(request: inout RequestContext) throws
    func modify(response: inout ResponseContext) throws
}

public extension Modifier {
    func modify(request: inout RequestContext) throws {}
    func modify(response: inout ResponseContext) throws {}
}

public struct ModifierGroup: Modifier {
    public let modifiers: [any Modifier]
    public let aggregateErrors: Bool

    public init(_ modifiers: [any Modifier], aggregateErrors: Bool = false) {
        self.modifiers = modifiers
        self.aggregateErrors = aggregateErrors
    }

    public func modify(request: inout RequestContext) throws {
        var errors: [any Error] = []
        for modifier in modifiers {
            do { try modifier.modify(request: &request) } catch {
                guard aggregateErrors else { throw error }
                errors.append(error)
            }
        }
        if !errors.isEmpty { throw ModifierErrors(errors) }
    }

    public func modify(response: inout ResponseContext) throws {
        var errors: [any Error] = []
        for modifier in modifiers {
            do { try modifier.modify(response: &response) } catch {
                guard aggregateErrors else { throw error }
                errors.append(error)
            }
        }
        if !errors.isEmpty { throw ModifierErrors(errors) }
    }
}

/// Errors in execution order, including errors from nested modifier groups.
public struct ModifierErrors: Error, CustomStringConvertible {
    public let errors: [any Error]

    public init(_ errors: [any Error]) { self.errors = errors }

    public var description: String {
        errors.map { String(describing: $0) }.joined(separator: "; ")
    }
}

public struct HeaderModifier: Modifier {
    public enum Scope: Sendable { case request, response, both }
    public let scope: Scope
    public let name: String
    public let value: String

    public init(scope: Scope, name: String, value: String) {
        self.scope = scope
        self.name = name
        self.value = value
    }

    public func modify(request: inout RequestContext) throws {
        if scope == .request || scope == .both {
            try MessageHeaders.set(name, value: value, head: &request.head, response: false)
        }
    }

    public func modify(response: inout ResponseContext) throws {
        if scope == .response || scope == .both {
            try MessageHeaders.set(name, value: value, head: &response.head, response: true)
        }
    }
}

public struct HostFilter: Modifier {
    public let host: String
    public let modifier: any Modifier

    public init(host: String, modifier: any Modifier) {
        self.host = host
        self.modifier = modifier
    }

    public func modify(request: inout RequestContext) throws {
        let requestHost =
            URL(string: request.target)?.host ?? request.head["Host"]?.split(separator: ":").first.map(String.init)
        if requestHost?.caseInsensitiveCompare(host) == .orderedSame {
            try modifier.modify(request: &request)
        }
    }

    public func modify(response: inout ResponseContext) throws {
        if URL(string: response.target)?.host?.caseInsensitiveCompare(host) == .orderedSame {
            try modifier.modify(response: &response)
        }
    }
}

public struct MethodFilter: Modifier {
    public let methods: Set<String>
    public let modifier: any Modifier

    public init(methods: [String], modifier: any Modifier) {
        self.methods = Set(methods.map { $0.uppercased() })
        self.modifier = modifier
    }

    public func modify(request: inout RequestContext) throws {
        if methods.contains(request.method.uppercased()) { try modifier.modify(request: &request) }
    }

    public func modify(response: inout ResponseContext) throws {
        if methods.contains(response.requestMethod.uppercased()) { try modifier.modify(response: &response) }
    }
}

public struct URLFilter: Modifier {
    public let host: String?
    public let pathPrefix: String?
    public let modifier: any Modifier

    public init(host: String? = nil, pathPrefix: String? = nil, modifier: any Modifier) {
        self.host = host
        self.pathPrefix = pathPrefix
        self.modifier = modifier
    }

    public func modify(request: inout RequestContext) throws {
        if matches(request.target) { try modifier.modify(request: &request) }
    }

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

public struct StatusModifier: Modifier {
    public let statusCode: Int
    public let reason: String

    public init(statusCode: Int, reason: String? = nil) {
        self.statusCode = statusCode
        self.reason = reason ?? Self.defaultReason(statusCode)
    }

    public func modify(response: inout ResponseContext) {
        let version = response.head.startLine.split(separator: " ").first.map(String.init) ?? "HTTP/1.1"
        response.head.startLine = "\(version) \(statusCode) \(reason)"
    }

    private static func defaultReason(_ code: Int) -> String {
        switch code {
        case 200: "OK"
        case 201: "Created"
        case 204: "No Content"
        case 206: "Partial Content"
        case 301: "Moved Permanently"
        case 302: "Found"
        case 304: "Not Modified"
        case 400: "Bad Request"
        case 401: "Unauthorized"
        case 403: "Forbidden"
        case 404: "Not Found"
        case 405: "Method Not Allowed"
        case 413: "Content Too Large"
        case 416: "Range Not Satisfiable"
        case 429: "Too Many Requests"
        case 500: "Internal Server Error"
        case 502: "Bad Gateway"
        case 503: "Service Unavailable"
        default: "Modified"
        }
    }
}

public struct DelayModifier: Modifier {
    public enum Scope: Sendable { case request, response, both }
    public let scope: Scope
    public let milliseconds: Int

    public init(scope: Scope, milliseconds: Int) {
        self.scope = scope
        self.milliseconds = milliseconds
    }

    public func modify(request: inout RequestContext) {
        if scope == .request || scope == .both { pause() }
    }

    public func modify(response: inout ResponseContext) {
        if scope == .response || scope == .both { pause() }
    }

    private func pause() { Thread.sleep(forTimeInterval: Double(milliseconds) / 1_000) }
}

public struct QueryStringModifier: Modifier {
    public let name: String
    public let value: String?

    public init(name: String, value: String?) {
        self.name = name
        self.value = value
    }

    public func modify(request: inout RequestContext) {
        guard var components = URLComponents(string: request.target) else { return }
        var items = components.queryItems ?? []
        items.removeAll { $0.name == name }
        if let value { items.append(URLQueryItem(name: name, value: value)) }
        components.queryItems = items.isEmpty ? nil : items
        if let updated = components.string { request.target = updated }
    }
}

public struct CookieModifier: Modifier {
    public enum Scope: Sendable { case request, response, both }
    public let scope: Scope
    public let name: String
    public let value: String?

    public init(scope: Scope, name: String, value: String?) {
        self.scope = scope
        self.name = name
        self.value = value
    }

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

public struct BodyModifier: Modifier {
    public enum Scope: Sendable { case request, response, both }
    public let scope: Scope
    public let content: Data
    public let contentType: String?

    public init(scope: Scope, content: Data, contentType: String? = nil) {
        self.scope = scope
        self.content = content
        self.contentType = contentType
    }

    public func modify(request: inout RequestContext) {
        guard scope == .request || scope == .both else { return }
        request.body = content
        request.head.modifierContentLength = Int64(content.count)
        request.head["Content-Length"] = String(content.count)
        request.head.remove("Transfer-Encoding")
        request.head.remove("Content-Encoding")
        if let contentType { request.head["Content-Type"] = contentType }
    }

    public func modify(response: inout ResponseContext) {
        guard scope == .response || scope == .both else { return }
        let plan = ByteRangePlan(
            size: content.count, range: response.requestHead?["Range"],
            contentType: contentType ?? response.head["Content-Type"] ?? "application/octet-stream")
        plan.apply(to: &response, changeFullStatus: false)
        response.body = plan.data(from: content)
    }
}

public struct FailureModifier: Modifier {
    public let statusCode: Int
    public let reason: String
    public let body: Data
    public let contentType: String

    public init(
        statusCode: Int = 503, reason: String = "Service Unavailable",
        body: Data = Data(), contentType: String = "text/plain; charset=utf-8"
    ) {
        self.statusCode = statusCode
        self.reason = reason
        self.body = body
        self.contentType = contentType
    }

    public func modify(request: inout RequestContext) {
        request.syntheticResponse = SyntheticResponse(
            statusCode: statusCode, reason: reason,
            headers: [("Content-Type", contentType)], body: body)
    }
}

public struct IPFilter: Modifier {
    private let networks: [IPNetwork]
    public let modifier: any Modifier

    public init(networks: [String], modifier: any Modifier) throws {
        self.networks = try networks.map(IPNetwork.init)
        self.modifier = modifier
    }

    public func modify(request: inout RequestContext) throws {
        if matches(request.remoteAddress) { try modifier.modify(request: &request) }
    }

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

public struct CORSModifier: Modifier {
    public let allowOrigin: String
    public let allowMethods: [String]
    public let allowHeaders: [String]
    public let exposeHeaders: [String]
    public let allowCredentials: Bool
    public let maxAge: Int?

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
