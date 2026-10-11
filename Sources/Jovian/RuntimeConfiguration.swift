import Foundation

/// A case-insensitive header-name expectation with an optional exact value match.
public struct HeaderExpectation: Codable, Sendable {
    public var name: String
    public var value: String?

    /// Uses `nil` to require only that the named header is present.
    public init(name: String, value: String? = nil) {
        self.name = name
        self.value = value
    }
}

/// Codable runtime rules, verification expectations, and per-direction byte rates.
///
/// `RuntimeConfiguration.replace(with:)` validates and normalizes omitted fields.
public struct RuntimeConfigurationDocument: Codable, Sendable {
    public var requestHeaders: [String: String]?
    public var responseHeaders: [String: String]?
    public var verifyStatus: [String: Int]?
    public var modifier: ModifierSpec?
    public var uploadBytesPerSecond: Int?
    public var downloadBytesPerSecond: Int?
    public var verifyRequestHeaders: [String: [HeaderExpectation]]?
    public var verifyResponseHeaders: [String: [HeaderExpectation]]?

    /// Creates a configuration document; omitted rates mean no runtime rate override.
    public init(
        requestHeaders: [String: String]? = nil,
        responseHeaders: [String: String]? = nil,
        verifyStatus: [String: Int]? = nil,
        modifier: ModifierSpec? = nil,
        uploadBytesPerSecond: Int? = nil,
        downloadBytesPerSecond: Int? = nil,
        verifyRequestHeaders: [String: [HeaderExpectation]]? = nil,
        verifyResponseHeaders: [String: [HeaderExpectation]]? = nil
    ) {
        self.requestHeaders = requestHeaders
        self.responseHeaders = responseHeaders
        self.verifyStatus = verifyStatus
        self.modifier = modifier
        self.uploadBytesPerSecond = uploadBytesPerSecond
        self.downloadBytesPerSecond = downloadBytesPerSecond
        self.verifyRequestHeaders = verifyRequestHeaders
        self.verifyResponseHeaders = verifyResponseHeaders
    }
}

/// JSON representation of the composable Martian-style modifier tree.
public indirect enum ModifierSpec: Codable, Sendable {
    case header(scope: [String], name: String, value: String)
    case group(modifiers: [ModifierSpec])
    case hostFilter(host: String, modifier: ModifierSpec)
    case methodFilter(methods: [String], modifier: ModifierSpec)
    case urlFilter(host: String?, pathPrefix: String?, modifier: ModifierSpec)
    case status(statusCode: Int, reason: String?)
    case delay(scope: [String], milliseconds: Int)
    case queryString(name: String, value: String?)
    case cookie(scope: [String], name: String, value: String?)
    case body(scope: [String], content: String, contentType: String?)
    case failure(statusCode: Int, reason: String?, content: String?, contentType: String?)
    case ipFilter(networks: [String], modifier: ModifierSpec)
    case cors(
        allowOrigin: String, allowMethods: [String], allowHeaders: [String],
        exposeHeaders: [String], allowCredentials: Bool, maxAge: Int?)

    private enum Keys: String, CodingKey {
        case type, scope, name, value, modifiers, host, modifier, methods, pathPrefix
        case statusCode, reason, milliseconds, content, contentType, networks
        case allowOrigin, allowMethods, allowHeaders, exposeHeaders, allowCredentials, maxAge
    }
    private enum Kind: String, Codable {
        case header, group, hostFilter, methodFilter, urlFilter, status, delay, queryString, cookie, body
        case failure, ipFilter, cors
    }

    /// Decodes the Jovian modifier representation, rejecting unknown kinds or malformed fields.
    public init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: Keys.self)
        switch try values.decode(Kind.self, forKey: .type) {
        case .header:
            self = .header(
                scope: try values.decode([String].self, forKey: .scope),
                name: try values.decode(String.self, forKey: .name),
                value: try values.decode(String.self, forKey: .value))
        case .group:
            self = .group(modifiers: try values.decode([ModifierSpec].self, forKey: .modifiers))
        case .hostFilter:
            self = .hostFilter(
                host: try values.decode(String.self, forKey: .host),
                modifier: try values.decode(ModifierSpec.self, forKey: .modifier))
        case .methodFilter:
            self = .methodFilter(
                methods: try values.decode([String].self, forKey: .methods),
                modifier: try values.decode(ModifierSpec.self, forKey: .modifier))
        case .urlFilter:
            self = .urlFilter(
                host: try values.decodeIfPresent(String.self, forKey: .host),
                pathPrefix: try values.decodeIfPresent(String.self, forKey: .pathPrefix),
                modifier: try values.decode(ModifierSpec.self, forKey: .modifier))
        case .status:
            self = .status(
                statusCode: try values.decode(Int.self, forKey: .statusCode),
                reason: try values.decodeIfPresent(String.self, forKey: .reason))
        case .delay:
            self = .delay(
                scope: try values.decode([String].self, forKey: .scope),
                milliseconds: try values.decode(Int.self, forKey: .milliseconds))
        case .queryString:
            self = .queryString(
                name: try values.decode(String.self, forKey: .name),
                value: try values.decodeIfPresent(String.self, forKey: .value))
        case .cookie:
            self = .cookie(
                scope: try values.decode([String].self, forKey: .scope),
                name: try values.decode(String.self, forKey: .name),
                value: try values.decodeIfPresent(String.self, forKey: .value))
        case .body:
            self = .body(
                scope: try values.decode([String].self, forKey: .scope),
                content: try values.decode(String.self, forKey: .content),
                contentType: try values.decodeIfPresent(String.self, forKey: .contentType))
        case .failure:
            self = .failure(
                statusCode: try values.decodeIfPresent(Int.self, forKey: .statusCode) ?? 503,
                reason: try values.decodeIfPresent(String.self, forKey: .reason),
                content: try values.decodeIfPresent(String.self, forKey: .content),
                contentType: try values.decodeIfPresent(String.self, forKey: .contentType))
        case .ipFilter:
            self = .ipFilter(
                networks: try values.decode([String].self, forKey: .networks),
                modifier: try values.decode(ModifierSpec.self, forKey: .modifier))
        case .cors:
            self = .cors(
                allowOrigin: try values.decode(String.self, forKey: .allowOrigin),
                allowMethods: try values.decodeIfPresent([String].self, forKey: .allowMethods) ?? [],
                allowHeaders: try values.decodeIfPresent([String].self, forKey: .allowHeaders) ?? [],
                exposeHeaders: try values.decodeIfPresent([String].self, forKey: .exposeHeaders) ?? [],
                allowCredentials: try values.decodeIfPresent(Bool.self, forKey: .allowCredentials) ?? false,
                maxAge: try values.decodeIfPresent(Int.self, forKey: .maxAge))
        }
    }

    /// Encodes the modifier tree using Jovian's tagged JSON representation.
    public func encode(to encoder: Encoder) throws {
        var values = encoder.container(keyedBy: Keys.self)
        switch self {
        case .header(let scope, let name, let value):
            try values.encode(Kind.header, forKey: .type)
            try values.encode(scope, forKey: .scope)
            try values.encode(name, forKey: .name)
            try values.encode(value, forKey: .value)
        case .group(let modifiers):
            try values.encode(Kind.group, forKey: .type)
            try values.encode(modifiers, forKey: .modifiers)
        case .hostFilter(let host, let modifier):
            try values.encode(Kind.hostFilter, forKey: .type)
            try values.encode(host, forKey: .host)
            try values.encode(modifier, forKey: .modifier)
        case .methodFilter(let methods, let modifier):
            try values.encode(Kind.methodFilter, forKey: .type)
            try values.encode(methods, forKey: .methods)
            try values.encode(modifier, forKey: .modifier)
        case .urlFilter(let host, let pathPrefix, let modifier):
            try values.encode(Kind.urlFilter, forKey: .type)
            try values.encodeIfPresent(host, forKey: .host)
            try values.encodeIfPresent(pathPrefix, forKey: .pathPrefix)
            try values.encode(modifier, forKey: .modifier)
        case .status(let statusCode, let reason):
            try values.encode(Kind.status, forKey: .type)
            try values.encode(statusCode, forKey: .statusCode)
            try values.encodeIfPresent(reason, forKey: .reason)
        case .delay(let scope, let milliseconds):
            try values.encode(Kind.delay, forKey: .type)
            try values.encode(scope, forKey: .scope)
            try values.encode(milliseconds, forKey: .milliseconds)
        case .queryString(let name, let value):
            try values.encode(Kind.queryString, forKey: .type)
            try values.encode(name, forKey: .name)
            try values.encodeIfPresent(value, forKey: .value)
        case .cookie(let scope, let name, let value):
            try values.encode(Kind.cookie, forKey: .type)
            try values.encode(scope, forKey: .scope)
            try values.encode(name, forKey: .name)
            try values.encodeIfPresent(value, forKey: .value)
        case .body(let scope, let content, let contentType):
            try values.encode(Kind.body, forKey: .type)
            try values.encode(scope, forKey: .scope)
            try values.encode(content, forKey: .content)
            try values.encodeIfPresent(contentType, forKey: .contentType)
        case .failure(let statusCode, let reason, let content, let contentType):
            try values.encode(Kind.failure, forKey: .type)
            try values.encode(statusCode, forKey: .statusCode)
            try values.encodeIfPresent(reason, forKey: .reason)
            try values.encodeIfPresent(content, forKey: .content)
            try values.encodeIfPresent(contentType, forKey: .contentType)
        case .ipFilter(let networks, let modifier):
            try values.encode(Kind.ipFilter, forKey: .type)
            try values.encode(networks, forKey: .networks)
            try values.encode(modifier, forKey: .modifier)
        case .cors(
            let allowOrigin, let allowMethods, let allowHeaders, let exposeHeaders,
            let allowCredentials, let maxAge):
            try values.encode(Kind.cors, forKey: .type)
            try values.encode(allowOrigin, forKey: .allowOrigin)
            try values.encode(allowMethods, forKey: .allowMethods)
            try values.encode(allowHeaders, forKey: .allowHeaders)
            try values.encode(exposeHeaders, forKey: .exposeHeaders)
            try values.encode(allowCredentials, forKey: .allowCredentials)
            try values.encodeIfPresent(maxAge, forKey: .maxAge)
        }
    }

    func compile() throws -> any Modifier {
        switch self {
        case .header(let scopeNames, let name, let value):
            let normalized = Set(scopeNames.map { $0.lowercased() })
            guard !normalized.isEmpty, normalized.isSubset(of: ["request", "response"]) else {
                throw ProxyError.invalidHTTP("header modifier scope must contain request and/or response")
            }
            let scope: HeaderModifier.Scope =
                normalized.count == 2 ? .both : (normalized.contains("request") ? .request : .response)
            return HeaderModifier(scope: scope, name: name, value: value)
        case .group(let specs):
            return ModifierGroup(try specs.map { try $0.compile() })
        case .hostFilter(let host, let child):
            guard !host.isEmpty else { throw ProxyError.invalidHTTP("host filter host cannot be empty") }
            return HostFilter(host: host, modifier: try child.compile())
        case .methodFilter(let methods, let child):
            guard !methods.isEmpty, methods.allSatisfy({ !$0.isEmpty }) else {
                throw ProxyError.invalidHTTP("method filter requires at least one method")
            }
            return MethodFilter(methods: methods, modifier: try child.compile())
        case .urlFilter(let host, let pathPrefix, let child):
            guard host != nil || pathPrefix != nil else {
                throw ProxyError.invalidHTTP("URL filter requires host and/or pathPrefix")
            }
            if let pathPrefix, !pathPrefix.hasPrefix("/") {
                throw ProxyError.invalidHTTP("URL filter pathPrefix must start with /")
            }
            return URLFilter(host: host, pathPrefix: pathPrefix, modifier: try child.compile())
        case .status(let statusCode, let reason):
            guard (100...599).contains(statusCode), reason?.contains("\r") != true,
                reason?.contains("\n") != true
            else {
                throw ProxyError.invalidHTTP("status modifier is invalid")
            }
            return StatusModifier(statusCode: statusCode, reason: reason)
        case .delay(let scopeNames, let milliseconds):
            guard (0...60_000).contains(milliseconds) else {
                throw ProxyError.invalidHTTP("delay must be between 0 and 60000 milliseconds")
            }
            let normalized = Set(scopeNames.map { $0.lowercased() })
            guard !normalized.isEmpty, normalized.isSubset(of: ["request", "response"]) else {
                throw ProxyError.invalidHTTP("delay scope must contain request and/or response")
            }
            let scope: DelayModifier.Scope =
                normalized.count == 2 ? .both : (normalized.contains("request") ? .request : .response)
            return DelayModifier(scope: scope, milliseconds: milliseconds)
        case .queryString(let name, let value):
            guard !name.isEmpty, !name.contains("&"), !name.contains("=") else {
                throw ProxyError.invalidHTTP("query-string modifier name is invalid")
            }
            return QueryStringModifier(name: name, value: value)
        case .cookie(let scopeNames, let name, let value):
            guard !name.isEmpty, !name.contains(";"), !name.contains("="),
                value?.contains(";") != true, value?.contains("\r") != true,
                value?.contains("\n") != true
            else {
                throw ProxyError.invalidHTTP("cookie modifier name or value is invalid")
            }
            let normalized = Set(scopeNames.map { $0.lowercased() })
            guard !normalized.isEmpty, normalized.isSubset(of: ["request", "response"]) else {
                throw ProxyError.invalidHTTP("cookie scope must contain request and/or response")
            }
            let scope: CookieModifier.Scope =
                normalized.count == 2 ? .both : (normalized.contains("request") ? .request : .response)
            return CookieModifier(scope: scope, name: name, value: value)
        case .body(let scopeNames, let content, let contentType):
            guard content.utf8.count <= 1_048_576,
                contentType?.contains("\r") != true, contentType?.contains("\n") != true
            else {
                throw ProxyError.invalidHTTP("body modifier content or content type is invalid")
            }
            let normalized = Set(scopeNames.map { $0.lowercased() })
            guard !normalized.isEmpty, normalized.isSubset(of: ["request", "response"]) else {
                throw ProxyError.invalidHTTP("body scope must contain request and/or response")
            }
            let scope: BodyModifier.Scope =
                normalized.count == 2 ? .both : (normalized.contains("request") ? .request : .response)
            return BodyModifier(scope: scope, content: Data(content.utf8), contentType: contentType)
        case .failure(let statusCode, let reason, let content, let contentType):
            guard (400...599).contains(statusCode),
                reason?.contains("\r") != true, reason?.contains("\n") != true,
                contentType?.contains("\r") != true, contentType?.contains("\n") != true,
                (content?.utf8.count ?? 0) <= 1_048_576
            else {
                throw ProxyError.invalidHTTP("failure modifier is invalid")
            }
            return FailureModifier(
                statusCode: statusCode,
                reason: reason ?? StatusModifier(statusCode: statusCode).reason,
                body: Data((content ?? "").utf8),
                contentType: contentType ?? "text/plain; charset=utf-8")
        case .ipFilter(let networks, let child):
            guard !networks.isEmpty else { throw ProxyError.invalidHTTP("IP filter requires networks") }
            return try IPFilter(networks: networks, modifier: child.compile())
        case .cors(
            let allowOrigin, let allowMethods, let allowHeaders, let exposeHeaders,
            let allowCredentials, let maxAge):
            let allValues = [allowOrigin] + allowMethods + allowHeaders + exposeHeaders
            guard !allowOrigin.isEmpty, allValues.allSatisfy({ !$0.contains("\r") && !$0.contains("\n") }),
                maxAge == nil || maxAge! >= 0,
                !(allowCredentials && allowOrigin == "*")
            else {
                throw ProxyError.invalidHTTP("CORS modifier is invalid")
            }
            return CORSModifier(
                allowOrigin: allowOrigin, allowMethods: allowMethods,
                allowHeaders: allowHeaders, exposeHeaders: exposeHeaders,
                allowCredentials: allowCredentials, maxAge: maxAge)
        }
    }
}

/// A timestamped mismatch recorded by the runtime traffic verifier.
public struct VerificationFailure: Codable, Sendable {
    public let timestamp: Date
    public let message: String
}

/// Mutable control-plane state.
///
/// It is both a Modifier and a TrafficLogger so runtime rules remain isolated from the proxy transport.
/// The lock protects configuration, compiled rules, and verification failures. Modification takes a
/// rule snapshot under the lock and invokes its Sendable modifiers after releasing the lock.
public final class RuntimeConfiguration: Modifier, TrafficLogger, @unchecked Sendable {
    private let lock = NSLock()
    private var document = RuntimeConfigurationDocument(
        requestHeaders: [:], responseHeaders: [:], verifyStatus: [:], modifier: nil,
        uploadBytesPerSecond: nil, downloadBytesPerSecond: nil,
        verifyRequestHeaders: [:], verifyResponseHeaders: [:])
    private var compiled: any Modifier = ModifierGroup([])
    private var failures: [VerificationFailure] = []
    private var martianConfiguration: Data?

    /// Starts with no modifications, verification expectations, or rate overrides.
    public init() {}

    /// Validates and atomically replaces rules, clearing previous verification failures.
    ///
    /// Throws for invalid rules or rates; the previous configuration remains active on failure.
    public func replace(with next: RuntimeConfigurationDocument) throws {
        let statusRules = next.verifyStatus ?? [:]
        guard statusRules.values.allSatisfy({ (100...599).contains($0) }) else {
            throw ProxyError.invalidHTTP("verification status must be between 100 and 599")
        }
        guard Self.validRate(next.uploadBytesPerSecond), Self.validRate(next.downloadBytesPerSecond) else {
            throw ProxyError.invalidHTTP("traffic rates must be between 1 and 1000000000 bytes per second")
        }
        let headerRules =
            Array((next.verifyRequestHeaders ?? [:]).values.joined())
            + Array((next.verifyResponseHeaders ?? [:]).values.joined())
        guard headerRules.allSatisfy({ HTTPHead.isValidHeader(name: $0.name, value: $0.value ?? "") }) else {
            throw ProxyError.invalidHTTP("header verification contains an invalid name or value")
        }
        var modifiers: [any Modifier] = []
        for (name, value) in next.requestHeaders ?? [:] {
            modifiers.append(HeaderModifier(scope: .request, name: name, value: value))
        }
        for (name, value) in next.responseHeaders ?? [:] {
            modifiers.append(HeaderModifier(scope: .response, name: name, value: value))
        }
        if let spec = next.modifier { modifiers.append(try spec.compile()) }
        let nextCompiled = ModifierGroup(modifiers)
        lock.withLock {
            document = RuntimeConfigurationDocument(
                requestHeaders: next.requestHeaders ?? [:],
                responseHeaders: next.responseHeaders ?? [:],
                verifyStatus: statusRules,
                modifier: next.modifier,
                uploadBytesPerSecond: next.uploadBytesPerSecond,
                downloadBytesPerSecond: next.downloadBytesPerSecond,
                verifyRequestHeaders: next.verifyRequestHeaders ?? [:],
                verifyResponseHeaders: next.verifyResponseHeaders ?? [:])
            compiled = nextCompiled
            martianConfiguration = nil
            failures.removeAll(keepingCapacity: true)
        }
    }

    /// Installs a supported canonical Martian modifier tree and clears verification failures.
    ///
    /// Existing Jovian verification rules and traffic rates remain active. Unsupported or malformed
    /// input throws before the active modifier changes.
    public func replace(martianJSON: Data) throws {
        let nextCompiled = try MartianConfigurationParser.parse(martianJSON)
        let normalized = try JSONSerialization.data(
            withJSONObject: JSONSerialization.jsonObject(with: martianJSON), options: [.prettyPrinted, .sortedKeys])
        lock.withLock {
            compiled = nextCompiled
            martianConfiguration = normalized
            failures.removeAll(keepingCapacity: true)
        }
    }

    /// Encodes the installed Martian document, or the current Jovian document when none is installed.
    public func encodedConfiguration() throws -> Data {
        if let martian = lock.withLock({ martianConfiguration }) { return martian }
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        return try encoder.encode(snapshot())
    }

    /// Returns the Jovian document, which does not represent a separately installed Martian tree.
    public func snapshot() -> RuntimeConfigurationDocument { lock.withLock { document } }

    /// Applies a snapshot of request modifiers, suppressing thrown modifier errors.
    public func modify(request: inout RequestContext) {
        let modifier = lock.withLock { compiled }
        try? modifier.modify(request: &request)
    }

    /// Applies a snapshot of response modifiers, suppressing thrown modifier errors.
    public func modify(response: inout ResponseContext) {
        let modifier = lock.withLock { compiled }
        try? modifier.modify(response: &response)
    }

    /// Verifies successful exchanges against host rules and appends any observed mismatches.
    public func record(_ entry: TrafficEntry) {
        guard entry.error == nil, entry.status > 0, let host = Self.host(from: entry.target) else { return }
        lock.withLock {
            guard
                let expected = document.verifyStatus?.first(where: {
                    $0.key.caseInsensitiveCompare(host) == .orderedSame
                })?.value
            else {
                verifyHeaders(
                    entry.requestHeaders, rules: document.verifyRequestHeaders,
                    host: host, direction: "request", target: entry.target, timestamp: entry.timestamp)
                verifyHeaders(
                    entry.responseHeaders, rules: document.verifyResponseHeaders,
                    host: host, direction: "response", target: entry.target, timestamp: entry.timestamp)
                return
            }
            if expected != entry.status {
                failures.append(
                    VerificationFailure(
                        timestamp: entry.timestamp,
                        message:
                            "response(\(entry.target)) status verify failure: got \(entry.status), want \(expected)"))
            }
            verifyHeaders(
                entry.requestHeaders, rules: document.verifyRequestHeaders,
                host: host, direction: "request", target: entry.target, timestamp: entry.timestamp)
            verifyHeaders(
                entry.responseHeaders, rules: document.verifyResponseHeaders,
                host: host, direction: "response", target: entry.target, timestamp: entry.timestamp)
        }
    }

    /// Returns a snapshot of all mismatches retained since the last replacement or reset.
    public func verificationFailures() -> [VerificationFailure] { lock.withLock { failures } }
    /// Clears mismatches while preserving active configuration.
    public func resetVerificationFailures() { lock.withLock { failures.removeAll(keepingCapacity: true) } }
    /// Returns upload and download overrides in bytes per second; `nil` leaves the server default active.
    public func trafficRates() -> (upload: Int?, download: Int?) {
        lock.withLock { (document.uploadBytesPerSecond, document.downloadBytesPerSecond) }
    }

    private static func validRate(_ value: Int?) -> Bool {
        value == nil || (1...1_000_000_000).contains(value!)
    }

    private func verifyHeaders(
        _ headers: [LoggedHeader], rules: [String: [HeaderExpectation]]?,
        host: String, direction: String, target: String, timestamp: Date
    ) {
        guard
            let expectations = rules?.first(where: {
                $0.key.caseInsensitiveCompare(host) == .orderedSame
            })?.value
        else { return }
        for expectation in expectations {
            let actual = headers.first { $0.name.caseInsensitiveCompare(expectation.name) == .orderedSame }?.value
            if actual == nil {
                failures.append(
                    VerificationFailure(
                        timestamp: timestamp,
                        message: "\(direction)(\(target)) header verify failure: missing \(expectation.name)"))
            } else if let expected = expectation.value, actual != expected {
                failures.append(
                    VerificationFailure(
                        timestamp: timestamp,
                        message:
                            "\(direction)(\(target)) header verify failure: \(expectation.name) got \(actual!), want \(expected)"
                    ))
            }
        }
    }

    private static func host(from target: String) -> String? {
        if let host = URL(string: target)?.host { return host }
        if target.hasPrefix("[") { return target.dropFirst().split(separator: "]").first.map(String.init) }
        return target.split(separator: ":").first.map(String.init)
    }
}
