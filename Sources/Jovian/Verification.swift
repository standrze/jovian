import Foundation

/// An observation at a particular point in the modifier tree.
///
///
/// Failures do not stop forwarding.
public struct VerificationSpec: Codable, Sendable {
    public enum Kind: String, Codable, Sendable {
        case header, method, status, url, queryString, failure, pingback
    }

    public var kind: Kind
    public var name: String?
    public var value: String?
    public var method: String?
    public var statusCode: Int?
    public var scheme: String?
    public var host: String?
    public var path: String?
    public var query: String?
    public var message: String?

    public init(
        kind: Kind, name: String? = nil, value: String? = nil, method: String? = nil,
        statusCode: Int? = nil, scheme: String? = nil, host: String? = nil,
        path: String? = nil, query: String? = nil, message: String? = nil
    ) {
        self.kind = kind
        self.name = name
        self.value = value
        self.method = method
        self.statusCode = statusCode
        self.scheme = scheme
        self.host = host
        self.path = path
        self.query = query
        self.message = message
    }
}

/// Each compiled configuration owns a store.
///
/// Detached, in-flight trees cannot write into its replacement.
final class VerificationStore: @unchecked Sendable {
    private struct Pingback {
        let id: UUID
        var timestamp = Date()
        var seen = false
    }

    private let lock = NSLock()
    private var failures: [VerificationFailure] = []
    private var pingbacks: [Pingback] = []
    private var omitted = false
    static let maximumFailures = 10_000

    func registerPingback() -> UUID {
        lock.withLock {
            let id = UUID()
            pingbacks.append(Pingback(id: id))
            return id
        }
    }

    func observe(_ id: UUID) {
        lock.withLock {
            if let index = pingbacks.firstIndex(where: { $0.id == id }) { pingbacks[index].seen = true }
        }
    }

    func record(_ message: String) {
        lock.withLock {
            if failures.count < Self.maximumFailures {
                failures.append(VerificationFailure(timestamp: Date(), message: String(message.prefix(2048))))
            } else {
                omitted = true
            }
        }
    }

    func snapshot() -> [VerificationFailure] {
        lock.withLock {
            var result =
                pingbacks.filter { !$0.seen }.map {
                    VerificationFailure(timestamp: $0.timestamp, message: "request pingback never occurred [\($0.id)]")
                } + failures
            if omitted {
                result.append(
                    VerificationFailure(timestamp: Date(), message: "additional verification failures omitted"))
            }
            return result
        }
    }

    func reset() {
        lock.withLock {
            failures.removeAll(keepingCapacity: true)
            omitted = false
            for index in pingbacks.indices {
                pingbacks[index].seen = false
                pingbacks[index].timestamp = Date()
            }
        }
    }
}

struct VerifierModifier: Modifier {
    let spec: VerificationSpec
    private let scopes: Set<String>
    private let store: VerificationStore
    private let pingbackID: UUID?

    init(spec: VerificationSpec, scope: [String]? = nil, store: VerificationStore) throws {
        let supported: Set<String> =
            spec.kind == .header ? ["request", "response"] : (spec.kind == .status ? ["response"] : ["request"])
        let scopes = scope.map { Set($0.map { $0.lowercased() }) } ?? supported
        guard !scopes.isEmpty, scopes.isSubset(of: supported) else {
            throw ProxyError.invalidHTTP("unsupported verifier scope")
        }
        switch spec.kind {
        case .header:
            guard let name = spec.name, HTTPHead.isValidHeader(name: name, value: spec.value ?? "") else {
                throw ProxyError.invalidHTTP("header verifier requires a valid name and value")
            }
        case .method:
            guard let method = spec.method, HTTPHead.isValidHeader(name: method, value: "") else {
                throw ProxyError.invalidHTTP("method verifier requires a method token")
            }
        case .status:
            guard let code = spec.statusCode, (100...599).contains(code) else {
                throw ProxyError.invalidHTTP("status verifier requires statusCode from 100 through 599")
            }
        case .queryString:
            guard let name = spec.name, !name.isEmpty else {
                throw ProxyError.invalidHTTP("query verifier requires a name")
            }
        case .url, .pingback, .failure:
            break
        }
        self.spec = spec
        self.scopes = scopes
        self.store = store
        pingbackID = spec.kind == .pingback ? store.registerPingback() : nil
    }

    func modify(request: inout RequestContext) {
        guard scopes.contains("request") else { return }
        switch spec.kind {
        case .header:
            verifyHeader(request.head, direction: "request")
        case .method:
            if request.method != spec.method { store.record("request method verification failed") }
        case .url:
            if !matchesURL(request.target, wildcard: true) { store.record("request URL verification failed") }
        case .pingback:
            if let pingbackID, matchesURL(request.target, wildcard: false) { store.observe(pingbackID) }
        case .queryString:
            verifyQuery(request)
        case .failure:
            store.record("request verification failed: \(spec.message ?? "")")
        case .status:
            break
        }
    }

    func modify(response: inout ResponseContext) {
        guard scopes.contains("response") else { return }
        if spec.kind == .header { verifyHeader(response.head, direction: "response") }
        if spec.kind == .status,
            Int(response.head.startLine.split(separator: " ").dropFirst().first ?? "") != spec.statusCode
        {
            store.record("response status verification failed")
        }
    }

    private func verifyHeader(_ head: HTTPHead, direction: String) {
        let values = MessageHeaders.values(spec.name!, head: head, response: direction == "response")
        if values.isEmpty || (spec.value?.isEmpty == false && !values.contains(spec.value!)) {
            // Do not echo actual values, expectations, URLs, or credentials into the admin response.
            store.record("\(direction) header verification failed for \(spec.name!)")
        }
    }

    private func matchesURL(_ target: String, wildcard: Bool) -> Bool {
        guard let destination = try? RoutingTarget(target) else { return false }
        let url = destination.components
        if let scheme = spec.scheme, !scheme.isEmpty, scheme != url.scheme { return false }
        if let path = spec.path, !path.isEmpty, path != url.path { return false }
        if let query = spec.query, !query.isEmpty, query != url.percentEncodedQuery { return false }
        if let host = spec.host, !host.isEmpty {
            if !wildcard { return host == destination.authority }
            let actual = destination.authority.lowercased().split(separator: ".", omittingEmptySubsequences: false)
            let expected = host.lowercased().split(separator: ".", omittingEmptySubsequences: false)
            return actual.count == expected.count && zip(actual, expected).allSatisfy { $1 == "*" || $0 == $1 }
        }
        return true
    }

    private func verifyQuery(_ request: RequestContext) {
        var values: [(String, String)] = []
        do {
            values = try formValues(URLComponents(string: request.target)?.percentEncodedQuery ?? "")
            if ["POST", "PUT", "PATCH"].contains(request.method),
                request.head["Content-Type"]?.split(separator: ";").first?
                    .trimmingCharacters(in: .whitespaces).lowercased() == "application/x-www-form-urlencoded"
            {
                guard let body = request.body, let text = String(data: body, encoding: .utf8) else {
                    store.record("request query verification failed: form body unavailable")
                    return
                }
                values += try formValues(text)
            }
        } catch {
            store.record("request query verification failed: malformed form encoding")
            return
        }
        if !values.contains(where: { $0.0 == spec.name && (spec.value?.isEmpty != false || $0.1 == spec.value) }) {
            store.record("request query verification failed")
        }
    }

    private func formValues(_ text: String) throws -> [(String, String)] {
        try text.split(separator: "&").map { pair in
            let parts = pair.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false)
            func decode(_ value: String) throws -> String {
                guard let decoded = value.replacingOccurrences(of: "+", with: " ").removingPercentEncoding else {
                    throw ProxyError.invalidHTTP("malformed form encoding")
                }
                return decoded
            }
            return (try decode(String(parts[0])), try decode(parts.count > 1 ? String(parts[1]) : ""))
        }
    }
}
