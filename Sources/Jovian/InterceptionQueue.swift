import Foundation

public struct HeldRequest: Codable, Sendable {
    public let id: UUID
    public let revision: Int
    public let method: String
    public let url: String
    public let headers: [LoggedHeader]
    public let bodyBase64: String?
    public let expiresAt: Date
}

/// A bounded, manual request gate.
///
/// Turning interception off releases pending
/// requests with their current edits; cancellation, timeout, and shutdown drop them.
public final class RequestInterceptionQueue: RequestInterceptor, @unchecked Sendable {
    private struct Hold {
        var request: RequestContext
        var revision = 0
        let expiresAt: Date
        var decision: InterceptionAction?
    }
    private let condition = NSCondition()
    private var enabled = false
    private var holds: [UUID: Hold] = [:]
    private let timeout: TimeInterval
    public init(timeout: TimeInterval = 120) { self.timeout = max(0.05, min(timeout, 300)) }
    public var isEnabled: Bool {
        condition.lock()
        defer { condition.unlock() }
        return enabled
    }
    public func setEnabled(_ value: Bool) {
        condition.lock()
        defer { condition.unlock() }
        enabled = value
        if !value {
            for id in Array(holds.keys) {
                guard let hold = holds[id], hold.decision == nil else { continue }
                holds[id]?.decision = .forward(hold.request)
            }
            condition.broadcast()
        }
    }
    public func pending() -> [HeldRequest] {
        condition.lock()
        defer { condition.unlock() }
        return holds.compactMap { id, hold in
            guard hold.decision == nil else { return nil }
            return HeldRequest(
                id: id, revision: hold.revision, method: hold.request.method, url: hold.request.target,
                headers: hold.request.head.headers.map { LoggedHeader(name: $0.name, value: $0.value) },
                bodyBase64: hold.request.body?.base64EncodedString(), expiresAt: hold.expiresAt)
        }.sorted { $0.expiresAt < $1.expiresAt }
    }
    public func intercept(_ request: RequestContext) -> InterceptionAction {
        condition.lock()
        defer { condition.unlock() }
        guard enabled else { return .forward(request) }
        guard holds.count < 32, holds[request.id] == nil else {
            return Self.drop("Interception queue is full", status: 503)
        }
        holds[request.id] = Hold(request: request, expiresAt: Date().addingTimeInterval(timeout))
        defer { holds.removeValue(forKey: request.id) }
        while let hold = holds[request.id] {
            if let decision = hold.decision { return decision }
            if hold.expiresAt <= Date() { return Self.drop("Interception timed out", status: 504) }
            condition.wait(until: hold.expiresAt)
        }
        return Self.drop("Request cancelled", status: 499)
    }
    public func edit(
        id: UUID, revision: Int, method: String? = nil, url: String? = nil,
        headers: [LoggedHeader]? = nil, body: Data? = nil
    ) throws {
        condition.lock()
        defer { condition.unlock() }
        guard var hold = holds[id], hold.decision == nil, hold.revision == revision, hold.expiresAt > Date() else {
            throw ProxyError.invalidHTTP("Unknown, expired, decided, or stale request revision")
        }
        if let method {
            guard ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"].contains(method) else {
                throw ProxyError.invalidHTTP("Unsupported request method")
            }
            hold.request.method = method
        }
        if let url {
            _ = try JovianRequestExecutor.origin(url)
            hold.request.target = url
        }
        if let headers {
            guard headers.count <= 64, headers.allSatisfy({ HTTPHead.isValidHeader(name: $0.name, value: $0.value) }),
                headers.reduce(0, { $0 + $1.name.utf8.count + $1.value.utf8.count }) <= 65_536
            else { throw ProxyError.invalidHTTP("Invalid headers") }
            let managed = Set([
                "host", "content-length", "transfer-encoding", "connection", "upgrade", "expect", "proxy-authorization",
            ])
            guard
                headers.allSatisfy({
                    !managed.contains($0.name.lowercased()) && !$0.name.lowercased().hasPrefix("x-jovian-execution-")
                })
            else { throw ProxyError.invalidHTTP("Transport-owned headers cannot be edited") }
            hold.request.head.headers = headers.map { ($0.name, $0.value) }
        }
        if let body {
            guard hold.request.body != nil, body.count <= 1_048_576 else {
                throw ProxyError.invalidHTTP("Body is unavailable or exceeds 1 MiB")
            }
            hold.request.body = body
        }
        hold.revision += 1
        holds[id] = hold
    }
    public func decide(id: UUID, revision: Int, forward: Bool) throws {
        condition.lock()
        defer { condition.unlock() }
        guard let hold = holds[id], hold.decision == nil, hold.revision == revision, hold.expiresAt > Date() else {
            throw ProxyError.invalidHTTP("Unknown, expired, decided, or stale request revision")
        }
        holds[id]?.decision = forward ? .forward(hold.request) : Self.drop("Dropped by user", status: 499)
        condition.broadcast()
    }
    public func cancel(_ id: UUID) {
        condition.lock()
        defer { condition.unlock() }
        if holds[id]?.decision == nil { holds[id]?.decision = Self.drop("Request cancelled", status: 499) }
        condition.broadcast()
    }
    public func cancelPending() {
        condition.lock()
        defer { condition.unlock() }
        for id in Array(holds.keys) where holds[id]?.decision == nil {
            holds[id]?.decision = Self.drop("Request cancelled", status: 499)
        }
        condition.broadcast()
    }
    private static func drop(_ text: String, status: Int) -> InterceptionAction {
        .drop(
            SyntheticResponse(
                statusCode: status, reason: "Jovian Interception", headers: [("Content-Type", "text/plain")],
                body: Data(text.utf8)))
    }
}
