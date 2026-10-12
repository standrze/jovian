import Foundation

/// HTTP header operations including Martian special fields.
///
///
/// Copy follows Martian's first-value semantics.
public struct HeaderOperationModifier: Modifier {
    public enum Operation: Codable, Sendable {
        case append(name: String, value: String)
        case blacklist(names: [String])
        case copy(from: String, to: String)
    }

    private let operation: Operation
    private let scopes: Set<String>

    public init(_ operation: Operation, scope: [String] = ["request", "response"]) throws {
        let scopes = Set(scope.map { $0.lowercased() })
        guard !scopes.isEmpty, scopes.isSubset(of: ["request", "response"]) else {
            throw ProxyError.invalidHTTP("header operation scope must contain request and/or response")
        }
        let headers: [(String, String)]
        switch operation {
        case .append(let name, let value): headers = [(name, value)]
        case .blacklist(let names): headers = names.map { ($0, "") }
        case .copy(let from, let to): headers = [(from, ""), (to, "")]
        }
        guard headers.allSatisfy({ HTTPHead.isValidHeader(name: $0.0, value: $0.1) }) else {
            throw ProxyError.invalidHTTP("header operation requires valid HTTP header names and values")
        }
        self.operation = operation
        self.scopes = scopes
    }

    public func modify(request: inout RequestContext) throws {
        if scopes.contains("request") { try apply(to: &request.head, response: false) }
    }

    public func modify(response: inout ResponseContext) throws {
        if scopes.contains("response") { try apply(to: &response.head, response: true) }
    }

    private func apply(to head: inout HTTPHead, response: Bool) throws {
        switch operation {
        case .append(let name, let value):
            try MessageHeaders.append(name, value: value, head: &head, response: response)
        case .blacklist(let names):
            for name in names { MessageHeaders.remove(name, head: &head, response: response) }
        case .copy(let from, let to):
            let value = MessageHeaders.first(from, head: head, response: response)
            try MessageHeaders.set(to, value: value, head: &head, response: response)
        }
    }
}

/// Adds X-Martian-ID when absent/empty.
///
/// Response echo is a Jovian extension.
public struct HeaderIDModifier: Modifier {
    public let echoResponse: Bool

    public init(echoResponse: Bool = false) { self.echoResponse = echoResponse }

    public func modify(request: inout RequestContext) {
        if request.head["X-Martian-ID"]?.isEmpty != false {
            request.head["X-Martian-ID"] = request.id.uuidString.lowercased()
        }
    }

    public func modify(response: inout ResponseContext) {
        guard echoResponse, let id = response.requestHead?["X-Martian-ID"], !id.isEmpty else { return }
        response.head["X-Martian-ID"] = id
    }
}
