import Foundation

/// Associates one proxy listener with a stored session.
///
/// Existing in-flight work
/// may finish after close; subsequent requests are rejected.
public final class JovianProxySession: TrafficLogger, @unchecked Sendable {
    private let store: JovianSessionStore
    private let id: UUID
    public init(store: JovianSessionStore, id: UUID) throws {
        let value = try store.load(id)
        guard !value.closed else { throw ProxyError.invalidHTTP("Session is closed; resume it first") }
        self.store = store
        self.id = id
    }
    public func validate(method: String, target: String) throws {
        let value = try store.load(id)
        guard !value.closed else { throw SessionScopeError.denied("Session is closed") }
        if method == "CONNECT" {
            guard let requested = URLComponents(string: "https://" + target),
                let permitted = URLComponents(string: value.origin),
                requested.host?.lowercased() == permitted.host?.lowercased(),
                requested.port == permitted.port
            else { throw SessionScopeError.denied("CONNECT authority outside session origin") }
        } else {
            guard try JovianRequestExecutor.origin(target) == value.origin else {
                throw SessionScopeError.denied("Request outside session origin")
            }
        }
    }
    public func record(_ entry: TrafficEntry) {
        func headers(_ values: [LoggedHeader]) -> [String: String] {
            var result: [String: String] = [:]
            for value in values {
                result[value.name] =
                    ["authorization", "proxy-authorization", "cookie", "set-cookie"].contains(value.name.lowercased())
                    ? "[REDACTED]" : value.value
            }
            return result
        }
        let policy = BodyCapturePolicy()
        let body =
            policy.capture(entry.responseBody, headers: entry.responseHeaders, truncated: entry.responseBodyTruncated)
            .data ?? Data()
        let limited = Data(body.prefix(65_536))
        let text = String(data: limited, encoding: .utf8)
        var exchange = JovianExchange(
            id: UUID().uuidString, url: entry.target, method: entry.method,
            status: entry.status, headers: headers(entry.responseHeaders),
            body: text ?? limited.base64EncodedString(), bodyEncoding: text == nil ? "base64" : "utf8",
            truncated: entry.responseBodyTruncated || body.count > limited.count,
            durationMilliseconds: entry.durationMilliseconds)
        exchange.bodyOmitted = entry.responseBody == nil
        exchange.requestHeaders = headers(entry.requestHeaders)
        exchange.requestBody = policy.capture(
            entry.requestBody, headers: entry.requestHeaders, truncated: entry.requestBodyTruncated
        ).data.flatMap { String(data: $0, encoding: .utf8) }
        exchange.transport = entry.transport
        do { try store.append(exchange, sessionID: id) } catch {
            FileHandle.standardError.write(Data("Jovian session capture failed: \(error)\n".utf8))
        }
    }
}

enum SessionScopeError: Error { case denied(String) }
