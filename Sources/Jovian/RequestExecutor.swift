import Foundation

/// Experimental direct-request API.
///
/// Uses system TLS verification and deliberately
/// does not follow redirects or share a browser's cookies/credentials.
public struct JovianExchange: Codable, Sendable {
    public let id: String
    public let url: String
    public let method: String
    public let status: Int
    public let headers: [String: String]
    public var body: String
    public var transport: String? = nil
    public var bodyOmitted: Bool? = nil
    public var requestHeaders: [String: String]? = nil
    public var requestBody: String? = nil
    public let bodyEncoding: String
    public let truncated: Bool
    public let durationMilliseconds: Int
}

private final class NoRedirect: NSObject, URLSessionTaskDelegate, @unchecked Sendable {
    func urlSession(
        _ session: URLSession, task: URLSessionTask,
        willPerformHTTPRedirection response: HTTPURLResponse,
        newRequest request: URLRequest,
        completionHandler: @escaping (URLRequest?) -> Void
    ) {
        completionHandler(nil)
    }
}

public enum JovianRequestExecutor {
    public static func origin(_ address: String) throws -> String {
        guard address.utf8.count <= 4096, let u = URLComponents(string: address),
            let scheme = u.scheme?.lowercased(), ["http", "https"].contains(scheme),
            let host = u.host?.lowercased(), !host.isEmpty,
            u.user == nil, u.password == nil, u.fragment == nil,
            let port = UInt16(exactly: u.port ?? (scheme == "https" ? 443 : 80)), port > 0,
            !address.unicodeScalars.contains(where: {
                CharacterSet.whitespacesAndNewlines.union(.controlCharacters).contains($0)
            })
        else {
            throw ProxyError.invalidHTTP("Use an absolute HTTP(S) URL without credentials or fragments")
        }
        return "\(scheme)://\(host):\(port)"
    }

    public static func send(
        url address: String, method: String, headers: [String: String],
        body: String?, allowedOrigin: String, cookies: [JovianCookie] = [],
        onCookies: @Sendable ([JovianCookie]) throws -> Void = { _ in }
    ) async throws -> JovianExchange {
        guard try origin(address) == allowedOrigin else {
            throw ProxyError.invalidHTTP("Destination is outside the user-enabled Jovian origin")
        }
        guard ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"].contains(method),
            let url = URL(string: address), (body?.utf8.count ?? 0) <= 65_536,
            headers.count <= 32
        else { throw ProxyError.invalidHTTP("Invalid method, URL, or request size") }
        let forbidden = Set([
            "host", "connection", "content-length", "transfer-encoding", "upgrade", "proxy-authorization",
            "proxy-connection", "expect",
        ])
        var request = URLRequest(url: url)
        request.httpMethod = method
        for (key, value) in headers {
            guard HTTPHead.isValidHeader(name: key, value: value),
                key.utf8.count + value.utf8.count <= 8192, !forbidden.contains(key.lowercased())
            else {
                throw ProxyError.invalidHTTP("Invalid or transport-owned header")
            }
            request.setValue(value, forHTTPHeaderField: key)
        }
        if !headers.keys.contains(where: { $0.lowercased() == "cookie" }) {
            let value = cookies.filter { $0.matches(url) }.map { "\($0.name)=\($0.value)" }.joined(separator: "; ")
            if !value.isEmpty { request.setValue(value, forHTTPHeaderField: "Cookie") }
        }
        request.httpBody = body.map { Data($0.utf8) }
        let config = URLSessionConfiguration.ephemeral
        config.timeoutIntervalForRequest = 20
        config.timeoutIntervalForResource = 30
        config.httpCookieStorage = nil
        config.httpShouldSetCookies = false
        config.urlCredentialStorage = nil
        config.urlCache = nil
        config.requestCachePolicy = .reloadIgnoringLocalCacheData
        let session = URLSession(configuration: config)
        defer { session.invalidateAndCancel() }
        let start = Date()
        try Task.checkCancellation()
        let (bytes, response) = try await session.bytes(for: request, delegate: NoRedirect())
        guard let response = response as? HTTPURLResponse else { throw ProxyError.connection("No HTTP response") }
        let nativeCookies = HTTPCookie.cookies(
            withResponseHeaderFields: Dictionary(
                uniqueKeysWithValues:
                    response.allHeaderFields.map { (String(describing: $0.key), String(describing: $0.value)) }),
            for: url)
        try onCookies(nativeCookies.compactMap { JovianCookie($0, source: url) })
        var data = Data()
        var truncated = false
        for try await byte in bytes {
            try Task.checkCancellation()
            if data.count == 65_536 {
                truncated = true
                break
            }
            data.append(byte)
        }
        let secrets = Set(["authorization", "proxy-authorization", "cookie", "set-cookie"])
        var outputHeaders: [String: String] = [:]
        for (key, value) in response.allHeaderFields {
            let name = String(describing: key)
            outputHeaders[name] = secrets.contains(name.lowercased()) ? "[REDACTED]" : String(describing: value)
        }
        let text = String(data: data, encoding: .utf8)
        var exchange = JovianExchange(
            id: UUID().uuidString, url: address, method: method,
            status: response.statusCode, headers: outputHeaders,
            body: text ?? data.base64EncodedString(), bodyEncoding: text == nil ? "base64" : "utf8",
            truncated: truncated, durationMilliseconds: Int(Date().timeIntervalSince(start) * 1000))
        exchange.requestHeaders = headers.mapValues { $0 }
        for key in exchange.requestHeaders!.keys where secrets.contains(key.lowercased()) {
            exchange.requestHeaders![key] = "[REDACTED]"
        }
        exchange.requestBody = body
        return exchange
    }
}
