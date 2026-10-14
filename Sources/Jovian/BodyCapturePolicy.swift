import Foundation

/// Opt-in bounded body retention.
///
/// JSON and form credential fields are redacted before retention.
public struct BodyCapturePolicy: Sendable {
    public static let sensitiveHeaders: Set<String> = ["authorization", "proxy-authorization", "cookie", "set-cookie"]
    public static let defaultRedactedFields: Set<String> = [
        "password", "passwd", "secret", "token", "access_token", "refresh_token", "api_key", "apikey", "authorization",
    ]
    public let maximumBytes: Int
    public let redactedFields: Set<String>

    public init(maximumBytes: Int = 65_536, redactedFields: Set<String> = Self.defaultRedactedFields) {
        self.maximumBytes = min(4 * 1_024 * 1_024, max(0, maximumBytes))
        self.redactedFields = Set(redactedFields.map { $0.lowercased() })
    }

    func capture(_ body: Data?, headers: [LoggedHeader], truncated: Bool) -> (data: Data?, truncated: Bool) {
        guard let body, maximumBytes > 0 else { return (nil, truncated || body?.isEmpty == false) }
        if body.isEmpty { return (Data(), truncated) }
        let type =
            headers.first { $0.name.caseInsensitiveCompare("Content-Type") == .orderedSame }?.value.lowercased() ?? ""
        let encoding = headers.first { $0.name.caseInsensitiveCompare("Content-Encoding") == .orderedSame }?.value
            .lowercased()
        let structured = type.contains("json") || type.contains("application/x-www-form-urlencoded")
        // A compressed or incomplete structured body cannot be safely field-redacted.
        if structured && !redactedFields.isEmpty && (truncated || (encoding != nil && encoding != "identity")) {
            return (Data("[REDACTED: incomplete or encoded structured body]".utf8).prefixData(maximumBytes), true)
        }
        var safe = body
        if type.contains("json") && !redactedFields.isEmpty {
            guard let object = try? JSONSerialization.jsonObject(with: body, options: [.fragmentsAllowed]),
                let encoded = try? JSONSerialization.data(
                    withJSONObject: redact(object), options: [.fragmentsAllowed, .sortedKeys])
            else { return (Data("[REDACTED: invalid JSON]".utf8).prefixData(maximumBytes), true) }
            safe = encoded
        } else if type.contains("application/x-www-form-urlencoded") && !redactedFields.isEmpty {
            guard let text = String(data: body, encoding: .utf8) else {
                return (Data("[REDACTED: invalid form]".utf8).prefixData(maximumBytes), true)
            }
            safe = Data(
                text.components(separatedBy: "&").map { pair in
                    let key = pair.components(separatedBy: "=").first ?? ""
                    let decoded = key.replacingOccurrences(of: "+", with: " ").removingPercentEncoding ?? key
                    return redactedFields.contains(decoded.lowercased()) ? key + "=%5BREDACTED%5D" : pair
                }.joined(separator: "&").utf8)
        }
        return (safe.prefixData(maximumBytes), truncated || safe.count > maximumBytes)
    }

    static func headers(_ headers: [LoggedHeader]) -> [LoggedHeader] {
        headers.map {
            LoggedHeader(
                name: $0.name, value: sensitiveHeaders.contains($0.name.lowercased()) ? "[REDACTED]" : $0.value)
        }
    }

    private func redact(_ object: Any) -> Any {
        if let values = object as? [String: Any] {
            var result: [String: Any] = [:]
            for (name, value) in values {
                result[name] = redactedFields.contains(name.lowercased()) ? "[REDACTED]" : redact(value)
            }
            return result
        }
        if let array = object as? [Any] { return array.map(redact) }
        return object
    }
}

extension Data {
    fileprivate func prefixData(_ limit: Int) -> Data { Data(prefix(limit)) }
}
