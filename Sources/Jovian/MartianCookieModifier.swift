import Foundation

/// Martian's append semantics, separate from Jovian's native cookie set/remove rule.
public struct MartianCookieModifier: Modifier {
    public let name: String
    public let value: String
    public let responseValue: String

    public init(
        name: String, value: String = "", path: String = "", domain: String = "",
        expires: Date? = nil, secure: Bool = false, httpOnly: Bool = false, maxAge: Int = 0
    ) throws {
        guard HTTPHead.isValidHeader(name: name, value: ""),
            value.utf8.allSatisfy({ $0 >= 32 && $0 < 127 && $0 != 34 && $0 != 59 && $0 != 92 }),
            path.utf8.allSatisfy({ $0 >= 32 && $0 < 127 && $0 != 59 }),
            domain.isEmpty || Self.validDomain(domain)
        else {
            throw ProxyError.invalidHTTP("invalid cookie name, value, path, or domain")
        }
        self.name = name
        self.value = value.contains(" ") || value.contains(",") ? "\"\(value)\"" : value
        var fields = ["\(name)=\(self.value)"]
        if !path.isEmpty { fields.append("Path=\(path)") }
        if !domain.isEmpty { fields.append("Domain=\(domain.hasPrefix(".") ? String(domain.dropFirst()) : domain)") }
        if let expires {
            let formatter = DateFormatter()
            formatter.locale = Locale(identifier: "en_US_POSIX")
            formatter.timeZone = TimeZone(secondsFromGMT: 0)
            formatter.dateFormat = "EEE, dd MMM yyyy HH:mm:ss 'GMT'"
            fields.append("Expires=\(formatter.string(from: expires))")
        }
        if maxAge != 0 { fields.append("Max-Age=\(max(0, maxAge))") }
        if httpOnly { fields.append("HttpOnly") }
        if secure { fields.append("Secure") }
        responseValue = fields.joined(separator: "; ")
    }

    public func modify(request: inout RequestContext) {
        let existing = request.head["Cookie"] ?? ""
        request.head["Cookie"] = (existing.isEmpty ? "" : existing + "; ") + "\(name)=\(value)"
    }

    public func modify(response: inout ResponseContext) {
        response.head.add(name: "Set-Cookie", value: responseValue)
    }

    private static func validDomain(_ value: String) -> Bool {
        let domain = value.hasPrefix(".") ? String(value.dropFirst()) : value
        return !domain.isEmpty && domain.utf8.count <= 253
            && domain.split(separator: ".", omittingEmptySubsequences: false)
                .allSatisfy { label in
                    !label.isEmpty && label.utf8.count <= 63 && label.first != "-" && label.last != "-"
                        && label.utf8.allSatisfy {
                            (48...57).contains($0) || (65...90).contains($0) || (97...122).contains($0) || $0 == 45
                        }
                }
    }
}
