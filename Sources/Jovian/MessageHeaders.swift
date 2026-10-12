import Foundation

/// Go's special HTTP message fields, projected onto Jovian's header representation.
enum MessageHeaders {
    static func values(_ name: String, head: HTTPHead, response: Bool) -> [String] {
        switch name.lowercased() {
        case "host":
            return response ? [] : head.values(for: name).filter { !$0.isEmpty }
        case "content-length":
            let length = length(head)
            return length > 0 ? [String(length)] : []
        case "transfer-encoding":
            return head.values(for: name).flatMap {
                $0.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }
            }
        default:
            return head.values(for: name)
        }
    }

    static func first(_ name: String, head: HTTPHead, response: Bool) -> String {
        if name.lowercased() == "content-length" {
            return length(head) >= 0 ? String(length(head)) : ""
        }
        return values(name, head: head, response: response).first ?? ""
    }

    static func set(_ name: String, value: String, head: inout HTTPHead, response: Bool) throws {
        guard HTTPHead.isValidHeader(name: name, value: value) else {
            throw ProxyError.invalidHTTP("invalid modifier header")
        }
        switch name.lowercased() {
        case "host":
            if !response { head[name] = value }
        case "content-length":
            guard let length = Int64(value), !value.isEmpty,
                value.dropFirst(value.hasPrefix("-") || value.hasPrefix("+") ? 1 : 0)
                    .utf8.allSatisfy({ (48...57).contains($0) })
            else {
                throw ProxyError.invalidHTTP("modifier Content-Length must be a signed 64-bit integer")
            }
            head[name] = length < 0 ? nil : String(length)
            head.modifierContentLength = length
        default:
            head[name] = value
        }
    }

    static func append(_ name: String, value: String, head: inout HTTPHead, response: Bool) throws {
        switch name.lowercased() {
        case "host":
            guard first(name, head: head, response: response).isEmpty else {
                throw ProxyError.invalidHTTP("cannot append a second Host")
            }
            try set(name, value: value, head: &head, response: response)
        case "content-length":
            guard length(head) <= 0 else { throw ProxyError.invalidHTTP("cannot append a second Content-Length") }
            try set(name, value: value, head: &head, response: response)
        default:
            guard HTTPHead.isValidHeader(name: name, value: value) else {
                throw ProxyError.invalidHTTP("invalid modifier header")
            }
            head.add(name: name, value: value)
        }
    }

    static func remove(_ name: String, head: inout HTTPHead, response: Bool) {
        if name.lowercased() == "host", response { return }
        if name.lowercased() == "content-length" { head.modifierContentLength = -1 }
        head.remove(name)
    }

    private static func length(_ head: HTTPHead) -> Int64 {
        head.modifierContentLength ?? head["Content-Length"].flatMap(Int64.init) ?? -1
    }
}
