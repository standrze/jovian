import Foundation

/// Appends a per-instance Via identity and rejects traffic that has already crossed this proxy.
public struct ViaModifier: Modifier {
    public let identity: String

    public init(requestedBy: String = "jovian") {
        // A token remains valid even when an embedding application supplies a display name.
        let name =
            requestedBy.utf8.allSatisfy {
                (48...57).contains($0) || (65...90).contains($0) || (97...122).contains($0) || $0 == 45
            } && !requestedBy.isEmpty ? requestedBy : "jovian"
        identity = name + "-" + UUID().uuidString.lowercased()
    }

    public func modify(request: inout RequestContext) throws {
        let existing = request.head.values(for: "Via")
        if existing.flatMap({ $0.split(separator: ",") }).contains(where: { entry in
            let fields = entry.split(whereSeparator: { $0 == " " || $0 == "\t" })
            return fields.count >= 2 && fields[1] == identity
        }) {
            throw ProxyLoopError()
        }
        let version = request.head.startLine.split(separator: " ").last.map(String.init) ?? "HTTP/1.1"
        let protocolVersion = version.hasPrefix("HTTP/") ? String(version.dropFirst(5)) : "1.1"
        request.head["Via"] = (existing + [protocolVersion + " " + identity]).joined(separator: ", ")
    }
}

struct ProxyLoopError: Error, CustomStringConvertible {
    var description: String { "proxy request loop detected" }
}
