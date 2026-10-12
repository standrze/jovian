import Foundation
import NIOHTTP1

extension ProxyServer {
    func hasProxyLoop(_ headers: HTTPHeaders) -> Bool {
        headers[canonicalForm: "via"].contains { value in
            let parts = value.split(whereSeparator: \.isWhitespace)
            return parts.count >= 2 && parts[1].caseInsensitiveCompare(viaIdentity) == .orderedSame
        }
    }

    func addForwardingHeaders(to request: inout RequestContext, version: HTTPVersion) {
        let hops = request.head.values(for: "Via") + ["\(version.major).\(version.minor) \(viaIdentity)"]
        request.head["Via"] = hops.joined(separator: ", ")
        if let remoteAddress = request.remoteAddress {
            let previous = request.head["X-Forwarded-For"]
            request.head["X-Forwarded-For"] = [previous, remoteAddress].compactMap { $0 }.joined(separator: ", ")
        }
        if request.head["X-Forwarded-Host"] == nil { request.head["X-Forwarded-Host"] = request.head["Host"] }
        if request.head["X-Forwarded-Proto"] == nil {
            request.head["X-Forwarded-Proto"] = URLComponents(string: request.target)?.scheme ?? "http"
        }
        if request.head["X-Forwarded-Url"] == nil { request.head["X-Forwarded-Url"] = request.target }
    }
    func ensureVia(_ head: inout HTTPHead) {
        let present = head.values(for: "Via").joined(separator: ",").split(separator: ",").contains {
            $0.split(whereSeparator: \.isWhitespace).dropFirst().first == Substring(viaIdentity)
        }
        if !present { head.add(name: "Via", value: "1.1 \(viaIdentity)") }
    }

    func addModifierWarning(_ error: Error, to head: inout HTTPHead) {
        let text = String(describing: error).unicodeScalars.filter { $0.value >= 32 && $0.value < 127 }
        let escaped = String(String.UnicodeScalarView(text)).replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: "\"", with: "\\\"")
        head.add(name: "Warning", value: "199 jovian \"\(escaped)\"")
    }
}
