import Foundation

/// An HTTP or HTTPS proxy that receives forwarded requests and CONNECT tunnels.
///
/// URL credentials are sent only to this proxy. They are never copied into traffic records.
public struct DownstreamProxy: Sendable {
    public let host: String
    public let port: Int
    public let usesTLS: Bool
    let authorization: String?

    /// Validate an absolute proxy URL, optionally containing percent-encoded Basic credentials.
    public init(url: URL) throws {
        guard let components = URLComponents(url: url, resolvingAgainstBaseURL: false),
            let scheme = components.scheme?.lowercased(), ["http", "https"].contains(scheme),
            let host = components.host, !host.isEmpty,
            components.path.isEmpty || components.path == "/",
            components.query == nil, components.fragment == nil,
            (1...65535).contains(components.port ?? (scheme == "https" ? 443 : 80))
        else { throw ProxyError.invalidHTTP("downstream proxy must be an HTTP or HTTPS URL with no path") }
        self.host = host.trimmingCharacters(in: CharacterSet(charactersIn: "[]"))
        self.port = components.port ?? (scheme == "https" ? 443 : 80)
        self.usesTLS = scheme == "https"
        if let username = components.user {
            let credentials = Data("\(username):\(components.password ?? "")".utf8).base64EncodedString()
            authorization = "Basic \(credentials)"
        } else {
            authorization = nil
        }
    }
}
