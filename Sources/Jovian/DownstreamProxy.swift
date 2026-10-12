import Foundation
import X509

/// An HTTP, HTTPS, or SOCKS5 next hop.
///
/// SOCKS hostnames are resolved by the proxy.
public struct DownstreamProxy: Sendable {
    enum Scheme: String { case http, https, socks5, socks5h }
    public let host: String
    public let port: Int
    public var usesTLS: Bool { scheme == .https }
    var usesHTTPForwarding: Bool { scheme == .http || scheme == .https }
    let scheme: Scheme
    let authorization: String?
    let credentials: ProxyCredentials?
    let trustRootsPEM: Data?

    /// Existing URL credentials remain supported; explicit credentials cannot be combined with them.
    public init(url: URL, credentials: ProxyCredentials? = nil, certificateAuthority: URL? = nil) throws {
        guard let components = URLComponents(url: url, resolvingAgainstBaseURL: false),
            let scheme = components.scheme.flatMap({ Scheme(rawValue: $0.lowercased()) }),
            let host = components.host, !host.isEmpty,
            !host.unicodeScalars.contains(where: { $0.value <= 32 || $0.value == 127 }),
            components.path.isEmpty || components.path == "/", components.query == nil, components.fragment == nil,
            (1...65535).contains(components.port ?? (scheme == .https ? 443 : scheme == .http ? 80 : 1080)),
            credentials == nil || components.user == nil,
            components.password == nil || components.user != nil,
            certificateAuthority == nil || scheme == .https
        else { throw ProxyError.invalidHTTP("invalid HTTP, HTTPS, or SOCKS5 upstream proxy URL or credentials") }
        let selected =
            credentials ?? components.user.map { ProxyCredentials(username: $0, password: components.password ?? "") }
        if ![Scheme.http, .https].contains(scheme), let selected { try SOCKS5Handshake.validate(selected) }
        self.host = host.trimmingCharacters(in: CharacterSet(charactersIn: "[]"))
        self.port = components.port ?? (scheme == .https ? 443 : scheme == .http ? 80 : 1080)
        self.scheme = scheme
        self.credentials = selected
        authorization =
            [Scheme.http, .https].contains(scheme)
            ? selected.map {
                "Basic " + Data("\($0.username):\($0.password)".utf8).base64EncodedString()
            } : nil
        trustRootsPEM = try certificateAuthority.map {
            let bytes = try Data(contentsOf: $0)
            if String(decoding: bytes, as: UTF8.self).contains("-----BEGIN CERTIFICATE-----") { return bytes }
            return Data(try Certificate(derEncoded: Array(bytes)).serializeAsPEM().pemString.utf8)
        }
    }

    public init(url: String, credentials: ProxyCredentials? = nil, certificateAuthority: URL? = nil) throws {
        guard !url.unicodeScalars.contains(where: { $0.value <= 32 || $0.value == 127 }), let parsed = URL(string: url),
            parsed.user == nil, parsed.password == nil
        else {
            throw ProxyError.invalidHTTP("invalid upstream proxy URL")
        }
        try self.init(url: parsed, credentials: credentials, certificateAuthority: certificateAuthority)
    }
}

/// Preferred next-hop name; the original DownstreamProxy API remains source compatible.
public typealias UpstreamProxy = DownstreamProxy
