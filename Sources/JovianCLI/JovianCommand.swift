import ArgumentParser
import Foundation
import Jovian

#if canImport(Darwin)
    import Darwin
#else
    import Glibc
#endif

@main
struct JovianCommand: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "jovian",
        abstract: "Programmable Swift HTTP/HTTPS proxy.",
        version: "0.3.0",
        subcommands: [Serve.self, CertificateCommand.self, CACommand.self, SessionsCommand.self])
}

struct Serve: ParsableCommand {
    static let configuration = CommandConfiguration(abstract: "Run the proxy and its local administration API.")

    @Option(help: "Proxy listen address.")
    var host = "127.0.0.1"

    @Option(help: "Proxy listen port.")
    var port: UInt16 = 8080

    @Option(help: "Administration API listen address.")
    var apiHost = "127.0.0.1"

    @Option(help: "Administration API listen port.")
    var apiPort: UInt16 = 8181

    @Option(name: .customLong("log"), help: "Write traffic to a JSON Lines file.")
    var logPath: String?

    @Option(name: .customLong("har"), help: "Write traffic to a HAR file.")
    var harPath: String?

    @Flag(help: "Include sensitive headers in traffic logs.")
    var captureSensitiveHeaders = false

    @Option(help: "Proxy authentication username.")
    var proxyUser: String?

    @Option(help: "Environment variable containing the proxy password.")
    var proxyPasswordEnv: String?

    @Option(name: .customLong("upload-bps"), help: "Upload limit in bytes per second (greater than zero).")
    var uploadBPS: Int?

    @Option(name: .customLong("download-bps"), help: "Download limit in bytes per second (greater than zero).")
    var downloadBPS: Int?

    @Option(
        name: [.customLong("downstream-proxy-url"), .customLong("upstream-proxy")],
        help: "HTTP, HTTPS, socks5, or socks5h next hop.")
    var downstreamProxyURL: String?

    @Option(help: "Request socket deadline in seconds; zero disables it.")
    var requestTimeout: Double = 300

    @Option(help: "Upstream connection timeout in seconds.")
    var connectTimeout: Double = 30

    @Option(help: "Seconds to drain current requests on SIGINT or SIGTERM.")
    var shutdownGrace: Double = 30

    @Option(help: "Readable prefix for this instance's unique Via identity.")
    var proxyName = "jovian"

    @Flag(help: "Generate an in-memory CA and enable HTTPS interception.")
    var generateCACert = false

    @Option(help: "PEM CA certificate used for HTTPS interception.")
    var cert: String?

    @Option(help: "Unencrypted PEM private key matching --cert.")
    var key: String?

    @Option(help: "Write the public interception CA certificate as PEM; does not change system trust.")
    var caOutput: String?

    @Option(help: "Also listen for TLS proxy connections on this port; requires a CA.")
    var tlsPort: UInt16?

    @Option(help: "Certificate hostname for TLS clients that omit SNI.")
    var tlsServerName = "localhost"

    @Option(help: "PEM trust roots for HTTPS origins and a next-hop TLS proxy.")
    var upstreamCA: String?

    @Flag(help: "Disable upstream TLS verification for explicitly configured test origins.")
    var skipTLSVerify = false

    @Option(name: .customLong("request-header"), help: "Set a request header as NAME:VALUE; repeat for more headers.")
    var requestHeaders: [HeaderArgument] = []

    @Option(name: .customLong("response-header"), help: "Set a response header as NAME:VALUE; repeat for more headers.")
    var responseHeaders: [HeaderArgument] = []

    @Option(help: "Username for the next-hop proxy only.")
    var upstreamProxyUser: String?
    @Option(help: "Environment variable containing the next-hop password.")
    var upstreamProxyPasswordEnv: String?
    @Option(help: "PEM CA for the HTTPS next hop only, independent of origin trust.")
    var upstreamProxyCA: String?
    @Option(help: "Persistent CA directory for interception.")
    var interceptCA: String?
    @Option(help: "CA directory for a dynamic TLS listener.")
    var tlsCA: String?
    @Option(help: "PEM TLS listener certificate chain.")
    var tlsCert: String?
    @Option(help: "PEM TLS listener private key.")
    var tlsKey: String?
    @Option(help: "TLS listen address; defaults to --host.")
    var tlsHost: String?
    @Option(help: "Fallback TLS certificate hostname; alias of --tls-server-name.")
    var tlsDefaultHost: String?
    @Option(help: "Drain duration in milliseconds; overrides --shutdown-grace.")
    var shutdownGraceMS: Int?
    @Flag(help: "Enable CORS for the local control API.")
    var apiCORS = false
    @Flag(help: "Retain bounded, redacted HAR bodies.")
    var harBodies = false
    @Option(help: "Maximum captured bytes per HAR body.")
    var harBodyLimit = 65_536
    @Option(help: "Total retained HAR body budget in bytes.")
    var harBodyBudget = 32 * 1_024 * 1_024
    @Option(name: .customLong("body-redact-field"), help: "Additional JSON/form field to redact; repeatable.")
    var bodyRedactFields: [String] = []
    @Option(help: "Session name or ID restricting this proxy to one origin.")
    var session: String?
    @Option(help: "Session storage directory.")
    var sessionsDirectory: String?

    mutating func validate() throws {
        if let shutdownGraceMS {
            guard (0...300_000).contains(shutdownGraceMS) else {
                throw ValidationError("--shutdown-grace-ms must be 0 through 300000")
            }
            shutdownGrace = Double(shutdownGraceMS) / 1_000
        }
        guard (1...4_194_304).contains(harBodyLimit), (1...268_435_456).contains(harBodyBudget) else {
            throw ValidationError("invalid HAR body limit or budget")
        }
        guard (upstreamProxyUser == nil) == (upstreamProxyPasswordEnv == nil),
            downstreamProxyURL != nil || (upstreamProxyUser == nil && upstreamProxyCA == nil)
        else {
            throw ValidationError(
                "next-hop credentials and CA require --upstream-proxy; credentials require user and password environment variable"
            )
        }
        guard (tlsCert == nil) == (tlsKey == nil), tlsCA == nil || tlsCert == nil,
            tlsPort != nil || (tlsCA == nil && tlsCert == nil && tlsHost == nil && tlsDefaultHost == nil)
        else {
            throw ValidationError("TLS listener requires --tls-port and either a CA or matching --tls-cert/--tls-key")
        }
        guard interceptCA == nil || (!generateCACert && cert == nil) else {
            throw ValidationError("choose one interception CA source")
        }

        guard requestTimeout.isFinite, requestTimeout >= 0,
            connectTimeout.isFinite, connectTimeout > 0,
            shutdownGrace.isFinite, shutdownGrace >= 0
        else { throw ValidationError("timeouts must be finite and nonnegative; --connect-timeout must be positive.") }
        guard !proxyName.isEmpty, proxyName.allSatisfy({ $0.isASCII && ($0.isLetter || $0.isNumber || $0 == "-") })
        else {
            throw ValidationError("--proxy-name must contain only ASCII letters, digits, or hyphens.")
        }
        guard (cert == nil) == (key == nil) else {
            throw ValidationError("--cert and --key must be used together.")
        }
        guard !generateCACert || cert == nil else {
            throw ValidationError("use --generate-ca-cert or --cert/--key, not both.")
        }
        guard
            (tlsPort == nil && caOutput == nil) || generateCACert || cert != nil || interceptCA != nil
                || (caOutput == nil && (tlsCA != nil || tlsCert != nil))
        else {
            throw ValidationError("--tls-port and --ca-output require --generate-ca-cert or --cert/--key.")
        }
        if let downstreamProxyURL {
            guard let url = URL(string: downstreamProxyURL) else {
                throw ValidationError("invalid downstream proxy URL")
            }
            _ = try DownstreamProxy(
                url: url, credentials: upstreamCredentials(),
                certificateAuthority: upstreamProxyCA.map { URL(fileURLWithPath: $0) })
        }
        if let uploadBPS, uploadBPS <= 0 {
            throw ValidationError("--upload-bps must be greater than zero.")
        }
        if let downloadBPS, downloadBPS <= 0 {
            throw ValidationError("--download-bps must be greater than zero.")
        }
        guard (proxyUser == nil) == (proxyPasswordEnv == nil) else {
            throw ValidationError("--proxy-user and --proxy-password-env must be used together.")
        }
    }

    func credentials(environment: [String: String] = ProcessInfo.processInfo.environment) throws -> ProxyCredentials? {
        guard let proxyUser, let proxyPasswordEnv else { return nil }
        guard let password = environment[proxyPasswordEnv] else {
            throw ValidationError("environment variable \(proxyPasswordEnv) is not set")
        }
        return ProxyCredentials(username: proxyUser, password: password)
    }

    func upstreamCredentials(environment: [String: String] = ProcessInfo.processInfo.environment) throws
        -> ProxyCredentials?
    {
        guard let upstreamProxyUser, let upstreamProxyPasswordEnv else { return nil }
        guard let password = environment[upstreamProxyPasswordEnv] else {
            throw ValidationError("next-hop password environment variable is not set")
        }
        return ProxyCredentials(username: upstreamProxyUser, password: password)
    }

    func run() throws {
        try ProxyApplication(options: self).run()
    }
}

struct HeaderArgument: ExpressibleByArgument, Sendable {
    let name: String
    let value: String

    init?(argument: String) {
        guard let colon = argument.firstIndex(of: ":") else { return nil }
        name = String(argument[..<colon])
        value = String(argument[argument.index(after: colon)...]).trimmingCharacters(in: .whitespaces)
    }
}
