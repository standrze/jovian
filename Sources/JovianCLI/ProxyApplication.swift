import Foundation
import Jovian

#if canImport(Darwin)
    import Darwin
#else
    import Glibc
#endif

/// Owns CLI startup, optional listener identities, signals, and complete resource teardown.
struct ProxyApplication {
    let options: Serve

    func run() throws {
        let runtime = RuntimeConfiguration()
        let har = HARStore()
        let authority = try makeAuthority()
        if let path = options.caOutput, let authority {
            try authority.certificatePEM.write(to: URL(fileURLWithPath: path), options: .atomic)
        }
        let upstreamRoots = try options.upstreamCA.map { try Data(contentsOf: URL(fileURLWithPath: $0)) }
        let tls = try ProxyTLSConfiguration(
            trustRootsPEM: upstreamRoots, insecureSkipVerification: options.skipTLSVerify)
        let downstream = try options.downstreamProxyURL.map { value in
            guard let url = URL(string: value) else { throw ProxyError.invalidHTTP("invalid downstream proxy URL") }
            return try DownstreamProxy(url: url)
        }
        var modifiers: [any Modifier] = options.requestHeaders.map {
            HeaderModifier(scope: .request, name: $0.name, value: $0.value)
        }
        modifiers += options.responseHeaders.map {
            HeaderModifier(scope: .response, name: $0.name, value: $0.value)
        }
        modifiers.append(runtime)
        var loggers: [any TrafficLogger] = [ConsoleTrafficLogger(), runtime, har]
        if let path = options.logPath { loggers.append(try JSONLinesTrafficLogger(url: URL(fileURLWithPath: path))) }
        if let path = options.harPath { loggers.append(try HARFileLogger(url: URL(fileURLWithPath: path))) }
        let modifier = ModifierGroup(modifiers)
        let logger = CompositeTrafficLogger(loggers)
        let credentials = try options.credentials()
        let server = ProxyServer(
            host: options.host, port: options.port, modifier: modifier, logger: logger,
            redactSensitiveHeaders: !options.captureSensitiveHeaders,
            credentials: credentials, uploadBytesPerSecond: options.uploadBPS,
            downloadBytesPerSecond: options.downloadBPS, runtimeConfiguration: runtime,
            downstreamProxy: downstream, tlsConfiguration: tls, certificateAuthority: authority,
            requestTimeout: options.requestTimeout, connectTimeout: options.connectTimeout, proxyName: options.proxyName
        )
        var servers = [server]
        if let port = options.tlsPort, let authority {
            let listenerContext = try authority.listenerContext(defaultHostname: options.tlsServerName)
            servers.append(
                ProxyServer(
                    host: options.host, port: port, modifier: modifier, logger: logger,
                    redactSensitiveHeaders: !options.captureSensitiveHeaders,
                    credentials: credentials, uploadBytesPerSecond: options.uploadBPS,
                    downloadBytesPerSecond: options.downloadBPS, runtimeConfiguration: runtime,
                    downstreamProxy: downstream, tlsConfiguration: tls, certificateAuthority: authority,
                    tlsListenerContext: listenerContext, requestTimeout: options.requestTimeout,
                    connectTimeout: options.connectTimeout, proxyName: options.proxyName))
        }
        let admin = AdminServer(host: options.apiHost, port: options.apiPort, configuration: runtime, har: har)
        defer {
            admin.stop()
            for server in servers { server.stop() }
        }
        _ = try admin.start()
        for server in servers { _ = try server.start() }
        waitForShutdown(servers: servers, admin: admin)
    }

    private func makeAuthority() throws -> CertificateAuthority? {
        if options.generateCACert { return try CertificateAuthority.generate() }
        guard let certificate = options.cert, let key = options.key else { return nil }
        return try CertificateAuthority(
            certificatePEM: Data(contentsOf: URL(fileURLWithPath: certificate)),
            privateKeyPEM: Data(contentsOf: URL(fileURLWithPath: key)))
    }

    private func waitForShutdown(servers: [ProxyServer], admin: AdminServer) {
        let completed = DispatchSemaphore(value: 0)
        let grace = Duration.seconds(options.shutdownGrace)
        let signals = [SIGINT, SIGTERM].map { number in
            signal(number, SIG_IGN)
            let source = DispatchSource.makeSignalSource(signal: number, queue: .global())
            source.setEventHandler {
                Task {
                    await withTaskGroup(of: Void.self) { group in
                        for server in servers { group.addTask { await server.shutdown(gracePeriod: grace) } }
                    }
                    await admin.shutdown()
                    completed.signal()
                }
            }
            source.resume()
            return source
        }
        completed.wait()
        for source in signals { source.cancel() }
    }
}
