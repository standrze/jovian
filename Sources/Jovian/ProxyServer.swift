import Foundation
import Logging
import NIOCore
import NIOHTTP1
import NIOSSL

/// Independent HTTP/1.1 proxy.
///
/// SwiftNIO owns sockets, HTTP framing, channel backpressure and shutdown.
/// Configuration is immutable; mutable collaborators use locks, actors, or event-loop confinement.
public final class ProxyServer: @unchecked Sendable {
    private let diagnosticLogger = Logger(label: "jovian.proxy")
    let host: String
    let port: UInt16
    let modifier: any Modifier
    let logger: any TrafficLogger
    let redactSensitiveHeaders: Bool
    let credentials: ProxyCredentials?
    let uploadBytesPerSecond: Int?
    let downloadBytesPerSecond: Int?
    let maximumBufferedBodyBytes: Int
    let runtimeConfiguration: RuntimeConfiguration?
    let interceptor: (any RequestInterceptor)?
    let transport: ServerTransport
    let upstreamPool: UpstreamConnectionPool
    let downstreamProxy: DownstreamProxy?
    let certificateAuthority: CertificateAuthority?
    let tlsListenerContext: NIOSSLContext?
    let requestTimeout: TimeInterval
    let proxyName: String
    let viaIdentity: String
    let session: JovianProxySession?
    let controlAPI: ControlAPI?
    let failOnModifierError: Bool

    /// Create a server; port zero selects an available port at `start()`.
    ///
    /// Rates are payload bytes per second; nil or nonpositive rates are unlimited. Body buffering
    /// is clamped to zero or greater; larger bodies stream without modifier body access.
    /// TLS interception requires an explicit authority. Upstream TLS validates system trust by default.
    /// Request timeouts are seconds and zero disables them; connect timeouts are seconds.
    public init(
        host: String = "127.0.0.1", port: UInt16 = 8080,
        modifier: any Modifier = ModifierGroup([]),
        logger: any TrafficLogger = ConsoleTrafficLogger(),
        redactSensitiveHeaders: Bool = true,
        credentials: ProxyCredentials? = nil,
        uploadBytesPerSecond: Int? = nil,
        downloadBytesPerSecond: Int? = nil,
        maximumBufferedBodyBytes: Int = 4 * 1_024 * 1_024,
        runtimeConfiguration: RuntimeConfiguration? = nil,
        interceptor: (any RequestInterceptor)? = nil,
        downstreamProxy: DownstreamProxy? = nil,
        tlsConfiguration: ProxyTLSConfiguration? = nil,
        certificateAuthority: CertificateAuthority? = nil,
        tlsListenerContext: NIOSSLContext? = nil,
        requestTimeout: TimeInterval = 300,
        connectTimeout: TimeInterval = 30,
        proxyName: String = "jovian",
        session: JovianProxySession? = nil,
        controlAPI: ControlAPI? = nil,
        failOnModifierError: Bool = false
    ) {
        let transport = ServerTransport()
        self.transport = transport
        upstreamPool = UpstreamConnectionPool(
            group: transport.group, downstreamProxy: downstreamProxy,
            tlsConfiguration: tlsConfiguration, connectTimeout: connectTimeout)
        self.downstreamProxy = downstreamProxy
        self.certificateAuthority = certificateAuthority
        self.tlsListenerContext = tlsListenerContext
        self.requestTimeout = requestTimeout.isFinite ? max(0, requestTimeout) : 300
        self.proxyName = proxyName
        viaIdentity = "\(proxyName)-\(UUID().uuidString.lowercased())"
        self.session = session
        self.controlAPI = controlAPI
        self.failOnModifierError = failOnModifierError
        self.host = host
        self.port = port
        self.modifier = modifier
        self.logger = logger
        self.redactSensitiveHeaders = redactSensitiveHeaders
        self.credentials = credentials
        self.uploadBytesPerSecond = uploadBytesPerSecond
        self.downloadBytesPerSecond = downloadBytesPerSecond
        self.maximumBufferedBodyBytes = max(0, maximumBufferedBodyBytes)
        self.runtimeConfiguration = runtimeConfiguration
        self.interceptor = interceptor
    }

    /// Run until `stop()` is called.
    ///
    /// Call from an application thread, never a NIO event loop.
    public func run() throws {
        let port = try start()
        diagnosticLogger.info("listening", metadata: ["host": .string(host), "port": .stringConvertible(port)])
        try transport.wait()
    }

    /// Bind synchronously; the returned port is ready to accept connections.
    public func start() throws -> UInt16 {
        try transport.start(
            host: host, port: port,
            configure: { [tlsListenerContext] channel in
                if let tlsListenerContext {
                    try channel.pipeline.syncOperations.addHandler(NIOSSLServerHandler(context: tlsListenerContext))
                }
            }
        ) { [self] connection in
            await handle(connection, scheme: tlsListenerContext == nil ? "http" : "https")
        }
    }

    /// Begin closing the server and cancel pending interception without waiting for teardown.
    ///
    /// Use `shutdown()` when the caller must wait until all server resources are released.
    public func stop() {
        interceptor?.cancelPending()
        let pool = upstreamPool
        transport.stop { await pool.closeAll() }
    }

    /// Close the server and wait for connections, handlers, worker threads, and event loops to finish.
    ///
    /// Concurrent calls share the same teardown; a stopped server cannot be restarted.
    public func shutdown() async {
        interceptor?.cancelPending()
        let pool = upstreamPool
        await transport.shutdown(closingConnections: { await pool.closeAll() })
    }

    /// Stop admitting requests and allow current exchanges to finish within the grace period.
    ///
    /// Idle connections close immediately. At expiry, pending interception is cancelled and all
    /// remaining channels close. `stop()` can force an in-progress drain to finish immediately.
    public func shutdown(gracePeriod: Duration) async {
        let pool = upstreamPool
        await transport.shutdown(
            gracePeriod: gracePeriod,
            onGracePeriodExpired: { [interceptor] in interceptor?.cancelPending() },
            closingConnections: { await pool.closeAll() })
    }

    func handle(_ client: ChannelConnection, scheme: String = "http", authenticatedTunnel: Bool = false) async {
        defer { client.close() }
        while true {
            client.resetResponse()
            let started = ContinuousClock.now
            var method = ""
            var target = ""
            var receivedRequest: RequestContext?
            let deadline = RequestDeadline(client: client.channel, seconds: requestTimeout) { [transport] in
                transport.cancelConnectionTask(client.channel)
            }
            defer { deadline.finish() }
            do {
                guard let event = try await client.next() else { return }
                guard case .request(var head) = event else { throw ProxyError.invalidHTTP("expected request head") }
                guard transport.beginRequest(client.channel) else { return }
                defer { transport.endRequest(client.channel) }
                method = head.method.rawValue
                target = head.uri
                if !authenticatedTunnel, let credentials, !credentials.authorizes(HTTPHead(head)) {
                    try await sendError(
                        client, status: 407, reason: "Proxy Authentication Required", authentication: true)
                    await record(
                        method: method, target: target, status: 407, bytes: 0, start: started, transport: "proxy-auth")
                    return
                }
                if hasProxyLoop(head.headers) {
                    try await sendError(client, status: 400, reason: "Bad Request", message: "proxy loop detected")
                    return
                }
                if let controlAPI, ControlAPI.isReservedTarget(head.uri, head: HTTPHead(head)) {
                    try await controlAPI.serve(head: head, client: client, workers: transport.workers)
                    return
                }
                try session?.validate(
                    method: method,
                    target: head.uri.hasPrefix("/")
                        ? "\(scheme)://\(head.headers.first(name: "Host") ?? "")\(head.uri)" : head.uri)
                _ = try HTTPHead(head).validatedFraming()
                if method == "CONNECT" {
                    try await tunnel(client: client, initialHead: head, started: started, deadline: deadline)
                    return
                }
                if head.uri.hasPrefix("/"), let authority = head.headers.first(name: "Host") {
                    head.uri = "\(scheme)://\(authority)\(head.uri)"
                }
                target = head.uri
                receivedRequest = RequestContext(
                    method: method, target: target, head: HTTPHead(head), body: nil,
                    remoteAddress: client.channel.remoteAddress?.ipAddress)
                let expectations = head.headers[canonicalForm: "expect"].map { $0.lowercased() }
                if !expectations.isEmpty && expectations != ["100-continue"] {
                    try await sendError(client, status: 417, reason: "Expectation Failed")
                    await record(
                        method: method, target: target, status: 417, bytes: 0, start: started, transport: "http")
                    return
                }
                if !expectations.isEmpty {
                    try await client.write(
                        HTTPServerResponsePart.head(HTTPResponseHead(version: .http1_1, status: .continue)))
                }
                if try await !exchange(
                    client: client, initialHead: head, started: started, deadline: deadline, defaultScheme: scheme)
                {
                    return
                }
            } catch {
                if case TrafficShapingError.recordedClose = error { return }
                let failure = error as? ProxyExchangeFailure
                let request =
                    failure?.request ?? receivedRequest
                    ?? RequestContext(method: method, target: target, head: HTTPHead(startLine: ""))
                let underlying = failure?.underlying ?? error
                let failureStatus = underlying is SessionScopeError ? 403 : 502
                let failureReason = failureStatus == 403 ? "Forbidden" : "Bad Gateway"
                let failureDescription = String(describing: underlying)
                if !client.finalResponseStarted {
                    var pacer = TransferPacer(bytesPerSecond: nil)
                    do {
                        _ = try await syntheticResponse(
                            SyntheticResponse(
                                statusCode: failureStatus, reason: failureReason, body: Data(failureReason.utf8)),
                            request: request, client: client, keepAlive: false, started: started, pacer: &pacer,
                            error: failureDescription, transportName: method == "CONNECT" ? "tls-tunnel" : "http",
                            applyModifiers: !(underlying is ResponseModifierFailure || underlying is SessionScopeError))
                        return
                    } catch {
                        // A closed client cannot receive the error response, but the failed exchange still has a record.
                    }
                }
                await record(
                    method: request.method, target: request.target, status: 502, bytes: 0, start: started,
                    transport: method == "CONNECT" ? "tls-tunnel" : "http", error: failureDescription,
                    requestHeaders: redacted(request.head.headers), requestBody: request.body,
                    requestBodyTruncated: request.body == nil)
                return
            }
        }
    }

    func sendError(
        _ client: ChannelConnection, status: Int, reason: String, message: String = "", authentication: Bool = false
    ) async throws {
        let body = Data("\(status) \(reason)\n\(message)".utf8)
        var headers = HTTPHeaders([
            ("Content-Type", "text/plain; charset=utf-8"), ("Content-Length", String(body.count)),
            ("Connection", "close"),
        ])
        if authentication { headers.add(name: "Proxy-Authenticate", value: "Basic realm=\"jovian\"") }
        try await client.write(
            HTTPServerResponsePart.head(
                HTTPResponseHead(
                    version: .http1_1, status: HTTPResponseStatus(statusCode: status, reasonPhrase: reason),
                    headers: headers)))
        try await client.write(HTTPServerResponsePart.body(.byteBuffer(ByteBuffer(bytes: body))))
        try await client.write(HTTPServerResponsePart.end(nil))
    }

    func record(
        method: String, target: String, status: Int, bytes: Int,
        start: ContinuousClock.Instant, transport: String, error: String? = nil,
        requestHeaders: [LoggedHeader] = [], responseHeaders: [LoggedHeader] = [],
        requestBody: Data? = nil, responseBody: Data? = nil,
        requestBodyTruncated: Bool = false, responseBodyTruncated: Bool = false
    ) async {
        let duration = start.duration(to: .now)
        let milliseconds =
            Int(duration.components.seconds * 1_000) + Int(duration.components.attoseconds / 1_000_000_000_000_000)
        let entry = TrafficEntry(
            timestamp: Date(), method: method, target: target, status: status, bytes: bytes,
            durationMilliseconds: milliseconds,
            transport: transport, error: error, requestHeaders: requestHeaders, responseHeaders: responseHeaders,
            requestBody: requestBody,
            responseBody: responseBody, requestBodyTruncated: requestBodyTruncated,
            responseBodyTruncated: responseBodyTruncated)
        try? await self.transport.workers.runIfActive { self.logger.record(entry) }
    }

    func redacted(_ headers: [(name: String, value: String)]) -> [LoggedHeader] {
        let sensitive: Set<String> = ["authorization", "proxy-authorization", "cookie", "set-cookie"]
        return headers.map {
            LoggedHeader(
                name: $0.name,
                value: redactSensitiveHeaders && sensitive.contains($0.name.lowercased()) ? "[REDACTED]" : $0.value)
        }
    }

    func trafficRates() -> (upload: Int?, download: Int?) {
        let runtime = runtimeConfiguration?.trafficRates()
        return (runtime?.upload ?? uploadBytesPerSecond, runtime?.download ?? downloadBytesPerSecond)
    }
}
