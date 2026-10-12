import Foundation
import Logging
import NIOCore
import NIOHTTP1

/// Control API modeled after Martian's configure, HAR, and verifier endpoints.
///
/// Defaults to loopback. Stored references are immutable; configuration, traffic storage, and
/// transport each synchronize their own mutable state.
public final class AdminServer: @unchecked Sendable {
    private let diagnosticLogger = Logger(label: "jovian.admin")
    private let host: String
    private let port: UInt16
    private let configuration: RuntimeConfiguration
    private let har: HARStore
    private let transport = ServerTransport()
    private let api: ControlAPI

    /// Creates the listener configuration; port zero requests an available ephemeral port.
    public init(
        host: String = "127.0.0.1", port: UInt16 = 8181, configuration: RuntimeConfiguration, har: HARStore,
        certificateAuthority: CertificateAuthority? = nil, allowCORS: Bool = false
    ) {
        self.host = host
        self.port = port
        self.configuration = configuration
        self.har = har
        self.api = ControlAPI(
            configuration: configuration, har: har, certificateAuthority: certificateAuthority, allowCORS: allowCORS)
    }

    /// Bind and wait on the application's calling thread; NIO handles clients asynchronously.
    public func run() throws {
        let boundPort = try start()
        diagnosticLogger.info("listening", metadata: ["host": .string(host), "port": .stringConvertible(boundPort)])
        try transport.wait()
    }

    /// Return the bound port once ready, including when port zero was requested.
    public func start() throws -> UInt16 {
        try transport.start(host: host, port: port) { [self] client in await handle(client) }
    }

    /// Begins asynchronous teardown; repeated calls share the same transport shutdown.
    public func stop() { transport.stop() }

    /// Close the API listener and wait for its channels, workers, and event loops to finish.
    public func shutdown() async { await transport.shutdown() }

    private func handle(_ client: ChannelConnection) async {
        defer { client.close() }
        do {
            guard case .request(let head)? = try await client.next() else { return }
            try await api.serve(head: head, client: client, workers: transport.workers)
        } catch { client.close() }
    }
}
