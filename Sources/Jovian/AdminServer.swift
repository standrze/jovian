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

    /// Creates the listener configuration; port zero requests an available ephemeral port.
    public init(host: String = "127.0.0.1", port: UInt16 = 8181, configuration: RuntimeConfiguration, har: HARStore) {
        self.host = host
        self.port = port
        self.configuration = configuration
        self.har = har
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
            if let length = head.headers.first(name: "Content-Length"), Int(length).map({ $0 > 1_048_576 }) == true {
                throw ProxyError.invalidHTTP("admin request body exceeds 1 MiB")
            }
            var body = Data()
            var complete = false
            while let event = try await client.next() {
                switch event {
                case .body(let bytes):
                    guard body.count + bytes.readableBytes <= 1_048_576 else {
                        throw ProxyError.invalidHTTP("admin request body exceeds 1 MiB")
                    }
                    body.append(contentsOf: bytes.readableBytesView)
                case .end: complete = true
                default: throw ProxyError.invalidHTTP("admin request body")
                }
                if complete { break }
            }
            guard complete else { throw ProxyError.invalidHTTP("admin request body ended early") }
            let requestBody = body
            let response = try await transport.workers.runIfActive { [self] in
                try route(method: head.method.rawValue, path: head.uri, body: requestBody)
            }
            try await respond(client, status: response.status, body: response.body)
        } catch {
            try? await respond(client, status: 400, body: json(["error": String(describing: error)]))
        }
    }

    private func route(method: String, path: String, body: Data) throws -> (status: Int, body: Data) {
        switch (method, path) {
        case ("GET", "/health"): return (200, json(["status": "ok", "harEntries": har.count()]))
        case ("GET", "/configure"): return (200, try configuration.encodedConfiguration())
        case ("POST", "/configure"):
            if MartianConfigurationParser.isCanonical(body) {
                try configuration.replace(martianJSON: body)
                return (200, Data())
            }
            try configuration.replace(with: JSONDecoder().decode(RuntimeConfigurationDocument.self, from: body))
            return (200, try encode(configuration.snapshot()))
        case ("GET", "/logs"): return (200, try har.encodedHAR())
        case ("DELETE", "/logs/reset"), ("POST", "/logs/reset"):
            har.reset()
            return (200, json(["status": "reset"]))
        case ("GET", "/verify"): return (200, try encode(["errors": configuration.verificationFailures()]))
        case ("POST", "/verify/reset"), ("DELETE", "/verify/reset"):
            configuration.resetVerificationFailures()
            return (200, json(["status": "reset"]))
        default: return (404, json(["error": "not found"]))
        }
    }

    private func respond(_ client: ChannelConnection, status: Int, body: Data) async throws {
        let headers = HTTPHeaders([
            ("Content-Type", "application/json"), ("Content-Length", String(body.count)), ("Connection", "close"),
        ])
        try await client.write(
            HTTPServerResponsePart.head(
                HTTPResponseHead(version: .http1_1, status: HTTPResponseStatus(statusCode: status), headers: headers)))
        try await client.write(HTTPServerResponsePart.body(.byteBuffer(ByteBuffer(bytes: body))))
        try await client.write(HTTPServerResponsePart.end(nil))
    }

    private func encode<T: Encodable>(_ value: T) throws -> Data {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = [.sortedKeys]
        return try encoder.encode(value)
    }

    private func json(_ value: [String: Any]) -> Data {
        (try? JSONSerialization.data(withJSONObject: value, options: [.sortedKeys])) ?? Data("{}".utf8)
    }
}
