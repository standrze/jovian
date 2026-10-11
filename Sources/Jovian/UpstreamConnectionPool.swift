import Foundation
import NIOCore
import NIOHTTP1
import NIOPosix
import NIOSSL

/// Leases one HTTP/1.1 channel to one exchange at a time. Only fully consumed responses return here.
actor UpstreamConnectionPool {
    private struct IdleConnection {
        let connection: ChannelConnection
        let deadline: ContinuousClock.Instant
    }

    private let group: EventLoopGroup
    private let downstreamProxy: DownstreamProxy?
    private let tlsConfiguration: ProxyTLSConfiguration?
    private let connectTimeout: TimeInterval
    private var defaultTLSContext: NIOSSLContext?
    private let maximumPerOrigin: Int
    private let idleTimeout: Duration
    private var idle: [String: [IdleConnection]] = [:]
    private var expiryTasks: [ObjectIdentifier: Task<Void, Never>] = [:]
    private var stopped = false
    private var allConnections: [ObjectIdentifier: ChannelConnection] = [:]

    init(
        group: EventLoopGroup, downstreamProxy: DownstreamProxy? = nil,
        tlsConfiguration: ProxyTLSConfiguration? = nil, connectTimeout: TimeInterval = 30,
        maximumPerOrigin: Int = 4, idleTimeout: Duration = .seconds(30)
    ) {
        self.downstreamProxy = downstreamProxy
        self.tlsConfiguration = tlsConfiguration
        self.connectTimeout = connectTimeout.isFinite ? max(0.001, connectTimeout) : 30
        self.group = group
        self.maximumPerOrigin = max(0, maximumPerOrigin)
        self.idleTimeout = idleTimeout
    }

    func acquire(host: String, port: Int, usesTLS: Bool = false, deadline: RequestDeadline? = nil)
        async throws -> ChannelConnection
    {
        guard !stopped else { throw ProxyError.connection("proxy has stopped") }
        let key = "\(usesTLS ? "https" : "http")://\(host.lowercased()):\(port)"
        while let candidate = idle[key]?.popLast() {
            expiryTasks.removeValue(forKey: ObjectIdentifier(candidate.connection.channel))?.cancel()
            if idle[key]?.isEmpty == true { idle.removeValue(forKey: key) }
            if candidate.deadline > .now && candidate.connection.channel.isActive {
                deadline?.add(candidate.connection.channel)
                return candidate.connection
            }
            candidate.connection.close()
        }
        if let proxy = downstreamProxy {
            let connection = try await connect(
                host: proxy.host, port: proxy.port, role: .client, usesTLS: proxy.usesTLS, deadline: deadline)
            if usesTLS {
                do {
                    let response = try await establishTunnel(connection, host: host, port: port)
                    guard (200..<300).contains(response.status.code) else {
                        throw ProxyError.connection("downstream CONNECT returned \(response.status.code)")
                    }
                    try await connection.becomeHTTP(
                        role: .client, tls: .client(try upstreamTLSContext(), serverHostname: host))
                } catch {
                    connection.close()
                    throw error
                }
            }
            return connection
        }
        return try await connect(host: host, port: port, role: .client, usesTLS: usesTLS, deadline: deadline)
    }

    func connect(
        host: String, port: Int, role: ChannelConnection.Role, usesTLS: Bool = false,
        deadline: RequestDeadline? = nil
    ) async throws -> ChannelConnection {
        guard !stopped else { throw ProxyError.connection("proxy has stopped") }
        try Task.checkCancellation()
        let tls: TLSConnectionMode? = usesTLS ? .client(try upstreamTLSContext(), serverHostname: host) : nil
        let connection = try await ClientBootstrap(group: group)
            .channelOption(ChannelOptions.autoRead, value: false)
            .channelOption(ChannelOptions.allowRemoteHalfClosure, value: true)
            .channelOption(ChannelOptions.recvAllocator, value: FixedSizeRecvByteBufferAllocator(capacity: 16_384))
            .channelOption(ChannelOptions.maxMessagesPerRead, value: 1)
            .connectTimeout(.milliseconds(Int64(min(max(connectTimeout, 0.001), 31_536_000) * 1_000)))
            .connect(host: host, port: port) { channel in
                channel.eventLoop.makeCompletedFuture {
                    deadline?.add(channel)
                    return try ChannelConnection(channel: channel, role: role, tls: tls)
                }.flatMap { connection in
                    channel.eventLoop.makeFutureWithTask {
                        try await self.register(connection)
                        return connection
                    }
                }
            }
        deadline?.add(connection.channel)
        if stopped {
            connection.close()
            try? await connection.channel.closeFuture.get()
            throw ProxyError.connection("proxy has stopped")
        }
        return connection
    }

    /// Register before the bootstrap starts dialing so shutdown also owns connecting channels.
    private func register(_ connection: ChannelConnection) throws {
        guard !stopped else {
            connection.close()
            throw ProxyError.connection("proxy has stopped")
        }
        let identity = ObjectIdentifier(connection.channel)
        allConnections[identity] = connection
        connection.channel.closeFuture.whenComplete { _ in Task { await self.removeConnection(identity) } }
    }

    private func upstreamTLSContext() throws -> NIOSSLContext {
        if let tlsConfiguration { return tlsConfiguration.upstreamContext }
        if let defaultTLSContext { return defaultTLSContext }
        let context = try ProxyTLSConfiguration().upstreamContext
        defaultTLSContext = context
        return context
    }

    /// A successful CONNECT switches the proxy connection to opaque bytes, retaining any early payload.
    func establishTunnel(
        _ connection: ChannelConnection, host: String, port: Int, headers: HTTPHeaders = HTTPHeaders()
    ) async throws -> HTTPResponseHead {
        let authority = host.contains(":") ? "[\(host)]:\(port)" : "\(host):\(port)"
        var headers = headers
        headers.replaceOrAdd(name: "Host", value: authority)
        headers.remove(name: "Content-Length")
        headers.remove(name: "Transfer-Encoding")
        if let authorization = downstreamProxy?.authorization {
            headers.replaceOrAdd(name: "Proxy-Authorization", value: authorization)
        }
        try await connection.write(
            HTTPClientRequestPart.head(
                HTTPRequestHead(version: .http1_1, method: .CONNECT, uri: authority, headers: headers)))
        try await connection.write(HTTPClientRequestPart.end(nil))
        while let event = try await connection.next() {
            guard case .response(let head) = event else {
                throw ProxyError.invalidHTTP("expected downstream CONNECT response")
            }
            if head.status.code < 200 { continue }
            if (200..<300).contains(head.status.code) {
                guard case .end? = try await connection.next() else {
                    throw ProxyError.invalidHTTP("invalid downstream CONNECT response")
                }
                try await connection.becomeRaw()
            }
            return head
        }
        throw ProxyError.connection("downstream proxy closed before CONNECT response")
    }

    private func removeConnection(_ identity: ObjectIdentifier) {
        expiryTasks.removeValue(forKey: identity)?.cancel()
        allConnections.removeValue(forKey: identity)
    }

    func release(_ connection: ChannelConnection, host: String, port: Int, usesTLS: Bool = false) {
        guard !stopped, connection.channel.isActive, maximumPerOrigin > 0 else {
            connection.close()
            return
        }
        let key = "\(usesTLS ? "https" : "http")://\(host.lowercased()):\(port)"
        var connections = idle[key] ?? []
        if connections.count >= maximumPerOrigin {
            let removed = connections.removeFirst().connection
            expiryTasks.removeValue(forKey: ObjectIdentifier(removed.channel))?.cancel()
            removed.close()
        }
        let deadline = ContinuousClock.now.advanced(by: idleTimeout)
        connections.append(IdleConnection(connection: connection, deadline: deadline))
        idle[key] = connections
        let identity = ObjectIdentifier(connection.channel)
        expiryTasks.removeValue(forKey: identity)?.cancel()
        expiryTasks[identity] = Task { [weak self] in
            do { try await ContinuousClock().sleep(until: deadline) } catch { return }
            await self?.expire(identity: identity, key: key, deadline: deadline)
        }
    }

    private func expire(identity: ObjectIdentifier, key: String, deadline: ContinuousClock.Instant) {
        guard
            let index = idle[key]?.firstIndex(where: {
                ObjectIdentifier($0.connection.channel) == identity && $0.deadline == deadline
            })
        else { return }
        expiryTasks.removeValue(forKey: identity)
        idle[key]?.remove(at: index).connection.close()
        if idle[key]?.isEmpty == true { idle.removeValue(forKey: key) }
    }

    func closeAll() async {
        stopped = true
        let connections = Array(allConnections.values)
        let timers = Array(expiryTasks.values)
        for timer in timers { timer.cancel() }
        expiryTasks.removeAll()
        for connection in connections { connection.close() }
        allConnections.removeAll()
        idle.removeAll()
        for timer in timers { await timer.value }
        for connection in connections { try? await connection.channel.closeFuture.get() }
    }
}
