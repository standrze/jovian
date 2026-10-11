import Foundation
import NIOCore
import NIOPosix

/// Owns NIO resources and the synchronous application boundary.
///
/// The lock protects lifecycle state, accepted channels, handlers and active exchanges.
/// NIO owns channel operations. Shutdown keeps workers and event loops alive until
/// every accepted handler has returned. Never wait from an event loop.
final class ServerTransport: @unchecked Sendable {
    let group = MultiThreadedEventLoopGroup(numberOfThreads: 2)
    let workers = NIOThreadPool(numberOfThreads: 4)
    private let lock = NSLock()
    private var listener: Channel?
    private var channels: [ObjectIdentifier: Channel] = [:]
    private var tasks: [ObjectIdentifier: Task<Void, Never>] = [:]
    private var activeRequests: Set<ObjectIdentifier> = []
    private var startupCompletion: EventLoopPromise<Void>?
    private var shutdownTask: Task<Void, Never>?
    private var forceShutdown: (@Sendable () -> Void)?
    private var stopped = false
    private var starting = false

    init() { workers.start() }

    func start(
        host: String, port: UInt16,
        configure: @escaping @Sendable (Channel) throws -> Void = { _ in },
        handle: @escaping @Sendable (ChannelConnection) async -> Void
    ) throws
        -> UInt16
    {
        let startup = try lock.withLock {
            guard !stopped, listener == nil, !starting else {
                throw ProxyError.connection("server already started or stopped")
            }
            starting = true
            let completion = group.next().makePromise(of: Void.self)
            startupCompletion = completion
            return completion
        }
        defer {
            lock.withLock { starting = false }
            startup.succeed(())
        }
        let bound = try ServerBootstrap(group: group)
            .serverChannelOption(ChannelOptions.socketOption(.so_reuseaddr), value: 1)
            .childChannelOption(ChannelOptions.autoRead, value: false)
            .childChannelOption(ChannelOptions.allowRemoteHalfClosure, value: true)
            .childChannelOption(
                ChannelOptions.recvAllocator, value: FixedSizeRecvByteBufferAllocator(capacity: 16_384)
            )
            .childChannelOption(ChannelOptions.maxMessagesPerRead, value: 1)
            .childChannelInitializer { channel in
                channel.eventLoop.makeCompletedFuture {
                    try configure(channel)
                    let connection = try ChannelConnection(channel: channel, role: .server)
                    let accepted = self.lock.withLock {
                        guard !self.stopped else { return false }
                        self.channels[ObjectIdentifier(channel)] = channel
                        return true
                    }
                    guard accepted else {
                        channel.close(promise: nil)
                        return
                    }
                    channel.closeFuture.whenComplete { _ in
                        self.lock.withLock {
                            self.channels.removeValue(forKey: ObjectIdentifier(channel))
                            self.activeRequests.remove(ObjectIdentifier(channel))
                        }
                    }
                    let identity = ObjectIdentifier(channel)
                    let registered = self.lock.withLock {
                        guard !self.stopped else { return false }
                        // Registration and stop's task snapshot share the lock. Activation cannot
                        // arrive until this initializer returns, so the task cannot finish first.
                        self.tasks[identity] = Task {
                            defer { self.lock.withLock { _ = self.tasks.removeValue(forKey: identity) } }
                            do {
                                try await connection.waitUntilActive()
                                await handle(connection)
                            } catch { connection.close() }
                        }
                        return true
                    }
                    if !registered { channel.close(promise: nil) }
                }
            }
            .bind(host: host, port: Int(port)).wait()
        let accepted = lock.withLock {
            guard !stopped else { return false }
            listener = bound
            return true
        }
        guard accepted, let actualPort = bound.localAddress?.port else {
            try? bound.close().wait()
            throw ProxyError.connection("server stopped while binding")
        }
        return UInt16(actualPort)
    }

    func wait() throws {
        guard let channel = lock.withLock({ listener }) else { return }
        try channel.closeFuture.wait()
    }

    func stop(closingConnections: @escaping @Sendable () async -> Void = {}) {
        _ = beginShutdown(gracePeriod: nil, onGracePeriodExpired: {}, closingConnections: closingConnections)
    }

    /// Reserve a parsed request before invoking application code or connecting upstream.
    ///
    /// Once draining starts no additional requests, including pipelined ones, are admitted.
    func beginRequest(_ channel: Channel) -> Bool {
        lock.withLock {
            let identity = ObjectIdentifier(channel)
            guard !stopped, channels[identity] != nil else { return false }
            activeRequests.insert(identity)
            return true
        }
    }

    /// Release the request reservation and close a draining connection after its response.
    func endRequest(_ channel: Channel) {
        let shouldClose = lock.withLock {
            activeRequests.remove(ObjectIdentifier(channel))
            return stopped
        }
        if shouldClose { channel.close(promise: nil) }
    }

    var isClosing: Bool { lock.withLock { stopped } }

    /// Cancel suspended pacing work as well as pending channel reads for a deadline.
    func cancelConnectionTask(_ channel: Channel) {
        let task = lock.withLock { tasks[ObjectIdentifier(channel)] }
        task?.cancel()
        channel.close(promise: nil)
    }

    /// Close immediately, or allow current requests the supplied grace period to finish.
    ///
    /// Idle connections close immediately. A later `stop()` can force an existing drain.
    /// `onGracePeriodExpired` runs when a deadline or explicit stop forces the drain;
    /// it must unblock any application callback that waits synchronously.
    /// The grace period bounds network draining, not arbitrary application callbacks.
    func shutdown(
        gracePeriod: Duration? = nil,
        onGracePeriodExpired: @escaping @Sendable () -> Void = {},
        closingConnections: @escaping @Sendable () async -> Void = {}
    ) async {
        await beginShutdown(
            gracePeriod: gracePeriod, onGracePeriodExpired: onGracePeriodExpired,
            closingConnections: closingConnections
        ).value
    }

    private func beginShutdown(
        gracePeriod: Duration?,
        onGracePeriodExpired: @escaping @Sendable () -> Void,
        closingConnections: @escaping @Sendable () async -> Void
    ) -> Task<Void, Never> {
        let result = lock.withLock { () -> (Task<Void, Never>, (@Sendable () -> Void)?) in
            if let shutdownTask { return (shutdownTask, gracePeriod == nil ? forceShutdown : nil) }
            stopped = true
            let listeningChannel = listener
            listener = nil
            let runningTasks = Array(tasks.values)
            let idleChannels = channels.filter { !activeRequests.contains($0.key) }.map(\.value)
            let idleTasks = tasks.filter { !activeRequests.contains($0.key) }.map(\.value)
            let resources = ShutdownResources(
                channels: Array(channels.values), tasks: runningTasks,
                onForced: onGracePeriodExpired, cleanup: closingConnections)
            let force: @Sendable () -> Void = { resources.forceClose() }
            forceShutdown = force
            let startup = startupCompletion?.futureResult
            let group = group
            let workers = workers
            let task = Task {
                listeningChannel?.close(promise: nil)
                for task in idleTasks { task.cancel() }
                for channel in idleChannels { channel.close(promise: nil) }
                let timer: Task<Void, Never>?
                if let gracePeriod {
                    timer = Task {
                        do { try await ContinuousClock().sleep(for: max(.zero, gracePeriod)) } catch { return }
                        resources.forceClose()
                        await resources.cleanup.run()
                    }
                } else {
                    timer = nil
                    resources.forceClose()
                    await resources.cleanup.run()
                }
                for task in runningTasks { await task.value }
                timer?.cancel()
                await timer?.value
                for channel in resources.channels { channel.close(promise: nil) }
                for channel in resources.channels { try? await channel.closeFuture.get() }
                if let listeningChannel { try? await listeningChannel.closeFuture.get() }
                await resources.cleanup.run()
                if let startup { try? await startup.get() }
                resources.finish()
                try? await workers.shutdownGracefully()
                try? await group.shutdownGracefully()
            }
            shutdownTask = task
            return (task, nil)
        }
        result.1?()
        return result.0
    }

    deinit { stop() }
}

/// An immutable shutdown snapshot allows force-close to run without holding the transport lock.
private final class ShutdownResources: @unchecked Sendable {
    let channels: [Channel]
    let cleanup: ShutdownCleanup
    private let tasks: [Task<Void, Never>]
    private let onForced: @Sendable () -> Void
    private let lock = NSLock()
    private var forced = false
    private var finished = false

    init(
        channels: [Channel], tasks: [Task<Void, Never>], onForced: @escaping @Sendable () -> Void,
        cleanup: @escaping @Sendable () async -> Void
    ) {
        self.channels = channels
        self.tasks = tasks
        self.onForced = onForced
        self.cleanup = ShutdownCleanup(operation: cleanup)
    }

    func forceClose() {
        let shouldForce = lock.withLock {
            guard !forced, !finished else { return false }
            forced = true
            return true
        }
        guard shouldForce else { return }
        onForced()
        for task in tasks { task.cancel() }
        for channel in channels { channel.close(promise: nil) }
        Task { await cleanup.run() }
    }

    func finish() { lock.withLock { finished = true } }
}

/// Shares upstream teardown between deadline, explicit stop, and normal drain completion.
private actor ShutdownCleanup {
    private let operation: @Sendable () async -> Void
    private var task: Task<Void, Never>?

    init(operation: @escaping @Sendable () async -> Void) { self.operation = operation }

    func run() async {
        if let task {
            await task.value
            return
        }
        let task = Task { await operation() }
        self.task = task
        await task.value
    }
}
