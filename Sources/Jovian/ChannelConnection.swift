import DequeModule
import Foundation
import NIOCore
import NIOHTTP1
import NIOPosix

/// Transport events after NIO has decoded HTTP framing.
///
/// Raw bytes occur only after an upgrade.
enum ConnectionEvent: Sendable {
    case request(HTTPRequestHead)
    case response(HTTPResponseHead)
    case body(ByteBuffer)
    case end(HTTPHeaders?)
    case bytes(ByteBuffer)
}

/// One consumer owns each connection.
///
/// The inbox and pipeline mutate only on its event loop.
final class ChannelConnection: @unchecked Sendable {
    let channel: Channel
    private let inbox: ConnectionInbox
    private var usesHTTP: Bool
    private let upgradeEOF = UpgradeEOFGuard()
    private var hasConnectMethodAdapter = false
    private let activation: EventLoopPromise<Void>
    private(set) var finalResponseStarted = false

    init(channel: Channel, role: Role, tls: TLSConnectionMode? = nil) throws {
        self.channel = channel
        usesHTTP = role != .raw
        activation = channel.eventLoop.makePromise(of: Void.self)
        inbox = ConnectionInbox(activation: activation, readOnActivation: tls != nil)
        let pipeline = channel.pipeline.syncOperations
        do {
            if let tls { try pipeline.addHandler(tls.makeHandler()) }
            try pipeline.addHandler(inbox)
            if role == .raw {
                try pipeline.addHandler(RawAdapter(), name: "raw-adapter", position: .before(inbox))
            } else {
                try installHTTP(role: role)
            }
        } catch {
            inbox.failActivation(error)
            throw error
        }
    }

    private func installHTTP(role: Role) throws {
        let pipeline = channel.pipeline.syncOperations
        var limits = NIOHTTPDecoderLimitConfiguration()
        limits.maxHeaderFieldSize = 65_536
        limits.maxHeaderListSize = 65_536
        switch role {
        case .server:
            var configuration = HTTPResponseEncoder.Configuration()
            // Jovian explicitly chooses framing, including bodyless HEAD/CONNECT responses.
            configuration.automaticallySetFramingHeaders = false
            try pipeline.addHandler(
                HTTPResponseEncoder(configuration: configuration), name: "http-encoder", position: .before(inbox))
            try pipeline.addHandler(upgradeEOF, name: "upgrade-eof", position: .before(inbox))
            try pipeline.addHandler(
                ByteToMessageHandler(
                    HTTPRequestDecoder(leftOverBytesStrategy: .forwardBytes, limitConfiguration: limits)),
                name: "http-decoder", position: .before(inbox))
            try pipeline.addHandler(
                RequestAdapter(upgradeEOF: upgradeEOF), name: "http-adapter", position: .before(inbox))
        case .client:
            hasConnectMethodAdapter = true
            try pipeline.addHandler(HTTPRequestEncoder(), name: "http-encoder", position: .before(inbox))
            try pipeline.addHandler(
                ConnectMethodAdapter(upgradeEOF: upgradeEOF), name: "connect-method", position: .before(inbox))
            try pipeline.addHandler(upgradeEOF, name: "upgrade-eof", position: .before(inbox))
            try pipeline.addHandler(
                ByteToMessageHandler(
                    HTTPResponseDecoder(
                        leftOverBytesStrategy: .forwardBytes, informationalResponseStrategy: .forward,
                        limitConfiguration: limits)), name: "http-decoder", position: .before(inbox))
            try pipeline.addHandler(
                ResponseAdapter(upgradeEOF: upgradeEOF), name: "http-adapter", position: .before(inbox))
        case .raw:
            preconditionFailure("raw connections do not have HTTP codecs")
        }
    }

    enum Role: Sendable { case server, client, raw }

    func waitUntilActive() async throws { try await activation.futureResult.get() }

    func resetResponse() { finalResponseStarted = false }

    func next() async throws -> ConnectionEvent? {
        try await channel.eventLoop.flatSubmit { self.inbox.next(channel: self.channel) }.get()
    }

    func write(_ part: HTTPClientRequestPart) async throws {
        try await channel.eventLoop.flatSubmit {
            var part = part
            if case .head(var head) = part, head.method == .CONNECT {
                self.upgradeEOF.connectRequest = true
                // NIO treats every typed CONNECT response as bodyless, including rejection responses.
                // The decoder observes GET; ConnectMethodAdapter restores CONNECT before wire encoding.
                // Successful CONNECT is terminated explicitly by ResponseAdapter at the header boundary.
                head.method = .GET
                part = .head(head)
            }
            return self.channel.writeAndFlush(part)
        }.get()
    }

    func write(_ part: HTTPServerResponsePart) async throws {
        if case .head(let head) = part, head.status.code >= 200 || head.status.code == 101 {
            finalResponseStarted = true
        }
        try await channel.writeAndFlush(part).get()
    }

    func write(_ bytes: ByteBuffer) async throws {
        try await channel.writeAndFlush(bytes).get()
    }

    /// Remove the NIO HTTP codecs only after the handshake write has completed.
    ///
    /// Decoder leftovers
    /// flow through RawAdapter, retaining bytes coalesced with CONNECT or a 101 response.
    func becomeRaw() async throws {
        let isHTTP = try await channel.eventLoop.submit { self.usesHTTP }.get()
        guard isHTTP else { return }
        try await channel.pipeline.removeHandler(name: "http-adapter").get()
        try await channel.eventLoop.submit {
            try self.channel.pipeline.syncOperations.addHandler(
                RawAdapter(), name: "raw-adapter", position: .before(self.inbox))
        }.get()
        try await channel.pipeline.removeHandler(name: "http-decoder").get()
        if hasConnectMethodAdapter {
            try await channel.pipeline.removeHandler(name: "connect-method").get()
            hasConnectMethodAdapter = false
        }
        try await channel.pipeline.removeHandler(name: "http-encoder").get()
        try await channel.eventLoop.submit {
            self.upgradeEOF.completeUpgrade()
            self.usesHTTP = false
        }.get()
        try await channel.pipeline.removeHandler(name: "upgrade-eof").get()
    }

    /// Replaces raw framing with HTTP, optionally inserting TLS before the new codecs.
    ///
    /// Bytes already consumed for protocol detection are replayed before the inbox's queued raw bytes.
    /// The replay enters after existing TLS layers, preserving CONNECT data and half-close ordering.
    func becomeHTTP(role: Role, tls: TLSConnectionMode? = nil, replaying: [ByteBuffer] = []) async throws {
        precondition(role != .raw)
        try await channel.eventLoop.flatSubmit { () -> EventLoopFuture<Void> in
            guard !self.usesHTTP else {
                return self.channel.eventLoop.makeFailedFuture(ProxyError.invalidHTTP("connection already uses HTTP"))
            }
            return self.channel.pipeline.removeHandler(name: "raw-adapter").flatMapThrowing {
                let buffered = try self.inbox.takeRawEvents()
                let input = ProtocolInput()
                let pipeline = self.channel.pipeline.syncOperations
                try pipeline.addHandler(input, name: "protocol-input", position: .before(self.inbox))
                if let tls { try pipeline.addHandler(tls.makeHandler(), position: .before(self.inbox)) }
                try self.installHTTP(role: role)
                self.usesHTTP = true
                input.replay(replaying + buffered.bytes, inputClosed: buffered.inputClosed)
            }.flatMap {
                self.channel.pipeline.removeHandler(name: "protocol-input")
            }
        }.get()
    }

    func finishOutput() async { try? await channel.close(mode: .output).get() }
    func close() { channel.close(promise: nil) }
}

/// Manual reads put a finite socket read between batches.
///
/// NIO's receive allocator caps each read;
/// the inbox also rejects excessive pipelining from a single read instead of retaining it forever.
private final class ConnectionInbox: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = ConnectionEvent
    private var pending: EventLoopPromise<ConnectionEvent?>?
    private var events = Deque<ConnectionEvent>()
    private var ended = false
    private var failure: Error?
    private var reading = false
    private var activation: EventLoopPromise<Void>?
    private let readOnActivation: Bool

    init(activation: EventLoopPromise<Void>, readOnActivation: Bool) {
        self.activation = activation
        self.readOnActivation = readOnActivation
    }

    func failActivation(_ error: Error) {
        activation?.fail(error)
        activation = nil
    }

    func handlerRemoved(context: ChannelHandlerContext) { finish() }

    func takeRawEvents() throws -> (bytes: [ByteBuffer], inputClosed: Bool) {
        precondition(pending == nil, "cannot change protocols while a read is pending")
        if let failure { throw failure }
        var bytes: [ByteBuffer] = []
        while let event = events.popFirst() {
            guard case .bytes(let buffer) = event else {
                throw ProxyError.invalidHTTP("unexpected HTTP part during protocol change")
            }
            bytes.append(buffer)
        }
        let inputClosed = ended
        ended = false
        reading = false
        return (bytes, inputClosed)
    }

    func channelActive(context: ChannelHandlerContext) {
        activation?.succeed(())
        activation = nil
        context.fireChannelActive()
        // A TLS write waits for the handshake, which needs a first read even before the HTTP consumer asks.
        // NIOSSL continues empty handshake reads while autoRead is disabled.
        if readOnActivation {
            reading = true
            context.read()
        }
    }

    func next(channel: Channel) -> EventLoopFuture<ConnectionEvent?> {
        channel.eventLoop.preconditionInEventLoop()
        if let event = events.popFirst() { return channel.eventLoop.makeSucceededFuture(event) }
        if let failure { return channel.eventLoop.makeFailedFuture(failure) }
        if ended { return channel.eventLoop.makeSucceededFuture(nil) }
        precondition(pending == nil, "connections have one reader")
        let promise = channel.eventLoop.makePromise(of: ConnectionEvent?.self)
        pending = promise
        if !reading {
            reading = true
            channel.read()
        }
        return promise.futureResult
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        let event = unwrapInboundIn(data)
        if let pending {
            self.pending = nil
            pending.succeed(event)
        } else if events.count < 256 {
            events.append(event)
        } else {
            errorCaught(context: context, error: ProxyError.invalidHTTP("too many pipelined HTTP parts"))
        }
    }

    func channelReadComplete(context: ChannelHandlerContext) {
        reading = false
        if pending != nil {
            reading = true
            context.read()
        }
    }

    func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
        if let event = event as? ChannelEvent, event == .inputClosed { finish() }
        context.fireUserInboundEventTriggered(event)
    }

    func channelInactive(context: ChannelHandlerContext) {
        finish()
        context.fireChannelInactive()
    }

    func errorCaught(context: ChannelHandlerContext, error: Error) {
        failure = error
        pending?.fail(error)
        pending = nil
        context.close(promise: nil)
    }

    private func finish() {
        activation?.fail(ProxyError.connection("connection closed before activation"))
        activation = nil
        ended = true
        pending?.succeed(nil)
        pending = nil
    }
}

/// Separates NIO's response-body decision from the method encoded on the wire.
private final class ConnectMethodAdapter: ChannelOutboundHandler, RemovableChannelHandler {
    typealias OutboundIn = HTTPClientRequestPart
    typealias OutboundOut = HTTPClientRequestPart
    private let upgradeEOF: UpgradeEOFGuard

    init(upgradeEOF: UpgradeEOFGuard) { self.upgradeEOF = upgradeEOF }

    func write(context: ChannelHandlerContext, data: NIOAny, promise: EventLoopPromise<Void>?) {
        var part = unwrapOutboundIn(data)
        if upgradeEOF.connectRequest, case .head(var head) = part {
            head.method = .CONNECT
            part = .head(head)
        }
        context.write(wrapOutboundOut(part), promise: promise)
    }
}

private final class RequestAdapter: ChannelInboundHandler, RemovableChannelHandler {
    typealias InboundIn = HTTPServerRequestPart
    private let upgradeEOF: UpgradeEOFGuard
    init(upgradeEOF: UpgradeEOFGuard) { self.upgradeEOF = upgradeEOF }
    typealias InboundOut = ConnectionEvent
    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        let event: ConnectionEvent
        switch unwrapInboundIn(data) {
        case .head(let head):
            if head.method == .CONNECT
                || (head.headers.first(name: "Upgrade") != nil
                    && head.headers[canonicalForm: "connection"].contains(where: { $0.lowercased() == "upgrade" }))
            {
                upgradeEOF.upgradePending = true
            }
            event = .request(head)
        case .body(let body): event = .body(body)
        case .end(let trailers): event = .end(trailers)
        }
        context.fireChannelRead(wrapInboundOut(event))
    }
}

private final class ResponseAdapter: ChannelInboundHandler, RemovableChannelHandler {
    typealias InboundIn = HTTPClientResponsePart
    private let upgradeEOF: UpgradeEOFGuard
    init(upgradeEOF: UpgradeEOFGuard) { self.upgradeEOF = upgradeEOF }
    typealias InboundOut = ConnectionEvent
    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        let event: ConnectionEvent
        switch unwrapInboundIn(data) {
        case .head(let head):
            upgradeEOF.receivedResponse(head)
            if upgradeEOF.connectRequest, (200...299).contains(head.status.code) {
                context.fireChannelRead(wrapInboundOut(.response(head)))
                context.fireChannelRead(wrapInboundOut(.end(nil)))
                return
            }
            event = .response(head)
        case .body(let body):
            event = .body(body)
        case .end(let trailers):
            if upgradeEOF.connectRequest, upgradeEOF.upgradePending { return }
            event = .end(trailers)
        }
        context.fireChannelRead(wrapInboundOut(event))
    }
}

private final class RawAdapter: ChannelInboundHandler, RemovableChannelHandler {
    typealias InboundIn = ByteBuffer
    typealias InboundOut = ConnectionEvent
    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        context.fireChannelRead(wrapInboundOut(.bytes(unwrapInboundIn(data))))
    }
}

/// NIO deliberately discards undecoded upgrade bytes on EOF.
///
/// Hold the half-close event until
/// removing its decoder has forwarded those bytes, then deliver EOF in the original order.
private final class UpgradeEOFGuard: ChannelInboundHandler, RemovableChannelHandler, @unchecked Sendable {
    typealias InboundIn = ByteBuffer
    var upgradePending = false
    var connectRequest = false
    private var connectResponseReceived = false
    private var connectHeaders: ByteBuffer?
    private var connectHeaderScanOffset = 0
    private var tunnelBytes: ByteBuffer?
    private var deferredEOF = false
    private var context: ChannelHandlerContext?

    func handlerAdded(context: ChannelHandlerContext) { self.context = context }
    func handlerRemoved(context: ChannelHandlerContext) { self.context = nil }

    func receivedResponse(_ head: HTTPResponseHead) {
        if connectRequest, head.status.code >= 200 { connectResponseReceived = true }
        if head.status.code == 101 || (connectRequest && (200...299).contains(head.status.code)) {
            upgradePending = true
        }
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        guard connectRequest else {
            context.fireChannelRead(data)
            return
        }
        var bytes = unwrapInboundIn(data)
        if upgradePending {
            bufferTunnelBytes(&bytes, context: context)
            return
        }
        guard !connectResponseReceived else {
            context.fireChannelRead(data)
            return
        }
        if connectHeaders == nil { connectHeaders = context.channel.allocator.buffer(capacity: bytes.readableBytes) }
        connectHeaders?.writeBuffer(&bytes)
        while var headers = connectHeaders {
            let view = headers.readableBytesView
            guard
                let boundary = view.indices.dropFirst(connectHeaderScanOffset).first(where: { index in
                    index + 3 < view.endIndex && view[index] == 13 && view[index + 1] == 10
                        && view[index + 2] == 13 && view[index + 3] == 10
                })
            else {
                if headers.readableBytes > 65_536 {
                    context.fireErrorCaught(ProxyError.invalidHTTP("downstream CONNECT headers exceed limit"))
                    context.close(promise: nil)
                }
                connectHeaderScanOffset = max(0, headers.readableBytes - 3)
                return
            }
            let length = boundary + 4 - headers.readerIndex
            guard length <= 65_536, let head = headers.readSlice(length: length) else {
                context.fireErrorCaught(ProxyError.invalidHTTP("downstream CONNECT headers exceed limit"))
                context.close(promise: nil)
                return
            }
            connectHeaders = nil
            connectHeaderScanOffset = 0
            // NIO validates each complete head. Keeping its raw suffix outside the decoder prevents a
            // successful CONNECT's tunnel bytes from being interpreted as a subsequent HTTP response.
            context.fireChannelRead(NIOAny(head))
            if upgradePending {
                bufferTunnelBytes(&headers, context: context)
            } else if connectResponseReceived {
                if headers.readableBytes > 0 { context.fireChannelRead(NIOAny(headers)) }
            } else if headers.readableBytes > 0 {
                connectHeaders = headers
            }
        }
    }

    private func bufferTunnelBytes(_ bytes: inout ByteBuffer, context: ChannelHandlerContext) {
        guard bytes.readableBytes > 0 else { return }
        guard (tunnelBytes?.readableBytes ?? 0) + bytes.readableBytes <= 1_048_576 else {
            context.fireErrorCaught(ProxyError.invalidHTTP("downstream CONNECT early data exceeds limit"))
            context.close(promise: nil)
            return
        }
        if tunnelBytes == nil { tunnelBytes = context.channel.allocator.buffer(capacity: bytes.readableBytes) }
        tunnelBytes?.writeBuffer(&bytes)
    }

    func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
        if upgradePending, let channelEvent = event as? ChannelEvent, channelEvent == .inputClosed {
            deferredEOF = true
        } else {
            context.fireUserInboundEventTriggered(event)
        }
    }

    func completeUpgrade() {
        upgradePending = false
        connectRequest = false
        connectResponseReceived = false
        connectHeaders = nil
        connectHeaderScanOffset = 0
        if let bytes = tunnelBytes {
            tunnelBytes = nil
            context?.fireChannelRead(NIOAny(bytes))
        }
        if deferredEOF {
            deferredEOF = false
            context?.fireUserInboundEventTriggered(ChannelEvent.inputClosed)
        }
    }
}

/// A temporary replay boundary after preexisting TLS layers and before newly installed protocol handlers.
private final class ProtocolInput: ChannelInboundHandler, RemovableChannelHandler {
    typealias InboundIn = ByteBuffer
    private var context: ChannelHandlerContext?

    func handlerAdded(context: ChannelHandlerContext) { self.context = context }
    func handlerRemoved(context: ChannelHandlerContext) { self.context = nil }

    func replay(_ buffers: [ByteBuffer], inputClosed: Bool) {
        guard let context else { return }
        for buffer in buffers { context.fireChannelRead(NIOAny(buffer)) }
        context.fireChannelReadComplete()
        if inputClosed { context.fireUserInboundEventTriggered(ChannelEvent.inputClosed) }
    }
}
