import Foundation
import NIOCore
import NIOHTTP1
import NIOSSL

extension ProxyServer {
    func tunnel(
        client: ChannelConnection, initialHead: HTTPRequestHead, started: ContinuousClock.Instant,
        deadline: RequestDeadline
    ) async throws {
        guard case .end? = try await client.next() else { throw ProxyError.invalidHTTP("CONNECT must not have a body") }
        let initial = RequestContext(
            method: "CONNECT", target: initialHead.uri, head: HTTPHead(initialHead),
            remoteAddress: client.channel.remoteAddress?.ipAddress)
        let request = try await transport.workers.runIfActive { [self] in
            var request = initial
            request.head.removeHopByHopHeaders()
            addForwardingHeaders(to: &request, version: initialHead.version)
            do { try modifier.modify(request: &request) } catch {
                addModifierWarning(error, to: &request.head)
            }
            if let interceptor {
                switch interceptor.intercept(request) {
                case .forward(let forwarded): request = forwarded
                case .drop(let response): request.syntheticResponse = response
                }
            }
            request.head.removeHopByHopHeaders()
            return request
        }
        if let synthetic = request.syntheticResponse {
            var pacer = TransferPacer(bytesPerSecond: trafficRates().download)
            _ = try await syntheticResponse(
                synthetic, request: request, client: client, keepAlive: false, started: started, pacer: &pacer)
            return
        }
        let destination = try authority(request.target, defaultPort: 443)
        var upstream: ChannelConnection?
        var responseHead = HTTPResponseHead(
            version: .http1_1, status: .custom(code: 200, reasonPhrase: "Connection Established"))
        var responseBody = Data()
        do {
            if certificateAuthority == nil {
                if let proxy = downstreamProxy {
                    let connection = try await upstreamPool.connect(
                        host: proxy.host, port: proxy.port, role: .client,
                        usesTLS: proxy.usesTLS, deadline: deadline)
                    upstream = connection
                    responseHead = try await upstreamPool.establishTunnel(
                        connection, host: destination.host, port: destination.port,
                        headers: HTTPHeaders(request.head.headers))
                    if !(200..<300).contains(responseHead.status.code) {
                        while let event = try await connection.next() {
                            if case .end = event { break }
                            guard case .body(let bytes) = event,
                                responseBody.count + bytes.readableBytes <= maximumBufferedBodyBytes
                            else { throw ProxyError.invalidHTTP("downstream CONNECT error body exceeds buffer limit") }
                            responseBody.append(contentsOf: bytes.readableBytesView)
                        }
                    }
                } else {
                    upstream = try await upstreamPool.connect(
                        host: destination.host, port: destination.port, role: .raw, deadline: deadline)
                }
            }
        } catch {
            upstream?.close()
            upstream = nil
            responseHead.status = .badGateway
            responseBody = Data("upstream connection failed".utf8)
        }
        defer { upstream?.close() }
        let context = ResponseContext(
            requestMethod: "CONNECT", target: request.target, head: HTTPHead(responseHead), body: responseBody,
            remoteAddress: client.channel.remoteAddress?.ipAddress)
        var response = try await modifyResponse(context)
        response.head.removeHopByHopHeaders()
        let status = try response.head.responseHead().status.code
        let established = (200..<300).contains(status) && (200..<300).contains(responseHead.status.code)
        response.head.remove("Transfer-Encoding")
        if established {
            response.head.remove("Content-Length")
        } else {
            // A modifier cannot turn a failed dial into a working tunnel.
            if (200..<300).contains(status) { response.head.startLine = "HTTP/1.1 502 Bad Gateway" }
            response.head["Content-Length"] = String(response.body?.count ?? 0)
            response.head["Connection"] = "close"
        }
        let outgoing = try response.head.responseHead(version: initialHead.version)
        try await client.write(HTTPServerResponsePart.head(outgoing))
        if !established, let body = response.body, !body.isEmpty {
            try await client.write(HTTPServerResponsePart.body(.byteBuffer(ByteBuffer(bytes: body))))
        }
        try await client.write(HTTPServerResponsePart.end(nil))
        guard established else {
            await record(
                method: "CONNECT", target: request.target, status: Int(outgoing.status.code),
                bytes: response.body?.count ?? 0, start: started, transport: "tls-tunnel",
                requestHeaders: redacted(request.head.headers), responseHeaders: redacted(response.head.headers))
            return
        }
        try await client.becomeRaw()
        if let certificateAuthority {
            guard case .bytes(let first)? = try await client.next(), let firstByte = first.readableBytesView.first
            else {
                return
            }
            let usesTLS = firstByte == 22
            let context =
                usesTLS
                ? try await transport.workers.runIfActive {
                    try certificateAuthority.listenerContext(defaultHostname: destination.host)
                }
                : nil
            try await client.becomeHTTP(
                role: .server, tls: context.map { .server($0) }, replaying: [first])
            deadline.finish()
            transport.endRequest(client.channel)
            await handle(client, scheme: usesTLS ? "https" : "http", authenticatedTunnel: true)
            return
        }
        guard let upstream else { throw ProxyError.connection("missing tunnel connection") }
        let downloaded = try await relay(client: client, upstream: upstream, rates: trafficRates())
        await record(
            method: "CONNECT", target: request.target, status: Int(outgoing.status.code), bytes: downloaded,
            start: started, transport: "tls-tunnel", requestHeaders: redacted(request.head.headers),
            responseHeaders: redacted(response.head.headers))
    }

    /// Half-close each direction independently.
    ///
    /// A clean client EOF must not discard its response.
    func relay(client: ChannelConnection, upstream: ChannelConnection, rates: (upload: Int?, download: Int?))
        async throws -> Int
    {
        try await withThrowingTaskGroup(of: Int.self) { group in
            group.addTask {
                _ = try await Self.pipe(from: client, to: upstream, rate: rates.upload)
                return 0
            }
            group.addTask { try await Self.pipe(from: upstream, to: client, rate: rates.download) }
            do {
                var downloaded = 0
                for try await count in group { downloaded += count }
                return downloaded
            } catch {
                client.close()
                upstream.close()
                group.cancelAll()
                throw error
            }
        }
    }

    private static func pipe(from source: ChannelConnection, to destination: ChannelConnection, rate: Int?) async throws
        -> Int
    {
        var pacer = TransferPacer(bytesPerSecond: rate)
        var total = 0
        while let event = try await source.next() {
            guard case .bytes(let bytes) = event else {
                throw ProxyError.invalidHTTP("unexpected HTTP part after upgrade")
            }
            try await pacer.pace(bytes.readableBytes)
            try await destination.write(bytes)
            total += bytes.readableBytes
        }
        await destination.finishOutput()
        return total
    }
}
