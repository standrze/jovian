import Foundation
import NIOCore
import NIOHTTP1

/// Body collection stops at the configured modifier limit plus a single NIO receive buffer.
private struct BufferedBody {
    var prefix = Data()
    var complete = false
    var trailers: HTTPHeaders?
    var body: Data? { complete ? prefix : nil }
}

extension ProxyServer {
    func exchange(
        client: ChannelConnection, initialHead: HTTPRequestHead, started: ContinuousClock.Instant,
        deadline: RequestDeadline, defaultScheme: String = "http"
    )
        async throws -> Bool
    {
        let original = HTTPHead(initialHead)
        let method = initialHead.method.rawValue
        let requestedUpgrade = original.connectionTokens().contains("upgrade") && original["Upgrade"] != nil
        let collected = try await collectBody(from: client, expectedLength: Int(original["Content-Length"] ?? ""))
        let initial = RequestContext(
            method: method, target: initialHead.uri, head: original, body: collected.body,
            remoteAddress: client.channel.remoteAddress?.ipAddress)
        var request = try await transport.workers.runIfActive { [self] in
            var request = initial
            request.head.removeHopByHopHeaders(preservingUpgrade: requestedUpgrade)
            request.head.remove("Expect")
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
            return request
        }
        do {
            request.head.removeHopByHopHeaders(preservingUpgrade: requestedUpgrade)
            request.head["Connection"] = requestedUpgrade ? "Upgrade" : "keep-alive"
            let requestTrailers = request.body == collected.body ? collected.trailers : nil
            normalizeBodyHeaders(
                &request.head, body: request.body, streamingChunked: original["Transfer-Encoding"] != nil,
                trailers: requestTrailers)
            let rates = trafficRates()
            var upload = TransferPacer(bytesPerSecond: rates.upload)
            var download = TransferPacer(bytesPerSecond: rates.download)
            if let synthetic = request.syntheticResponse {
                return try await syntheticResponse(
                    synthetic, request: request, client: client,
                    keepAlive: initialHead.isKeepAlive && collected.complete && !requestedUpgrade, started: started,
                    pacer: &download)
            }
            let destination = try destination(
                target: request.target, hostHeader: request.head["Host"], defaultScheme: defaultScheme)
            let upstream = try await upstreamPool.acquire(
                host: destination.host, port: destination.port, usesTLS: destination.usesTLS, deadline: deadline)
            var reused = false
            defer { if !reused { upstream.close() } }
            var wireHead = try request.head.requestHead(
                method: method,
                uri: downstreamProxy != nil && !destination.usesTLS ? request.target : originForm(request.target),
                version: initialHead.version)
            if let downstreamProxy, !destination.usesTLS, let authorization = downstreamProxy.authorization {
                wireHead.headers.replaceOrAdd(name: "Proxy-Authorization", value: authorization)
            }
            try await upstream.write(HTTPClientRequestPart.head(wireHead))
            if let body = request.body {
                try await upload.pace(body.count)
                try await upstream.write(HTTPClientRequestPart.body(.byteBuffer(ByteBuffer(bytes: body))))
                if !collected.complete { try await drainBody(from: client) }
                try await upstream.write(HTTPClientRequestPart.end(requestTrailers))
            } else {
                if !collected.prefix.isEmpty {
                    try await upload.pace(collected.prefix.count)
                    try await upstream.write(
                        HTTPClientRequestPart.body(.byteBuffer(ByteBuffer(bytes: collected.prefix))))
                }
                while true {
                    guard let event = try await client.next() else {
                        throw ProxyError.invalidHTTP("request body ended early")
                    }
                    switch event {
                    case .body(let bytes):
                        try await upload.pace(bytes.readableBytes)
                        try await upstream.write(HTTPClientRequestPart.body(.byteBuffer(bytes)))
                    case .end(let trailers):
                        try await upstream.write(HTTPClientRequestPart.end(trailers))
                    default: throw ProxyError.invalidHTTP("unexpected request part")
                    }
                    if case .end = event { break }
                }
            }
            let head = try await finalResponseHead(from: upstream, to: client)
            if head.status.code == 101 {
                guard requestedUpgrade,
                    head.headers.first(name: "Upgrade")?.caseInsensitiveCompare(request.head["Upgrade"] ?? "")
                        == .orderedSame
                else {
                    throw ProxyError.invalidHTTP("unexpected or mismatched upgrade")
                }
                guard case .end? = try await upstream.next() else {
                    throw ProxyError.invalidHTTP("invalid upgrade response")
                }
                let context = ResponseContext(
                    requestMethod: method, target: request.target, head: HTTPHead(head), body: nil,
                    remoteAddress: client.channel.remoteAddress?.ipAddress)
                var response = try await modifyResponse(context)
                response.head.removeHopByHopHeaders(preservingUpgrade: true)
                response.head["Connection"] = "Upgrade"
                let outgoing = try response.head.responseHead(version: initialHead.version)
                try await client.write(HTTPServerResponsePart.head(outgoing))
                try await client.write(HTTPServerResponsePart.end(nil))
                guard outgoing.status.code == 101 else { return false }
                try await client.becomeRaw()
                try await upstream.becomeRaw()
                let bytes = try await relay(client: client, upstream: upstream, rates: rates)
                await record(
                    method: method, target: request.target, status: 101, bytes: bytes, start: started,
                    transport: "http-upgrade",
                    requestHeaders: redacted(request.head.headers), responseHeaders: redacted(response.head.headers),
                    requestBody: request.body)
                return false
            }
            let upstreamHasNoBody = method == "HEAD" || head.status.code == 204 || head.status.code == 304
            let responseBody = try await collectBody(
                from: upstream,
                expectedLength: upstreamHasNoBody ? 0 : Int(head.headers.first(name: "Content-Length") ?? ""),
                forceStreaming: !upstreamHasNoBody && head.headers.contains(name: "Transfer-Encoding"))
            let context = ResponseContext(
                requestMethod: method, target: request.target, head: HTTPHead(head), body: responseBody.body,
                remoteAddress: client.channel.remoteAddress?.ipAddress)
            var response = try await modifyResponse(context)
            response.head.removeHopByHopHeaders()
            let status = try response.head.responseHead().status.code
            let noBody = method == "HEAD" || status == 204 || status == 304
            let responseTrailers = response.body == responseBody.body ? responseBody.trailers : nil
            let chunked = initialHead.version != .http1_0
            let keepAlive =
                initialHead.isKeepAlive && !requestedUpgrade && !transport.isClosing
                && (noBody || response.body != nil || chunked || response.head["Content-Length"] != nil)
            response.head["Connection"] = keepAlive ? "keep-alive" : "close"
            if noBody {
                response.head.remove("Transfer-Encoding")
                if status == 204 { response.head.remove("Content-Length") }
                response.body = Data()
            } else {
                normalizeBodyHeaders(
                    &response.head, body: response.body, streamingChunked: chunked,
                    trailers: chunked ? responseTrailers : nil)
                if !chunked { response.head.remove("Transfer-Encoding") }
            }
            let outgoing = try response.head.responseHead(version: initialHead.version)
            try await client.write(HTTPServerResponsePart.head(outgoing))
            var captured = Data()
            var byteCount = 0
            if let body = response.body {
                if !noBody {
                    captured = Data(body.prefix(maximumBufferedBodyBytes))
                    byteCount = body.count
                    try await download.pace(body.count)
                    try await client.write(HTTPServerResponsePart.body(.byteBuffer(ByteBuffer(bytes: body))))
                }
                if !responseBody.complete { try await drainBody(from: upstream) }
                try await client.write(HTTPServerResponsePart.end(noBody || !chunked ? nil : responseTrailers))
            } else {
                captured = Data(responseBody.prefix.prefix(maximumBufferedBodyBytes))
                byteCount = responseBody.prefix.count
                if !responseBody.prefix.isEmpty {
                    try await download.pace(responseBody.prefix.count)
                    try await client.write(
                        HTTPServerResponsePart.body(.byteBuffer(ByteBuffer(bytes: responseBody.prefix))))
                }
                while true {
                    guard let event = try await upstream.next() else {
                        throw ProxyError.invalidHTTP("response body ended early")
                    }
                    switch event {
                    case .body(let bytes):
                        byteCount += bytes.readableBytes
                        if captured.count < maximumBufferedBodyBytes {
                            captured.append(
                                contentsOf: bytes.readableBytesView.prefix(maximumBufferedBodyBytes - captured.count))
                        }
                        try await download.pace(bytes.readableBytes)
                        try await client.write(HTTPServerResponsePart.body(.byteBuffer(bytes)))
                    case .end(let trailers):
                        try await client.write(HTTPServerResponsePart.end(chunked ? trailers : nil))
                    default: throw ProxyError.invalidHTTP("unexpected response part")
                    }
                    if case .end = event { break }
                }
            }
            await record(
                method: method, target: request.target, status: Int(outgoing.status.code), bytes: byteCount,
                start: started,
                transport: "http",
                requestHeaders: redacted(request.head.headers), responseHeaders: redacted(response.head.headers),
                requestBody: request.body,
                responseBody: captured, requestBodyTruncated: request.body == nil,
                responseBodyTruncated: byteCount > captured.count)
            deadline.finish()
            if head.isKeepAlive {
                await upstreamPool.release(
                    upstream, host: destination.host, port: destination.port, usesTLS: destination.usesTLS)
                reused = true
            }
            return keepAlive
        } catch {
            throw ProxyExchangeFailure(underlying: error, request: request)
        }
    }

    private func collectBody(from connection: ChannelConnection, expectedLength: Int?, forceStreaming: Bool = false)
        async throws -> BufferedBody
    {
        var body = BufferedBody()
        if forceStreaming { return body }
        if let expectedLength, expectedLength > maximumBufferedBodyBytes { return body }
        while let event = try await connection.next() {
            switch event {
            case .body(let bytes):
                body.prefix.append(contentsOf: bytes.readableBytesView)
                if body.prefix.count > maximumBufferedBodyBytes { return body }
            case .end(let trailers):
                body.complete = true
                body.trailers = trailers
                return body
            default: throw ProxyError.invalidHTTP("expected message body")
            }
        }
        throw ProxyError.invalidHTTP("message ended before body boundary")
    }

    private func drainBody(from connection: ChannelConnection) async throws {
        while let event = try await connection.next() {
            if case .end = event { return }
            guard case .body = event else { throw ProxyError.invalidHTTP("unexpected message body") }
        }
        throw ProxyError.invalidHTTP("message body ended early")
    }

    private func finalResponseHead(from upstream: ChannelConnection, to client: ChannelConnection) async throws
        -> HTTPResponseHead
    {
        while let event = try await upstream.next() {
            guard case .response(let head) = event else { throw ProxyError.invalidHTTP("expected upstream response") }
            if head.status.code >= 200 || head.status.code == 101 { return head }
            var informational = HTTPHead(head)
            informational.removeHopByHopHeaders()
            try await client.write(HTTPServerResponsePart.head(try informational.responseHead()))
        }
        throw ProxyError.invalidHTTP("upstream closed before a final response")
    }

    func modifyResponse(_ initial: ResponseContext) async throws -> ResponseContext {
        try await transport.workers.runIfActive { [self] in
            var response = initial
            do { try modifier.modify(response: &response) } catch {
                addModifierWarning(error, to: &response.head)
            }
            response.head.add(name: "Via", value: "1.1 \(viaIdentity)")
            return response
        }
    }

    private func normalizeBodyHeaders(
        _ head: inout HTTPHead, body: Data?, streamingChunked: Bool, trailers: HTTPHeaders? = nil
    ) {
        if let trailers, !trailers.isEmpty {
            head.remove("Content-Length")
            head["Transfer-Encoding"] = "chunked"
        } else if let body {
            head.remove("Transfer-Encoding")
            head.remove("Trailer")
            head["Content-Length"] = String(body.count)
        } else if streamingChunked {
            head.remove("Content-Length")
            head["Transfer-Encoding"] = "chunked"
        }
    }

    func syntheticResponse(
        _ synthetic: SyntheticResponse, request: RequestContext, client: ChannelConnection,
        keepAlive: Bool, started: ContinuousClock.Instant, pacer: inout TransferPacer,
        error: String? = nil, transportName: String = "synthetic"
    ) async throws -> Bool {
        let initial = ResponseContext(
            requestMethod: request.method, target: request.target,
            head: HTTPHead(
                startLine: "HTTP/1.1 \(synthetic.statusCode) \(synthetic.reason)", headers: synthetic.headers),
            body: synthetic.body,
            remoteAddress: client.channel.remoteAddress?.ipAddress)
        var response = try await modifyResponse(initial)
        let body = response.body ?? Data()
        response.head.removeHopByHopHeaders()
        normalizeBodyHeaders(&response.head, body: body, streamingChunked: false)
        response.head["Connection"] = keepAlive ? "keep-alive" : "close"
        let status = try response.head.responseHead().status.code
        let noBody = request.method == "HEAD" || status == 204 || status == 304
        if noBody {
            response.head.remove("Transfer-Encoding")
            if status == 204 { response.head.remove("Content-Length") }
        }
        let head = try response.head.responseHead()
        try await client.write(HTTPServerResponsePart.head(head))
        if !noBody {
            try await pacer.pace(body.count)
            try await client.write(HTTPServerResponsePart.body(.byteBuffer(ByteBuffer(bytes: body))))
        }
        try await client.write(HTTPServerResponsePart.end(nil))
        await record(
            method: request.method, target: request.target, status: Int(head.status.code),
            bytes: noBody ? 0 : body.count,
            start: started, transport: transportName, error: error, requestHeaders: redacted(request.head.headers),
            responseHeaders: redacted(response.head.headers),
            requestBody: request.body, responseBody: noBody ? Data() : Data(body.prefix(maximumBufferedBodyBytes)),
            requestBodyTruncated: request.body == nil,
            responseBodyTruncated: !noBody && body.count > maximumBufferedBodyBytes)
        return keepAlive
    }

    func destination(target: String, hostHeader: String?, defaultScheme: String = "http") throws
        -> (host: String, port: Int, usesTLS: Bool)
    {
        if let components = URLComponents(string: target), let scheme = components.scheme?.lowercased() {
            let usesTLS = scheme == "https"
            let port = components.port ?? (usesTLS ? 443 : 80)
            guard ["http", "https"].contains(scheme), let host = components.host,
                components.user == nil, components.password == nil, (1...65535).contains(port)
            else { throw ProxyError.unsupported("expected an HTTP or HTTPS URL without user information") }
            return (host.trimmingCharacters(in: CharacterSet(charactersIn: "[]")), port, usesTLS)
        }
        guard let hostHeader else { throw ProxyError.invalidHTTP("missing Host header") }
        let usesTLS = defaultScheme == "https"
        let destination = try authority(hostHeader, defaultPort: usesTLS ? 443 : 80)
        return (destination.host, destination.port, usesTLS)
    }

    func authority(_ value: String, defaultPort: Int) throws -> (host: String, port: Int) {
        guard let components = URLComponents(string: "http://\(value)"), let host = components.host, !host.isEmpty,
            components.user == nil, components.password == nil, components.path.isEmpty,
            components.query == nil, components.fragment == nil, (1...65535).contains(components.port ?? defaultPort)
        else {
            throw ProxyError.invalidHTTP("invalid authority")
        }
        return (host.trimmingCharacters(in: CharacterSet(charactersIn: "[]")), components.port ?? defaultPort)
    }

    private func originForm(_ target: String) -> String {
        guard let components = URLComponents(string: target), components.scheme != nil else { return target }
        let path = components.percentEncodedPath.isEmpty ? "/" : components.percentEncodedPath
        return path + (components.percentEncodedQuery.map { "?" + $0 } ?? "")
    }
}

/// Carries the post-modifier request through failures so response hooks and traffic records see the same exchange.
struct ProxyExchangeFailure: Error {
    let underlying: Error
    let request: RequestContext
}
