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
        var method = initialHead.method.rawValue
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
            let transportVia = request.head.values(for: "Via")
            do { try modifier.modify(request: &request) } catch {
                if failOnModifierError { throw error }
                addModifierWarning(error, to: &request.head)
            }
            let configurationModifiers = request.configurationModifiers
            let streamingLog = request.streamingLog
            if let interceptor {
                switch interceptor.intercept(request) {
                case .forward(let forwarded): request = forwarded
                case .drop(let response): request.syntheticResponse = response
                }
            }
            request.configurationModifiers = configurationModifiers
            request.streamingLog = streamingLog
            try session?.validate(method: request.method, target: request.target)
            // A rule cannot remove the instance identity used to detect chained loops.
            request.head.replaceValues(for: "Via", with: transportVia)
            ensureVia(&request.head)
            return request
        }
        var responseCapture: StreamingMessageCapture?
        var partialWriter: PayloadWriter?
        var partialHead: HTTPHead?
        var partialRequestBody: Data?
        var requestComplete = false
        var responseComplete = false
        defer {
            request.streamingLog?.finish(complete: requestComplete)
            responseCapture?.finish(complete: responseComplete)
        }
        do {
            method = request.method
            request.head.removeHopByHopHeaders(preservingUpgrade: requestedUpgrade)
            request.head["Connection"] = requestedUpgrade ? "Upgrade" : "keep-alive"
            let requestTrailers = request.body == collected.body ? collected.trailers : nil
            normalizeBodyHeaders(
                &request.head, body: request.body, streamingChunked: original["Transfer-Encoding"] != nil,
                trailers: requestTrailers)
            let rates = trafficRates()
            var download = TransferPacer(bytesPerSecond: rates.download)
            if request.skipRoundTrip && request.syntheticResponse == nil {
                request.syntheticResponse = SyntheticResponse(statusCode: 200, reason: "OK")
            }
            if let synthetic = request.syntheticResponse {
                return try await syntheticResponse(
                    synthetic, request: request, client: client,
                    keepAlive: initialHead.isKeepAlive && collected.complete && !requestedUpgrade, started: started,
                    pacer: &download)
            }
            let destination = try destination(
                target: request.target, hostHeader: request.head["Host"], defaultScheme: defaultScheme)
            let originalDestination = try self.destination(
                target: initialHead.uri, hostHeader: original["Host"], defaultScheme: defaultScheme)
            if originalDestination.host.lowercased() != destination.host.lowercased()
                || originalDestination.port != destination.port || originalDestination.usesTLS != destination.usesTLS
            {
                for name in ["Authorization", "Cookie"]
                where request.head.values(for: name) == original.values(for: name) { request.head.remove(name) }
            }
            if request.head["Host"]?.isEmpty != false {
                request.head["Host"] = try RoutingTarget(request.target).authority
            }
            let upstream = try await upstreamPool.acquire(
                host: destination.host, port: destination.port, usesTLS: destination.usesTLS, deadline: deadline)
            var reused = false
            defer { if !reused { upstream.close() } }
            var wireHead = try request.head.requestHead(
                method: method,
                uri: downstreamProxy?.usesHTTPForwarding == true && !destination.usesTLS
                    ? request.target : originForm(request.target),
                version: initialHead.version)
            if let downstreamProxy, downstreamProxy.usesHTTPForwarding, !destination.usesTLS,
                let authorization = downstreamProxy.authorization
            {
                wireHead.headers.replaceOrAdd(name: "Proxy-Authorization", value: authorization)
            }
            try await upstream.write(HTTPClientRequestPart.head(wireHead))
            var capturedRequest = Data()
            func retainRequest(_ data: Data) {
                if capturedRequest.count < maximumBufferedBodyBytes {
                    capturedRequest.append(data.prefix(maximumBufferedBodyBytes - capturedRequest.count))
                }
            }
            let uploadWriter = try PayloadWriter(
                connection: upstream, upload: true, controller: runtimeConfiguration?.trafficShaping,
                target: request.target, head: request.head, rate: rates.upload, capture: request.streamingLog,
                latencyConnection: client)
            if let body = request.body {
                retainRequest(body)
                try await uploadWriter.write(body)
                // Replaced unread uploads are closed after this response rather than blocking on a drain.
                try await upstream.write(HTTPClientRequestPart.end(requestTrailers))
            } else {
                retainRequest(collected.prefix)
                try await uploadWriter.write(collected.prefix)
                while true {
                    guard let event = try await client.next() else {
                        throw ProxyError.invalidHTTP("request body ended early")
                    }
                    switch event {
                    case .body(let bytes):
                        let data = Data(bytes.readableBytesView)
                        retainRequest(data)
                        try await uploadWriter.write(data)
                    case .end(let trailers): try await upstream.write(HTTPClientRequestPart.end(trailers))
                    default: throw ProxyError.invalidHTTP("unexpected request part")
                    }
                    if case .end = event { break }
                }
            }
            partialRequestBody = capturedRequest
            requestComplete = true
            request.streamingLog?.finish(complete: true)
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
                    remoteAddress: client.channel.remoteAddress?.ipAddress, requestHead: request.head)
                var response = try await modifyResponse(context, request: request)
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
            let upstreamHasNoBody =
                method == "HEAD" || head.status.code == 204 || head.status.code == 205 || head.status.code == 304
            let responseBody = try await collectBody(
                from: upstream,
                expectedLength: upstreamHasNoBody ? 0 : Int(head.headers.first(name: "Content-Length") ?? ""),
                forceStreaming: !upstreamHasNoBody && head.headers.contains(name: "Transfer-Encoding"))
            let context = ResponseContext(
                requestMethod: method, target: request.target, head: HTTPHead(head), body: responseBody.body,
                remoteAddress: client.channel.remoteAddress?.ipAddress, requestHead: request.head)
            var response = try await modifyResponse(context, request: request)
            responseCapture = response.streamingLog
            response.head.removeHopByHopHeaders()
            let status = try response.head.responseHead().status.code
            guard (200...599).contains(status) else {
                throw ResponseModifierFailure(
                    underlying: ProxyError.invalidHTTP("modifier must produce a final response status"))
            }
            let noBody = method == "HEAD" || status == 204 || status == 205 || status == 304
            let responseTrailers = response.body == responseBody.body ? responseBody.trailers : nil
            let chunked = initialHead.version != .http1_0
            let keepAlive =
                initialHead.isKeepAlive && (collected.complete || request.body == nil) && !requestedUpgrade
                && !transport.isClosing
                && (noBody || response.body != nil || response.bodyStream != nil || chunked
                    || response.head["Content-Length"] != nil)
            response.head["Connection"] = keepAlive ? "keep-alive" : "close"
            if noBody {
                response.head.remove("Transfer-Encoding")
                if status == 204 { response.head.remove("Content-Length") }
                if status == 205 { response.head["Content-Length"] = "0" }
                response.body = Data()
            } else {
                if let stream = response.bodyStream {
                    response.head.remove("Transfer-Encoding")
                    response.head.remove("Trailer")
                    response.head["Content-Length"] = String(stream.length)
                } else {
                    normalizeBodyHeaders(
                        &response.head, body: response.body, streamingChunked: chunked,
                        trailers: chunked ? responseTrailers : nil)
                }
                if !chunked { response.head.remove("Transfer-Encoding") }
            }
            let outgoing = try response.head.responseHead(version: initialHead.version)
            try await client.write(HTTPServerResponsePart.head(outgoing))
            var captured = Data()
            let downloadWriter = try PayloadWriter(
                connection: client, controller: runtimeConfiguration?.trafficShaping,
                target: request.target, head: response.head, rate: rates.download, capture: response.streamingLog)
            partialWriter = downloadWriter
            partialHead = response.head
            func retain(_ bytes: Data) {
                if captured.count < maximumBufferedBodyBytes {
                    captured.append(bytes.prefix(maximumBufferedBodyBytes - captured.count))
                }
            }
            var consumed = responseBody.complete
            if let stream = response.bodyStream, !noBody {
                while let chunk = try await transport.workers.runIfActive({ try stream.read(maximum: 32_768) }) {
                    retain(chunk)
                    try await downloadWriter.write(chunk)
                }
                try await client.write(HTTPServerResponsePart.end(nil))
            } else if let body = response.body {
                if !noBody {
                    retain(body)
                    try await downloadWriter.write(body)
                }
                try await client.write(HTTPServerResponsePart.end(noBody || !chunked ? nil : responseTrailers))
            } else {
                retain(responseBody.prefix)
                try await downloadWriter.write(responseBody.prefix)
                while true {
                    guard let event = try await upstream.next() else {
                        throw ProxyError.invalidHTTP("response body ended early")
                    }
                    switch event {
                    case .body(let bytes):
                        let data = Data(bytes.readableBytesView)
                        retain(data)
                        try await downloadWriter.write(data)
                    case .end(let trailers):
                        consumed = true
                        try await client.write(HTTPServerResponsePart.end(chunked ? trailers : nil))
                    default: throw ProxyError.invalidHTTP("unexpected response part")
                    }
                    if case .end = event { break }
                }
            }
            responseComplete = true
            response.streamingLog?.finish(complete: true)
            let byteCount = downloadWriter.bytesSent
            await record(
                method: method, target: request.target, status: Int(outgoing.status.code), bytes: byteCount,
                start: started,
                transport: "http",
                requestHeaders: redacted(request.head.headers), responseHeaders: redacted(response.head.headers),
                requestBody: capturedRequest,
                responseBody: captured, requestBodyTruncated: uploadWriter.bytesSent > capturedRequest.count,
                responseBodyTruncated: byteCount > captured.count)
            deadline.finish()
            if head.isKeepAlive && consumed {
                await upstreamPool.release(
                    upstream, host: destination.host, port: destination.port, usesTLS: destination.usesTLS)
                reused = true
            }
            return keepAlive
        } catch {
            if case TrafficShapingError.recordedClose = error { throw error }
            if case TrafficShapingError.forcedClose = error, let writer = partialWriter, let head = partialHead {
                await record(
                    method: request.method, target: request.target, status: Int(try head.responseHead().status.code),
                    bytes: writer.bytesSent, start: started, transport: "http", error: "traffic shaping forced close",
                    requestHeaders: redacted(request.head.headers), responseHeaders: redacted(head.headers),
                    requestBody: partialRequestBody, responseBodyTruncated: true)
                throw TrafficShapingError.recordedClose
            }
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

    func modifyResponse(_ initial: ResponseContext, request: RequestContext? = nil) async throws -> ResponseContext {
        try await transport.workers.runIfActive { [self] in
            var response = initial
            if let request { response.configurationModifiers = request.configurationModifiers }
            do { try modifier.modify(response: &response) } catch {
                if failOnModifierError { throw ResponseModifierFailure(underlying: error) }
                addModifierWarning(error, to: &response.head)
            }
            ensureVia(&response.head)
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
        error: String? = nil, transportName: String = "synthetic", applyModifiers: Bool = true
    ) async throws -> Bool {
        let initial = ResponseContext(
            requestMethod: request.method, target: request.target,
            head: HTTPHead(
                startLine: "HTTP/1.1 \(synthetic.statusCode) \(synthetic.reason)", headers: synthetic.headers),
            body: synthetic.body,
            remoteAddress: client.channel.remoteAddress?.ipAddress, requestHead: request.head)
        var response = applyModifiers ? try await modifyResponse(initial, request: request) : initial
        let body = response.body ?? Data()
        response.head.removeHopByHopHeaders()
        normalizeBodyHeaders(&response.head, body: body, streamingChunked: false)
        if let stream = response.bodyStream { response.head["Content-Length"] = String(stream.length) }
        response.head["Connection"] = keepAlive ? "keep-alive" : "close"
        let status = try response.head.responseHead().status.code
        guard (200...599).contains(status) else {
            throw ResponseModifierFailure(
                underlying: ProxyError.invalidHTTP("modifier must produce a final response status"))
        }
        let noBody = request.method == "HEAD" || status == 204 || status == 205 || status == 304
        if noBody {
            response.head.remove("Transfer-Encoding")
            if status == 204 { response.head.remove("Content-Length") }
            if status == 205 { response.head["Content-Length"] = "0" }
        }
        let head = try response.head.responseHead()
        try await client.write(HTTPServerResponsePart.head(head))
        let writer = try PayloadWriter(
            connection: client, controller: runtimeConfiguration?.trafficShaping,
            target: request.target, head: response.head, rate: trafficRates().download, capture: response.streamingLog)
        var captured = Data()
        defer { response.streamingLog?.finish(complete: false) }
        do {
            if !noBody {
                if let stream = response.bodyStream {
                    while let chunk = try await transport.workers.runIfActive({ try stream.read(maximum: 32_768) }) {
                        if captured.count < maximumBufferedBodyBytes {
                            captured.append(chunk.prefix(maximumBufferedBodyBytes - captured.count))
                        }
                        try await writer.write(chunk)
                    }
                } else {
                    captured = Data(body.prefix(maximumBufferedBodyBytes))
                    try await writer.write(body)
                }
            }
            try await client.write(HTTPServerResponsePart.end(nil))
            response.streamingLog?.finish(complete: true)
        } catch TrafficShapingError.forcedClose {
            await record(
                method: request.method, target: request.target, status: Int(head.status.code),
                bytes: writer.bytesSent, start: started, transport: transportName,
                error: "traffic shaping forced close",
                requestHeaders: redacted(request.head.headers), responseHeaders: redacted(response.head.headers),
                requestBody: request.body, responseBody: Data(captured.prefix(writer.bytesSent)),
                requestBodyTruncated: request.body == nil, responseBodyTruncated: true)
            throw TrafficShapingError.recordedClose
        }
        await record(
            method: request.method, target: request.target, status: Int(head.status.code),
            bytes: writer.bytesSent,
            start: started, transport: transportName, error: error, requestHeaders: redacted(request.head.headers),
            responseHeaders: redacted(response.head.headers),
            requestBody: request.body, responseBody: captured,
            requestBodyTruncated: request.body == nil,
            responseBodyTruncated: writer.bytesSent > captured.count)
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

struct ResponseModifierFailure: Error, CustomStringConvertible {
    let underlying: Error
    var description: String { String(describing: underlying) }
}
