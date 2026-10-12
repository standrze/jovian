import Foundation

/// Filterable message snapshots at the rule's position; forwarded headers and bodies remain untouched.
public struct MessageLoggerModifier: Modifier {
    public let headersOnly: Bool
    public let decode: Bool
    private let capture: BodyCapturePolicy
    private let sink: @Sendable (String) -> Void

    public init(
        headersOnly: Bool = false, decode: Bool = false,
        capture: BodyCapturePolicy = BodyCapturePolicy(),
        sink: @escaping @Sendable (String) -> Void = { print($0) }
    ) {
        self.headersOnly = headersOnly
        self.decode = decode
        self.capture = capture
        self.sink = sink
    }

    public func modify(request: inout RequestContext) {
        if request.body == nil && !headersOnly {
            if request.streamingLog == nil { request.streamingLog = StreamingMessageCapture() }
            let target = request.target
            let head = request.head
            request.streamingLog?.register(limit: capture.maximumBytes) { body, truncated, complete in
                log(
                    direction: "Request to", target: target, head: head, body: body,
                    truncated: truncated, complete: complete)
            }
        } else {
            log(direction: "Request to", target: request.target, head: request.head, body: request.body)
        }
    }

    public func modify(response: inout ResponseContext) {
        if response.body == nil && !headersOnly {
            if response.streamingLog == nil { response.streamingLog = StreamingMessageCapture() }
            let target = response.target
            let head = response.head
            response.streamingLog?.register(limit: capture.maximumBytes) { body, truncated, complete in
                log(
                    direction: "Response from", target: target, head: head, body: body,
                    truncated: truncated, complete: complete)
            }
        } else {
            log(direction: "Response from", target: response.target, head: response.head, body: response.body)
        }
    }

    private func log(
        direction: String, target: String, head: HTTPHead, body: Data?,
        truncated: Bool = false, complete: Bool = true
    ) {
        let headers = BodyCapturePolicy.headers(head.headers.map { LoggedHeader(name: $0.name, value: $0.value) })
        let divider = String(repeating: "-", count: 80)
        var output = "\n\(divider)\n\(direction) \(target)\n\(divider)\n\(head.startLine)\n"
        for header in headers { output += "\(header.name): \(header.value)\n" }
        if !headersOnly {
            output += "\n"
            if let body {
                do {
                    let decoded =
                        decode
                        ? try DiagnosticBodyDecoder.decode(
                            body, encoding: head["Content-Encoding"], limit: capture.maximumBytes) : body
                    let bodyHeaders = decode ? headers.filter { $0.name.lowercased() != "content-encoding" } : headers
                    let safe = capture.capture(decoded, headers: bodyHeaders, truncated: truncated || !complete)
                    if let data = safe.data {
                        output += String(data: data, encoding: .utf8) ?? "[base64] " + data.base64EncodedString()
                    }
                    if safe.truncated { output += "\n[body truncated]" }
                } catch { output += "[body unavailable: decoding failed or exceeded capture limit]" }
            } else {
                output += "[streaming body unavailable at modifier snapshot]"
            }
        }
        if !complete { output += "\n[stream interrupted]" }
        output += "\n\(divider)"
        sink(output)
    }
}
