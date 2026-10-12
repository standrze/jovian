import Foundation
import NIOCore
import NIOHTTP1
import NIOPosix

/// Shared Martian control routes used by the admin listener and reserved proxy hostname.
public final class ControlAPI: @unchecked Sendable {
    private let configuration: RuntimeConfiguration
    private let har: HARStore
    private let certificateAuthority: CertificateAuthority?
    private let allowCORS: Bool

    public init(
        configuration: RuntimeConfiguration, har: HARStore,
        certificateAuthority: CertificateAuthority? = nil, allowCORS: Bool = false
    ) {
        self.configuration = configuration
        self.har = har
        self.certificateAuthority = certificateAuthority
        self.allowCORS = allowCORS
    }

    func serve(head: HTTPRequestHead, client: ChannelConnection, workers: NIOThreadPool) async throws {
        let model = HTTPHead(head)
        do {
            let framing = try model.validatedFraming()
            guard !framing.chunked, (framing.length ?? 0) <= 1_048_576 else {
                throw ProxyError.invalidHTTP("control body requires Content-Length and at most 1 MiB")
            }
            if let expect = model["Expect"] {
                guard expect.lowercased() == "100-continue" else {
                    throw ProxyError.invalidHTTP("unsupported expectation")
                }
                try await client.write(
                    HTTPServerResponsePart.head(HTTPResponseHead(version: .http1_1, status: .continue)))
            }
            var body = Data()
            while true {
                guard let part = try await client.next() else {
                    throw ProxyError.invalidHTTP("control body ended early")
                }
                if case .end = part { break }
                guard case .body(let bytes) = part, body.count + bytes.readableBytes <= 1_048_576 else {
                    throw ProxyError.invalidHTTP("invalid control body")
                }
                body.append(contentsOf: bytes.readableBytesView)
            }
            let requestBody = body
            let result = try await workers.runIfActive {
                try self.respond(method: head.method.rawValue, target: head.uri, head: model, body: requestBody)
            }
            try await write(result, method: head.method.rawValue, client: client)
        } catch {
            try await write(
                response(status: 400, reason: "Bad Request", body: json(["error": String(describing: error)])),
                method: head.method.rawValue, client: client)
        }
    }

    public func respond(method: String, target: String, head: HTTPHead, body: Data = Data()) throws -> SyntheticResponse
    {
        guard body.count <= 1_048_576 else { throw ProxyError.invalidHTTP("control body exceeds 1 MiB") }
        let path = URLComponents(string: target)?.path ?? target
        let result =
            allowCORS && method == "OPTIONS" && head["Origin"]?.isEmpty == false
            ? response(body: Data()) : try route(method: method, path: path, body: body)
        var headers = result.headers
        if allowCORS, head["Origin"]?.isEmpty == false {
            headers += [
                ("Access-Control-Allow-Origin", "*"),
                ("Access-Control-Allow-Methods", head["Access-Control-Request-Method"] ?? ""),
            ]
            if let value = head["Access-Control-Request-Headers"] {
                headers.append(("Access-Control-Allow-Headers", value))
            }
        }
        return SyntheticResponse(
            statusCode: result.statusCode, reason: result.reason, headers: headers, body: result.body)
    }

    private func write(_ result: SyntheticResponse, method: String, client: ChannelConnection) async throws {
        var head = HTTPHead(startLine: "HTTP/1.1 \(result.statusCode) \(result.reason)", headers: result.headers)
        head["Content-Length"] = String(result.body.count)
        head["Connection"] = "close"
        try await client.write(HTTPServerResponsePart.head(try head.responseHead()))
        if method != "HEAD" {
            try await client.write(HTTPServerResponsePart.body(.byteBuffer(ByteBuffer(bytes: result.body))))
        }
        try await client.write(HTTPServerResponsePart.end(nil))
    }

    static func isReservedTarget(_ target: String, head: HTTPHead) -> Bool {
        if let url = URLComponents(string: target), let host = url.host {
            return host.caseInsensitiveCompare("martian.proxy") == .orderedSame
                && ["http", "https"].contains(url.scheme?.lowercased() ?? "") && url.user == nil && url.password == nil
        }
        return target.hasPrefix("/") && head["Host"]?.lowercased().split(separator: ":").first == "martian.proxy"
    }

    private func route(method: String, path: String, body: Data) throws -> SyntheticResponse {
        switch (method, path) {
        case ("GET", "/health"):
            return response(body: json(["status": "ok", "harEntries": har.count()]))
        case ("GET", "/configure"):
            return response(body: try configuration.encodedConfiguration())
        case ("POST", "/configure"):
            if MartianConfigurationParser.isCanonical(body) {
                try configuration.replace(martianJSON: body)
                return response(body: Data())
            }
            try configuration.replace(with: JSONDecoder().decode(RuntimeConfigurationDocument.self, from: body))
            return response(body: try configuration.encodedConfiguration())
        case ("POST", "/shape-traffic"):
            try configuration.trafficShaping.replace(json: body)
            return response(body: body)
        case ("GET", "/shape-traffic"):
            return response(body: configuration.trafficShaping.encodedConfiguration())
        case ("GET", "/logs"):
            return response(body: try har.encodedHAR())
        case ("DELETE", "/logs/reset"), ("POST", "/logs/reset"):
            har.reset()
            return response(body: json(["status": "reset"]))
        case ("GET", "/verify"):
            return response(body: try encode(["errors": configuration.verificationFailures()]))
        case ("POST", "/verify/reset"), ("DELETE", "/verify/reset"):
            configuration.resetVerificationFailures()
            return response(body: json(["status": "reset"]))
        case ("GET", "/authority.cer"):
            guard let certificateAuthority else {
                return response(status: 404, reason: "Not Found", body: json(["error": "interception CA unavailable"]))
            }
            return response(contentType: "application/x-x509-ca-cert", body: certificateAuthority.certificatePEM)
        default:
            return response(status: 404, reason: "Not Found", body: json(["error": "not found"]))
        }
    }

    private func response(
        status: Int = 200, reason: String = "OK", contentType: String = "application/json",
        body: Data
    ) -> SyntheticResponse {
        SyntheticResponse(statusCode: status, reason: reason, headers: [("Content-Type", contentType)], body: body)
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
