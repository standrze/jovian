import Foundation

/// Parser for Martian's canonical one-key `package.Type` JSON envelope.
///
/// Support is intentionally explicit: unknown types fail instead of silently
/// degrading to Jovian semantics.
enum MartianConfigurationParser {
    static func isCanonical(_ data: Data) -> Bool {
        guard let object = try? JSONSerialization.jsonObject(with: data),
            let message = object as? [String: Any], message.count == 1,
            let name = message.keys.first
        else { return false }
        return name.contains(".")
    }

    static func parse(
        _ data: Data, verifications: VerificationStore = VerificationStore(),
        logSink: @escaping @Sendable (String) -> Void = { print($0) },
        logCapture: BodyCapturePolicy = BodyCapturePolicy()
    ) throws -> any Modifier {
        try parseNode(
            JSONSerialization.jsonObject(with: data), verifications: verifications, logSink: logSink,
            logCapture: logCapture)
    }

    private static func parseNode(
        _ object: Any, verifications: VerificationStore,
        logSink: @escaping @Sendable (String) -> Void, logCapture: BodyCapturePolicy
    ) throws -> any Modifier {
        guard let message = object as? [String: Any], message.count == 1,
            let type = message.keys.first,
            let payload = message[type] as? [String: Any]
        else {
            throw ProxyError.invalidHTTP("Martian configuration must contain exactly one package.Type object")
        }

        switch type {
        case "fifo.Group":
            guard let children = payload["modifiers"] as? [Any] else {
                throw ProxyError.invalidHTTP("fifo.Group requires modifiers")
            }
            let group = try ModifierGroup(
                children.map {
                    try parseNode($0, verifications: verifications, logSink: logSink, logCapture: logCapture)
                },
                aggregateErrors: boolean("aggregateErrors", in: payload))
            return try scoped(group, payload: payload, supportsRequest: true, supportsResponse: true)

        case "priority.Group":
            guard let children = payload["modifiers"] as? [[String: Any]] else {
                throw ProxyError.invalidHTTP("priority.Group requires modifiers with priority and modifier")
            }
            var ranked: [(priority: Int, index: Int, modifier: any Modifier)] = []
            for (index, child) in children.enumerated() {
                guard let node = child["modifier"] else {
                    throw ProxyError.invalidHTTP("priority child requires modifier")
                }
                let priority = try optionalInteger("priority", in: child) ?? 0
                let modifier = try parseNode(
                    node, verifications: verifications, logSink: logSink, logCapture: logCapture)
                ranked.append((priority: priority, index: index, modifier: modifier))
            }
            ranked.sort {
                if $0.priority == $1.priority { return $0.index > $1.index }
                return $0.priority > $1.priority
            }
            return try scoped(
                ModifierGroup(ranked.map { $0.modifier }), payload: payload,
                supportsRequest: true, supportsResponse: true)

        case "stash.Modifier":
            if let scope = payload["scope"] as? [String],
                scope.map({ $0.lowercased() }).contains("response"),
                !scope.map({ $0.lowercased() }).contains("request")
            {
                throw ProxyError.invalidHTTP("stash response scope also requires request scope")
            }
            return try scoped(
                StashModifier(headerName: string("headerName", in: payload) ?? ""),
                payload: payload, supportsRequest: true, supportsResponse: true)

        case "cookie.Modifier":
            let expires: Date?
            if let text = try string("expires", in: payload) {
                let fractional = ISO8601DateFormatter()
                fractional.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
                guard let date = fractional.date(from: text) ?? ISO8601DateFormatter().date(from: text) else {
                    throw ProxyError.invalidHTTP("cookie expires must be RFC 3339")
                }
                expires = date
            } else {
                expires = nil
            }
            return try scoped(
                MartianCookieModifier(
                    name: string("name", in: payload) ?? "", value: string("value", in: payload) ?? "",
                    path: string("path", in: payload) ?? "", domain: string("domain", in: payload) ?? "",
                    expires: expires, secure: boolean("secure", in: payload),
                    httpOnly: boolean("httpOnly", in: payload),
                    maxAge: optionalInteger("maxAge", in: payload) ?? 0),
                payload: payload, supportsRequest: true, supportsResponse: true)

        case "log.Logger":
            return try scoped(
                MessageLoggerModifier(
                    headersOnly: boolean("headersOnly", in: payload),
                    decode: boolean("decode", in: payload), capture: logCapture, sink: logSink),
                payload: payload, supportsRequest: true, supportsResponse: true)

        case "skip.RoundTrip":
            return try scoped(
                SkipRoundTripModifier(), payload: payload,
                supportsRequest: true, supportsResponse: false)

        case "noop.Modifier":
            return try scoped(ModifierGroup([]), payload: payload, supportsRequest: true, supportsResponse: true)

        case "static.Modifier":
            guard let rootPath = try string("rootPath", in: payload) else {
                throw ProxyError.invalidHTTP("static.Modifier requires rootPath")
            }
            if let paths = payload["explicitPaths"], !(paths is [String: String]) {
                throw ProxyError.invalidHTTP("static explicitPaths must map strings to strings")
            }
            return try scoped(
                StaticFileModifier(
                    rootPath: rootPath,
                    explicitPaths: payload["explicitPaths"] as? [String: String] ?? [:]),
                payload: payload, supportsRequest: true, supportsResponse: true)

        case "header.Verifier", "status.Verifier", "method.Verifier", "url.Verifier",
            "querystring.Verifier", "failure.Verifier", "pingback.Verifier":
            let kind: VerificationSpec.Kind
            switch type {
            case "header.Verifier": kind = .header
            case "status.Verifier": kind = .status
            case "method.Verifier": kind = .method
            case "url.Verifier": kind = .url
            case "querystring.Verifier": kind = .queryString
            case "failure.Verifier": kind = .failure
            default: kind = .pingback
            }
            let spec = try VerificationSpec(
                kind: kind, name: string("name", in: payload),
                value: string("value", in: payload), method: string("method", in: payload),
                statusCode: optionalInteger("statusCode", in: payload),
                scheme: string("scheme", in: payload), host: string("host", in: payload),
                path: string("path", in: payload), query: string("query", in: payload),
                message: string("message", in: payload))
            let modifier = try VerifierModifier(spec: spec, store: verifications)
            return try scoped(
                modifier, payload: payload, supportsRequest: kind != .status,
                supportsResponse: kind == .header || kind == .status)

        case "header.Append":
            guard let name = try string("name", in: payload), let value = try string("value", in: payload) else {
                throw ProxyError.invalidHTTP("header.Append requires name and value")
            }
            return try scoped(
                HeaderOperationModifier(.append(name: name, value: value)), payload: payload,
                supportsRequest: true, supportsResponse: true)

        case "header.Blacklist":
            guard let names = payload["names"] as? [String] else {
                throw ProxyError.invalidHTTP("header.Blacklist requires names")
            }
            return try scoped(
                HeaderOperationModifier(.blacklist(names: names)), payload: payload,
                supportsRequest: true, supportsResponse: true)

        case "header.Copy":
            guard let from = try string("from", in: payload), let to = try string("to", in: payload) else {
                throw ProxyError.invalidHTTP("header.Copy requires from and to")
            }
            return try scoped(
                HeaderOperationModifier(.copy(from: from, to: to)), payload: payload,
                supportsRequest: true, supportsResponse: true)

        case "header.Id":
            return try scoped(HeaderIDModifier(), payload: payload, supportsRequest: true, supportsResponse: false)

        case "header.Modifier":
            guard let name = payload["name"] as? String,
                let value = payload["value"] as? String,
                HTTPHead.isValidHeader(name: name, value: value)
            else {
                throw ProxyError.invalidHTTP("header.Modifier requires a valid name and value")
            }
            return try scoped(
                HeaderModifier(scope: .both, name: name, value: value),
                payload: payload, supportsRequest: true, supportsResponse: true)

        case "status.Modifier":
            guard let statusCode = integer(payload["statusCode"]), (100...599).contains(statusCode) else {
                throw ProxyError.invalidHTTP("status.Modifier requires statusCode from 100 through 599")
            }
            return try scoped(
                StatusModifier(statusCode: statusCode), payload: payload,
                supportsRequest: false, supportsResponse: true)

        case "body.Modifier":
            guard let encoded = payload["body"] as? String,
                let body = Data(base64Encoded: encoded),
                body.count <= 1_048_576
            else {
                throw ProxyError.invalidHTTP("body.Modifier requires a base64 body no larger than 1 MiB")
            }
            let contentType = payload["contentType"] as? String
            guard contentType?.contains("\r") != true, contentType?.contains("\n") != true else {
                throw ProxyError.invalidHTTP("body.Modifier contentType is invalid")
            }
            return try scoped(
                BodyModifier(scope: .both, content: body, contentType: contentType),
                payload: payload, supportsRequest: true, supportsResponse: true)

        case "querystring.Modifier":
            guard let name = payload["name"] as? String, !name.isEmpty,
                let value = payload["value"] as? String
            else {
                throw ProxyError.invalidHTTP("querystring.Modifier requires name and value")
            }
            return try scoped(
                QueryStringModifier(name: name, value: value), payload: payload,
                supportsRequest: true, supportsResponse: false)

        case "url.Modifier":
            return try scoped(
                URLRewriteModifier(
                    scheme: string("scheme", in: payload),
                    host: string("host", in: payload),
                    path: string("path", in: payload),
                    query: string("query", in: payload)),
                payload: payload, supportsRequest: true, supportsResponse: false)

        case "port.Modifier":
            let modifier = try PortRewriteModifier(
                port: optionalInteger("port", in: payload),
                defaultForScheme: boolean("defaultForScheme", in: payload),
                remove: boolean("remove", in: payload))
            return try scoped(modifier, payload: payload, supportsRequest: true, supportsResponse: false)

        case "url.Filter", "url.RegexFilter", "header.Filter", "header.RegexFilter",
            "querystring.Filter", "cookie.Filter", "method.Filter", "port.Filter":
            let kind: MatchCondition.Kind
            switch type {
            case "url.Filter": kind = .url
            case "url.RegexFilter": kind = .urlRegex
            case "header.Filter": kind = .header
            case "header.RegexFilter": kind = .headerRegex
            case "querystring.Filter": kind = .queryString
            case "cookie.Filter": kind = .cookie
            case "method.Filter": kind = .method
            default: kind = .port
            }
            let condition = try MatchCondition(
                kind: kind,
                name: string(kind == .headerRegex ? "header" : "name", in: payload),
                value: type == "header.Filter" ? string("value", in: payload) ?? "" : string("value", in: payload),
                regex: string("regex", in: payload),
                scheme: string("scheme", in: payload), host: string("host", in: payload),
                path: string("path", in: payload), query: string("query", in: payload),
                methods: string("method", in: payload).map { [$0] },
                port: optionalInteger("port", in: payload))
            guard let child = payload["modifier"] else {
                throw ProxyError.invalidHTTP("\(type) requires modifier")
            }
            if ["port.Filter", "header.RegexFilter"].contains(type), payload["else"] != nil {
                throw ProxyError.unsupported("Martian \(type) has no else branch; use Jovian match")
            }
            let modifier = try MatchModifier(
                condition: condition,
                modifier: parseNode(child, verifications: verifications, logSink: logSink, logCapture: logCapture),
                elseModifier: payload["else"].map {
                    try parseNode($0, verifications: verifications, logSink: logSink, logCapture: logCapture)
                },
                responseUsesRequestHeaders: type == "header.RegexFilter")
            return try scoped(modifier, payload: payload, supportsRequest: true, supportsResponse: true)

        default:
            throw ProxyError.invalidHTTP("unknown Martian modifier: \(type)")
        }
    }

    private static func string(_ key: String, in payload: [String: Any]) throws -> String? {
        guard let value = payload[key] else { return nil }
        guard let string = value as? String else { throw ProxyError.invalidHTTP("\(key) must be a string") }
        return string
    }

    private static func optionalInteger(_ key: String, in payload: [String: Any]) throws -> Int? {
        guard let value = payload[key] else { return nil }
        guard let number = integer(value) else { throw ProxyError.invalidHTTP("\(key) must be an integer") }
        return number
    }

    private static func boolean(_ key: String, in payload: [String: Any]) throws -> Bool {
        guard let value = payload[key] else { return false }
        guard let number = value as? NSNumber, CFGetTypeID(number) == CFBooleanGetTypeID() else {
            throw ProxyError.invalidHTTP("\(key) must be a boolean")
        }
        return number.boolValue
    }

    private static func scoped(
        _ modifier: any Modifier, payload: [String: Any],
        supportsRequest: Bool, supportsResponse: Bool
    ) throws -> any Modifier {
        let requested: Set<String>
        if payload["scope"] != nil, !(payload["scope"] is [String]) {
            throw ProxyError.invalidHTTP("Martian scope must be an array of strings")
        }
        if let values = payload["scope"] as? [String] {
            requested = Set(values.map { $0.lowercased() })
            guard !requested.isEmpty, requested.isSubset(of: ["request", "response"]) else {
                throw ProxyError.invalidHTTP("Martian scope must contain request and/or response")
            }
        } else {
            requested = Set(
                ["request", "response"].filter {
                    $0 == "request" ? supportsRequest : supportsResponse
                })
        }
        guard !requested.contains("request") || supportsRequest,
            !requested.contains("response") || supportsResponse
        else {
            throw ProxyError.invalidHTTP("scope is not supported by this Martian modifier")
        }
        return ScopedModifier(
            modifier: modifier,
            request: requested.contains("request"),
            response: requested.contains("response"))
    }

    private static func integer(_ value: Any?) -> Int? {
        guard let number = value as? NSNumber, CFGetTypeID(number) != CFBooleanGetTypeID() else { return nil }
        let result = number.intValue
        return number.doubleValue == Double(result) ? result : nil
    }
}

private struct ScopedModifier: Modifier {
    let modifier: any Modifier
    let request: Bool
    let response: Bool

    func modify(request context: inout RequestContext) throws {
        if request { try modifier.modify(request: &context) }
    }

    func modify(response context: inout ResponseContext) throws {
        if response { try modifier.modify(response: &context) }
    }
}
