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

    static func parse(_ data: Data) throws -> any Modifier {
        try parseNode(JSONSerialization.jsonObject(with: data))
    }

    private static func parseNode(_ object: Any) throws -> any Modifier {
        guard let message = object as? [String: Any], message.count == 1,
            let type = message.keys.first,
            let payload = message[type] as? [String: Any]
        else {
            throw ProxyError.invalidHTTP("Martian configuration must contain exactly one package.Type object")
        }

        switch type {
        case "fifo.Group":
            if payload["aggregateErrors"] as? Bool == true {
                throw ProxyError.unsupported("fifo.Group aggregateErrors")
            }
            guard let children = payload["modifiers"] as? [Any] else {
                throw ProxyError.invalidHTTP("fifo.Group requires modifiers")
            }
            let group = ModifierGroup(try children.map(parseNode))
            return try scoped(group, payload: payload, supportsRequest: true, supportsResponse: true)

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

        default:
            throw ProxyError.invalidHTTP("unknown Martian modifier: \(type)")
        }
    }

    private static func scoped(
        _ modifier: any Modifier, payload: [String: Any],
        supportsRequest: Bool, supportsResponse: Bool
    ) throws -> any Modifier {
        let requested: Set<String>
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
