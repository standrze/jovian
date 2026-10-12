import Darwin
import Foundation

public struct SkipRoundTripModifier: Modifier {
    public init() {}

    public func modify(request: inout RequestContext) {
        request.skipRoundTrip = true
    }
}

/// Local mocks with bounded reads and streamed large-file/multipart responses.
///
/// Descriptor-relative opens keep every file beneath the configured root.
public final class StaticFileModifier: Modifier, @unchecked Sendable {
    /// Buffer threshold; larger files use bounded descriptor reads.
    public static let maximumFileBytes = 4 * 1024 * 1024
    private let rootDescriptor: Int32
    private let explicitPaths: [String: String]

    public init(rootPath: String, explicitPaths: [String: String] = [:]) throws {
        guard rootPath.hasPrefix("/"), !rootPath.contains("\0") else {
            throw ProxyError.invalidHTTP("static rootPath must be an absolute directory path")
        }
        for (path, file) in explicitPaths {
            guard path.hasPrefix("/"), Self.components(path) != nil,
                !file.hasPrefix("/"), Self.components(file)?.isEmpty == false
            else {
                throw ProxyError.invalidHTTP("static explicitPaths must map URL paths to root-relative files")
            }
        }
        rootDescriptor = open(rootPath, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard rootDescriptor >= 0 else { throw ProxyError.invalidHTTP("static rootPath is not a readable directory") }
        self.explicitPaths = explicitPaths
    }

    deinit { Darwin.close(rootDescriptor) }

    public func modify(request: inout RequestContext) {
        request.skipRoundTrip = true
    }

    public func modify(response: inout ResponseContext) {
        guard ["GET", "HEAD"].contains(response.requestMethod) else {
            fail(405, response: &response)
            response.head["Allow"] = "GET, HEAD"
            return
        }
        guard let path = URLComponents(string: response.target)?.path,
            let pathParts = Self.components(path)
        else {
            fail(403, response: &response)
            return
        }
        let normalized = "/" + pathParts.joined(separator: "/")
        let file = explicitPaths[normalized] ?? pathParts.joined(separator: "/")
        guard let parts = Self.components(file), !parts.isEmpty else {
            fail(404, response: &response)
            return
        }
        var descriptor = dup(rootDescriptor)
        guard descriptor >= 0 else {
            fail(500, response: &response)
            return
        }
        defer { Darwin.close(descriptor) }
        for (index, part) in parts.enumerated() {
            let directory = index < parts.count - 1
            let next = openat(
                descriptor, part, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK | (directory ? O_DIRECTORY : 0))
            guard next >= 0 else {
                let code = errno
                fail(
                    code == ENOENT ? 404 : (code == EACCES || code == ELOOP || code == ENOTDIR ? 403 : 500),
                    response: &response)
                return
            }
            Darwin.close(descriptor)
            descriptor = next
        }
        var metadata = stat()
        guard fstat(descriptor, &metadata) == 0 else {
            fail(500, response: &response)
            return
        }
        guard metadata.st_mode & S_IFMT == S_IFREG else {
            fail(403, response: &response)
            return
        }
        guard metadata.st_size >= 0, metadata.st_size <= Int.max else {
            fail(413, response: &response)
            return
        }
        let plan = ByteRangePlan(
            size: Int(metadata.st_size), range: response.requestHead?["Range"],
            contentType: Self.contentType(file))
        plan.apply(to: &response)
        do {
            let stream = try FileBodyStream(descriptor: descriptor, pieces: plan.pieces, length: plan.length)
            if plan.length <= Self.maximumFileBytes && response.requestMethod != "HEAD" {
                var body = Data()
                while let chunk = try stream.read(maximum: 32_768) { body.append(chunk) }
                response.body = body
            } else {
                response.body = nil
                response.bodyStream = stream
            }
        } catch { fail(500, response: &response) }
    }

    private func fail(_ code: Int, response: inout ResponseContext) {
        StatusModifier(statusCode: code).modify(response: &response)
        for name in ["Content-Encoding", "Content-Range", "Transfer-Encoding", "Content-Type", "Accept-Ranges"] {
            response.head.remove(name)
        }
        response.head["Content-Length"] = "0"
        response.body = Data()
    }

    private static func components(_ path: String) -> [String]? {
        guard !path.unicodeScalars.contains(where: { $0.value < 32 || $0.value == 127 }),
            !path.contains("\\")
        else { return nil }
        let parts = path.split(separator: "/").map(String.init)
        guard !parts.contains(".."), !parts.contains(".") else { return nil }
        return parts
    }

    private static func contentType(_ path: String) -> String {
        switch URL(fileURLWithPath: path).pathExtension.lowercased() {
        case "html", "htm": "text/html; charset=utf-8"
        case "txt", "log": "text/plain; charset=utf-8"
        case "css": "text/css; charset=utf-8"
        case "js": "text/javascript; charset=utf-8"
        case "json": "application/json"
        case "xml": "application/xml"
        case "svg": "image/svg+xml"
        case "png": "image/png"
        case "jpg", "jpeg": "image/jpeg"
        case "gif": "image/gif"
        case "pdf": "application/pdf"
        default: "application/octet-stream"
        }
    }
}
