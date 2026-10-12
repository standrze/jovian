import Darwin
import Foundation

public struct JovianCookie: Codable, Sendable {
    public let name: String
    public let value: String
    public let domain: String
    public let path: String
    public let secure: Bool
    public let hostOnly: Bool
    public let expires: Date?
    public init?(_ cookie: HTTPCookie, source: URL) {
        let domain = cookie.domain.lowercased().trimmingCharacters(in: CharacterSet(charactersIn: "."))
        guard let host = source.host?.lowercased(), !domain.isEmpty,
            host == domain || host.hasSuffix("." + domain),
            cookie.name.utf8.count + cookie.value.utf8.count <= 4096,
            HTTPHead.isValidHeader(name: "Cookie", value: cookie.name + "=" + cookie.value)
        else { return nil }
        self.name = cookie.name
        self.value = cookie.value
        self.domain = domain
        self.path = cookie.path
        self.secure = cookie.isSecure
        self.hostOnly = !cookie.domain.hasPrefix(".")
        self.expires = cookie.expiresDate
    }
    public func matches(_ url: URL) -> Bool {
        guard expires == nil || expires! > Date(), let host = url.host?.lowercased(),
            host == domain || (!hostOnly && host.hasSuffix("." + domain)),
            !secure || url.scheme == "https"
        else { return false }
        let requestPath = url.path.isEmpty ? "/" : url.path
        return requestPath == path
            || (requestPath.hasPrefix(path) && (path.hasSuffix("/") || requestPath.dropFirst(path.count).first == "/"))
    }
}

public struct JovianSession: Codable, Sendable {
    public let schemaVersion: Int
    public let id: UUID
    public var name: String
    public let origin: String
    public let createdAt: Date
    public var updatedAt: Date
    public var closed: Bool
    public var retainBodies: Bool
    public var cookies: [JovianCookie]
    public var exchanges: [JovianExchange]
}

/// File transactions use an interprocess lock, bounded records and atomic writes.
///
/// No shared global cookie storage and no automatic credential imports.
public final class JovianSessionStore: @unchecked Sendable {
    public let directory: URL
    public static var defaultDirectory: URL {
        let environment = ProcessInfo.processInfo.environment
        if let path = environment["JOVIAN_SESSIONS_DIR"] ?? environment["REED_SESSIONS_DIR"]
            ?? environment["RELAY_SESSIONS_DIR"]
        {
            return URL(fileURLWithPath: path, isDirectory: true)
        }

        let fileManager = FileManager.default
        let homeDirectory = fileManager.homeDirectoryForCurrentUser
        let directory = homeDirectory.appendingPathComponent(".jovian/sessions", isDirectory: true)
        let reedDirectory = homeDirectory.appendingPathComponent(".reed/sessions", isDirectory: true)
        if !fileManager.fileExists(atPath: directory.path), fileManager.fileExists(atPath: reedDirectory.path) {
            return reedDirectory
        }
        let legacyDirectory = homeDirectory.appendingPathComponent(".relay/sessions", isDirectory: true)
        // Keep existing sessions visible until a jovian store is explicitly created.
        if !fileManager.fileExists(atPath: directory.path), fileManager.fileExists(atPath: legacyDirectory.path) {
            return legacyDirectory
        }
        return directory
    }
    public init(directory: URL = JovianSessionStore.defaultDirectory) throws {
        self.directory = directory.standardizedFileURL
        try FileManager.default.createDirectory(
            at: self.directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        let attributes = try FileManager.default.attributesOfItem(atPath: self.directory.path)
        guard attributes[.type] as? FileAttributeType == .typeDirectory else {
            throw ProxyError.invalidHTTP("Session store must be a directory, not a symlink")
        }
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: self.directory.path)
    }
    private func transaction<T>(_ work: () throws -> T) throws -> T {
        let fd = Darwin.open(directory.appendingPathComponent(".lock").path, O_RDWR | O_CREAT | O_NOFOLLOW, 0o600)
        guard fd >= 0 else { throw ProxyError.connection("Cannot open session-store lock") }
        defer { Darwin.close(fd) }
        guard flock(fd, LOCK_EX) == 0 else { throw ProxyError.connection("Cannot lock session store") }
        defer { flock(fd, LOCK_UN) }
        return try work()
    }
    private func path(_ id: UUID) -> URL { directory.appendingPathComponent(id.uuidString.lowercased() + ".json") }
    private func read(_ id: UUID) throws -> JovianSession {
        let url = path(id)
        let attrs = try FileManager.default.attributesOfItem(atPath: path(id).path)
        guard attrs[.type] as? FileAttributeType == .typeRegular,
            (attrs[.size] as? NSNumber)?.intValue ?? Int.max <= 8 * 1024 * 1024
        else { throw ProxyError.invalidHTTP("Invalid or oversized session file") }
        let result = try JSONDecoder().decode(JovianSession.self, from: Data(contentsOf: url))
        guard result.id == id, result.schemaVersion == 1 else {
            throw ProxyError.invalidHTTP("Unsupported session schema or ID mismatch")
        }
        return result
    }
    private func all() throws -> [JovianSession] {
        try FileManager.default.contentsOfDirectory(at: directory, includingPropertiesForKeys: nil)
            .filter { $0.pathExtension == "json" }
            .map { url in
                guard let id = UUID(uuidString: url.deletingPathExtension().lastPathComponent) else {
                    throw ProxyError.invalidHTTP("Invalid session filename")
                }
                return try read(id)
            }.sorted { $0.updatedAt > $1.updatedAt }
    }
    private func write(_ value: JovianSession) throws {
        var value = value
        value.cookies.removeAll { $0.expires != nil && $0.expires! <= Date() }
        value.cookies = Array(value.cookies.suffix(128))
        value.exchanges = Array(value.exchanges.suffix(40))
        if !value.retainBodies {
            for index in value.exchanges.indices {
                value.exchanges[index].body = ""
                value.exchanges[index].requestBody = nil
                value.exchanges[index].bodyOmitted = true
            }
        }
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        var data = try encoder.encode(value)
        while data.count > 8 * 1024 * 1024 && !value.exchanges.isEmpty {
            value.exchanges.removeFirst()
            data = try encoder.encode(value)
        }
        guard data.count <= 8 * 1024 * 1024 else { throw ProxyError.invalidHTTP("Session exceeds storage limit") }
        try data.write(to: path(value.id), options: .atomic)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: path(value.id).path)
    }
    public func create(name: String, origin: String, retainBodies: Bool = false) throws -> JovianSession {
        let origin = try JovianRequestExecutor.origin(origin)
        let name = name.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !name.isEmpty, name.utf8.count <= 200,
            !name.unicodeScalars.contains(where: CharacterSet.controlCharacters.contains)
        else { throw ProxyError.invalidHTTP("Session name must be 1–200 UTF-8 bytes") }
        return try transaction {
            let existing = try all()
            guard existing.count < 100, !existing.contains(where: { $0.name == name }) else {
                throw ProxyError.invalidHTTP("Session name already exists or 100-session limit reached")
            }
            let now = Date()
            let value = JovianSession(
                schemaVersion: 1, id: UUID(), name: name, origin: origin, createdAt: now, updatedAt: now, closed: false,
                retainBodies: retainBodies, cookies: [], exchanges: [])
            try write(value)
            return value
        }
    }
    public func list() throws -> [JovianSession] { try transaction { try all() } }
    public func load(_ id: UUID) throws -> JovianSession { try transaction { try read(id) } }
    public func resolve(_ selector: String) throws -> JovianSession {
        try transaction {
            let matches = try all().filter {
                $0.name == selector || $0.id.uuidString.lowercased() == selector.lowercased()
                    || (selector.count >= 8 && $0.id.uuidString.lowercased().hasPrefix(selector.lowercased()))
            }
            guard matches.count == 1, let value = matches.first else {
                throw ProxyError.invalidHTTP("Session not found or ambiguous; use its full ID")
            }
            return value
        }
    }
    public func update(_ id: UUID, _ change: (inout JovianSession) throws -> Void) throws {
        try transaction {
            var value = try read(id)
            try change(&value)
            value.updatedAt = Date()
            try write(value)
        }
    }
    public func close(_ id: UUID) throws { try update(id) { $0.closed = true } }
    public func resume(_ id: UUID) throws { try update(id) { $0.closed = false } }
    public func setBodyRetention(_ id: UUID, enabled: Bool) throws { try update(id) { $0.retainBodies = enabled } }
    public func delete(_ id: UUID) throws {
        try transaction {
            _ = try read(id)
            try FileManager.default.removeItem(at: path(id))
        }
    }
    public func saveCookies(_ cookies: [JovianCookie], sessionID: UUID) throws {
        try update(sessionID) { value in
            guard !value.closed else { throw ProxyError.invalidHTTP("Session is closed") }
            for cookie in cookies {
                value.cookies.removeAll {
                    $0.name == cookie.name && $0.domain == cookie.domain && $0.path == cookie.path
                }
                if cookie.expires == nil || cookie.expires! > Date() { value.cookies.append(cookie) }
            }
        }
    }
    public func append(_ exchange: JovianExchange, sessionID: UUID) throws {
        try update(sessionID) { $0.exchanges.append(exchange) }
    }
}
