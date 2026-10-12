import Darwin
import Foundation
import NIOCore

/// TCP CONNECT only.
///
/// Reads exact fields so fragmented replies and early tunnel bytes survive.
enum SOCKS5Handshake {
    static func validate(_ credentials: ProxyCredentials) throws {
        guard (1...255).contains(credentials.username.utf8.count), (1...255).contains(credentials.password.utf8.count)
        else {
            throw ProxyError.invalidHTTP("SOCKS5 username and password must each contain 1 through 255 UTF-8 bytes")
        }
    }

    static func connect(connection: ChannelConnection, host: String, port: UInt16, credentials: ProxyCredentials?)
        async throws
    {
        if let credentials { try validate(credentials) }
        let reader = SOCKSReader(connection: connection)
        let method: UInt8 = credentials == nil ? 0 : 2
        try await connection.write(ByteBuffer(bytes: [5, 1, method]))
        let selection = try await reader.read(2)
        guard selection[0] == 5, selection[1] == method else {
            throw ProxyError.connection("SOCKS5 proxy rejected the configured authentication method")
        }
        if let credentials {
            let user = Data(credentials.username.utf8)
            let password = Data(credentials.password.utf8)
            try await connection.write(
                ByteBuffer(bytes: Data([1, UInt8(user.count)]) + user + Data([UInt8(password.count)]) + password))
            let result = try await reader.read(2)
            guard result[0] == 1, result[1] == 0 else { throw ProxyError.connection("SOCKS5 authentication failed") }
        }
        try await connection.write(ByteBuffer(bytes: try request(host: host, port: port)))
        let reply = try await reader.read(4)
        guard reply[0] == 5, reply[2] == 0, reply[1] == 0 else {
            throw ProxyError.connection("SOCKS5 CONNECT rejected")
        }
        let length: Int
        switch reply[3] {
        case 1: length = 4
        case 4: length = 16
        case 3: length = Int(try await reader.read(1)[0])
        default: throw ProxyError.connection("invalid SOCKS5 address type")
        }
        guard length > 0 else { throw ProxyError.connection("empty SOCKS5 bound address") }
        _ = try await reader.read(length + 2)
        if !reader.buffer.isEmpty { try await connection.prependRaw(ByteBuffer(bytes: reader.buffer)) }
    }

    static func request(host: String, port: UInt16) throws -> Data {
        guard port > 0, !host.isEmpty, !host.contains("%"),
            !host.unicodeScalars.contains(where: { $0.value <= 32 || $0.value == 127 })
        else {
            throw ProxyError.invalidHTTP("invalid SOCKS5 destination")
        }
        var address = Data([5, 1, 0])
        var ipv4 = in_addr()
        var ipv6 = in6_addr()
        if inet_pton(AF_INET, host, &ipv4) == 1 {
            address.append(1)
            withUnsafeBytes(of: ipv4) { address.append(contentsOf: $0) }
        } else if inet_pton(AF_INET6, host, &ipv6) == 1 {
            address.append(4)
            withUnsafeBytes(of: ipv6) { address.append(contentsOf: $0) }
        } else {
            let name = Data(host.utf8)
            guard name.count <= 255, !host.contains(":") else {
                throw ProxyError.invalidHTTP("invalid SOCKS5 hostname")
            }
            address.append(contentsOf: [3, UInt8(name.count)])
            address.append(name)
        }
        address.append(contentsOf: [UInt8(port >> 8), UInt8(port & 0xff)])
        return address
    }
}

private final class SOCKSReader {
    let connection: ChannelConnection
    var buffer = Data()
    init(connection: ChannelConnection) { self.connection = connection }
    func read(_ count: Int) async throws -> Data {
        while buffer.count < count {
            guard case .bytes(let bytes)? = try await connection.next(), bytes.readableBytes > 0 else {
                throw ProxyError.connection("SOCKS5 proxy closed during negotiation")
            }
            buffer.append(contentsOf: bytes.readableBytesView)
        }
        let result = Data(buffer.prefix(count))
        buffer.removeFirst(count)
        return result
    }
}
