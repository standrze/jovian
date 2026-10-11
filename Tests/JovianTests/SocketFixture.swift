import Foundation

@testable import Jovian

#if canImport(Darwin)
    import Darwin
#else
    import Glibc
#endif

protocol ByteStream: AnyObject, Sendable {
    func read(maximum: Int) throws -> Data?
    func write(_ data: Data) throws
    func readHead(limit: Int) throws -> (HTTPHead, Data)
    func close()
}

extension ByteStream {
    func read() throws -> Data? { try read(maximum: 16_384) }
    func readHead() throws -> (HTTPHead, Data) { try readHead(limit: 65_536) }
}

final class Socket: ByteStream, @unchecked Sendable {
    private(set) var descriptor: Int32
    private init(_ descriptor: Int32) throws {
        self.descriptor = descriptor
        var timeout = timeval(tv_sec: 3, tv_usec: 0)
        setsockopt(descriptor, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))
        setsockopt(descriptor, SOL_SOCKET, SO_SNDTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))
        #if canImport(Darwin)
            var enabled: Int32 = 1
            guard
                setsockopt(
                    descriptor,
                    SOL_SOCKET,
                    SO_NOSIGPIPE,
                    &enabled,
                    socklen_t(MemoryLayout.size(ofValue: enabled))
                ) == 0
            else {
                let message = Self.systemError()
                _ = SocketSystem.close(descriptor)
                self.descriptor = -1
                throw ProxyError.connection(message)
            }
        #endif
    }
    deinit { close() }

    static func listen(host: String, port: UInt16) throws -> Socket {
        let fd = SocketSystem.socket(AF_INET, SocketSystem.streamType, 0)
        guard fd >= 0 else { throw ProxyError.connection(systemError()) }
        var reuse: Int32 = 1
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, socklen_t(MemoryLayout.size(ofValue: reuse)))
        var address = sockaddr_in()
        #if canImport(Darwin)
            address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        #endif
        address.sin_family = sa_family_t(AF_INET)
        address.sin_port = port.bigEndian
        guard inet_pton(AF_INET, host, &address.sin_addr) == 1 else {
            _ = SocketSystem.close(fd)
            throw ProxyError.connection("invalid IPv4 bind address \(host)")
        }
        let bindResult = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                SocketSystem.bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard bindResult == 0, SocketSystem.listen(fd, 128) == 0 else {
            let message = systemError()
            _ = SocketSystem.close(fd)
            throw ProxyError.connection(message)
        }
        return try Socket(fd)
    }

    static func connect(host: String, port: UInt16) throws -> Socket {
        var hints = addrinfo()
        hints.ai_family = AF_UNSPEC
        hints.ai_socktype = SocketSystem.streamType
        hints.ai_protocol = Int32(IPPROTO_TCP)
        var result: UnsafeMutablePointer<addrinfo>?
        guard getaddrinfo(host, String(port), &hints, &result) == 0, let first = result else {
            throw ProxyError.connection("cannot resolve \(host)")
        }
        defer { freeaddrinfo(result) }
        var cursor: UnsafeMutablePointer<addrinfo>? = first
        while let info = cursor {
            let fd = SocketSystem.socket(info.pointee.ai_family, info.pointee.ai_socktype, info.pointee.ai_protocol)
            if fd >= 0 && SocketSystem.connect(fd, info.pointee.ai_addr, info.pointee.ai_addrlen) == 0 {
                return try Socket(fd)
            }
            if fd >= 0 { _ = SocketSystem.close(fd) }
            cursor = info.pointee.ai_next
        }
        throw ProxyError.connection(systemError())
    }

    func accept() throws -> Socket {
        let fd = SocketSystem.accept(descriptor, nil, nil)
        guard fd >= 0 else { throw ProxyError.connection(Self.systemError()) }
        return try Socket(fd)
    }

    func localPort() throws -> UInt16 {
        var address = sockaddr_in()
        var length = socklen_t(MemoryLayout<sockaddr_in>.size)
        let result = withUnsafeMutablePointer(to: &address) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                getsockname(descriptor, $0, &length)
            }
        }
        guard result == 0 else { throw ProxyError.connection(Self.systemError()) }
        return UInt16(bigEndian: address.sin_port)
    }

    func peerAddress() -> String? {
        var storage = sockaddr_storage()
        var length = socklen_t(MemoryLayout<sockaddr_storage>.size)
        let result = withUnsafeMutablePointer(to: &storage) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                getpeername(descriptor, $0, &length)
            }
        }
        guard result == 0 else { return nil }
        var host = [CChar](repeating: 0, count: Int(NI_MAXHOST))
        let named = withUnsafePointer(to: &storage) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                getnameinfo($0, length, &host, socklen_t(host.count), nil, 0, NI_NUMERICHOST)
            }
        }
        guard named == 0 else { return nil }
        return String(decoding: host.prefix(while: { $0 != 0 }).map { UInt8(bitPattern: $0) }, as: UTF8.self)
    }

    func read(maximum: Int = 16_384) throws -> Data? {
        var buffer = [UInt8](repeating: 0, count: maximum)
        let count = recv(descriptor, &buffer, buffer.count, 0)
        if count == 0 { return nil }
        guard count > 0 else { throw ProxyError.connection(Self.systemError()) }
        return Data(buffer.prefix(count))
    }

    func readHead(limit: Int = 65_536) throws -> (HTTPHead, Data) {
        let marker = Data("\r\n\r\n".utf8)
        var received = Data()
        while let range = received.range(of: marker) {
            let end = range.upperBound
            return (try parseFixtureHead(received.prefix(end)), Data(received.suffix(from: end)))
        }
        while received.count <= limit {
            guard let chunk = try read() else { throw ProxyError.invalidHTTP("connection closed in headers") }
            received.append(chunk)
            if let range = received.range(of: marker) {
                let end = range.upperBound
                return (try parseFixtureHead(received.prefix(end)), Data(received.suffix(from: end)))
            }
        }
        throw ProxyError.invalidHTTP("headers exceed \(limit) bytes")
    }

    func write(_ data: Data) throws {
        try data.withUnsafeBytes { bytes in
            var offset = 0
            while offset < bytes.count {
                let written = send(
                    descriptor, bytes.baseAddress!.advanced(by: offset), bytes.count - offset, SocketSystem.sendFlags)
                guard written > 0 else { throw ProxyError.connection(Self.systemError()) }
                offset += written
            }
        }
    }

    func shutdownWrite() { _ = SocketSystem.shutdown(descriptor, Int32(SHUT_WR)) }
    func close() {
        if descriptor >= 0 {
            _ = SocketSystem.close(descriptor)
            descriptor = -1
        }
    }
    private static func systemError() -> String { String(cString: strerror(errno)) }
}

/// Independent wire fixture for observing the NIO proxy from a real TCP peer.
private func parseFixtureHead(_ data: Data) throws -> HTTPHead {
    let lines = String(decoding: data, as: UTF8.self).components(separatedBy: "\r\n")
    var headers: [(String, String)] = []
    for line in lines.dropFirst() where !line.isEmpty {
        guard let colon = line.firstIndex(of: ":") else {
            throw ProxyError.invalidHTTP("fixture header")
        }
        headers.append(
            (String(line[..<colon]), String(line[line.index(after: colon)...]).trimmingCharacters(in: .whitespaces)))
    }
    return HTTPHead(startLine: lines[0], headers: headers)
}

/// Narrow platform boundary for the test peer, independent of the proxy transport.
private enum SocketSystem {
    #if canImport(Darwin)
        static let streamType = SOCK_STREAM
        static let sendFlags: Int32 = 0
        static let socket = Darwin.socket
        static let close = Darwin.close
        static let bind = Darwin.bind
        static let listen = Darwin.listen
        static let connect = Darwin.connect
        static let accept = Darwin.accept
        static let shutdown = Darwin.shutdown
    #else
        static let streamType = Int32(SOCK_STREAM.rawValue)
        static let sendFlags = Int32(MSG_NOSIGNAL)
        static let socket = Glibc.socket
        static let close = Glibc.close
        static let bind = Glibc.bind
        static let listen = Glibc.listen
        static let connect = Glibc.connect
        static let accept = Glibc.accept
        static let shutdown = Glibc.shutdown
    #endif
}
