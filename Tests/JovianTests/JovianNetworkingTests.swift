import Foundation
import NIOCore
import NIOEmbedded
import NIOHTTP1
import XCTest

@testable import Jovian

final class JovianNetworkingTests: XCTestCase {
    func testNIOFramingPreservesFragmentedChunkedBodyTrailersAndPipelining() async throws {
        let channel = NIOAsyncTestingChannel()
        let connection = try await channel.eventLoop.submit { try ChannelConnection(channel: channel, role: .server) }
            .get()
        defer { connection.close() }
        for piece in [
            "POST /one HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: chu",
            "nked\r\n\r\n3;ignored=yes\r\nab",
            "c\r\n0\r\nX-Checksum: pass\r\n\r\nGET /two HTTP/1.1\r\nHost: example.test\r\n\r\n",
        ] { try await channel.writeInbound(ByteBuffer(string: piece)) }
        guard case .request(let first)? = try await connection.next() else { return XCTFail("missing first head") }
        XCTAssertEqual(first.uri, "/one")
        var body = Data()
        var trailers: HTTPHeaders?
        while let event = try await connection.next() {
            if case .body(let bytes) = event { body.append(contentsOf: bytes.readableBytesView) }
            if case .end(let value) = event {
                trailers = value
                break
            }
        }
        XCTAssertEqual(body, Data("abc".utf8))
        XCTAssertEqual(trailers?.first(name: "X-Checksum"), "pass")
        guard case .request(let second)? = try await connection.next() else { return XCTFail("missing second head") }
        XCTAssertEqual(second.uri, "/two")
        guard case .end? = try await connection.next() else { return XCTFail("missing second boundary") }
    }

    func testNIORejectsAmbiguousLengthAndMalformedChunks() async throws {
        for wire in [
            "POST / HTTP/1.1\r\nHost: example.test\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
            "POST / HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: chunked\r\n\r\nxyz\r\n",
            "GET / HTTP/1.1\r\nBad Name: value\r\n\r\n",
        ] {
            let channel = NIOAsyncTestingChannel()
            let connection = try await channel.eventLoop.submit {
                try ChannelConnection(channel: channel, role: .server)
            }.get()
            try await channel.writeInbound(ByteBuffer(string: wire))
            var failed = false
            do { while try await connection.next() != nil {} } catch { failed = true }
            XCTAssertTrue(failed, "NIO must reject malformed framing")
            _ = try? await channel.finish(acceptAlreadyClosed: true)
        }
    }

    func testConnectHandshakeHasNoChunkTerminatorAndPreservesCoalescedBytes() async throws {
        let channel = NIOAsyncTestingChannel()
        let connection = try await channel.eventLoop.submit { try ChannelConnection(channel: channel, role: .server) }
            .get()
        defer { connection.close() }
        let payload: [UInt8] = [0, 1, 2, 255]
        var wire = ByteBuffer(string: "CONNECT example.test:443 HTTP/1.1\r\n\r\n")
        wire.writeBytes(payload)
        try await channel.writeInbound(wire)
        guard case .request? = try await connection.next(), case .end? = try await connection.next() else {
            return XCTFail("missing CONNECT handshake")
        }
        try await connection.write(
            HTTPServerResponsePart.head(
                .init(
                    version: .http1_1,
                    status: .custom(code: 200, reasonPhrase: "Connection Established"))))
        try await connection.write(HTTPServerResponsePart.end(nil))
        var written = Data()
        while let bytes = try await channel.readOutbound(as: IOData.self) {
            guard case .byteBuffer(let buffer) = bytes else { return XCTFail("unexpected file region") }
            written.append(contentsOf: buffer.readableBytesView)
        }
        XCTAssertEqual(String(decoding: written, as: UTF8.self), "HTTP/1.1 200 Connection Established\r\n\r\n")
        try await connection.becomeRaw()
        guard case .bytes(let bytes)? = try await connection.next() else { return XCTFail("opaque bytes were lost") }
        XCTAssertEqual(Array(bytes.readableBytesView), payload)
    }
}
