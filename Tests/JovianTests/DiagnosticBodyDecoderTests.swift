import Foundation
import XCTest

@testable import Jovian

final class DiagnosticBodyDecoderTests: XCTestCase {
    // Independently generated with Python's gzip/zlib, not the implementation under test.
    private let plaintext = Data(#"{"hello":"world"}"#.utf8)
    private let gzip = Data(base64Encoded: "H4sIAAAAAAAC/6tWykjNyclXslIqzy/KSVGqBQDRQQnYEQAAAA==")!
    private let zlib = Data(base64Encoded: "eJyrVspIzcnJV7JSKs8vyklRqgUANWsF9w==")!
    private let raw = Data(base64Encoded: "q1bKSM3JyVeyUirPL8pJUaoFAA==")!
    private let optionalGzip = Data(
        base64Encoded: "H4sIHwAAAAAC/wMAYWJjbmFtZQBjb21tZW50APr+q1bKSM3JyVeyUirPL8pJUaoFANFBCdgRAAAA")!

    func testSupportedFormatsAndExactOutputLimit() throws {
        let stored = Data(base64Encoded: "AREA7v97ImhlbGxvIjoid29ybGQifQ==")!
        for (body, encoding) in [
            (gzip, "gzip"), (gzip, "x-gzip"), (gzip, "GZIP"), (optionalGzip, "gzip"),
            (zlib, "deflate"), (raw, "deflate"), (stored, "deflate"),
        ] {
            XCTAssertEqual(
                try DiagnosticBodyDecoder.decode(body, encoding: encoding, limit: plaintext.count), plaintext)
            XCTAssertThrowsError(try DiagnosticBodyDecoder.decode(body, encoding: encoding, limit: plaintext.count - 1))
            XCTAssertThrowsError(try DiagnosticBodyDecoder.decode(body, encoding: encoding, limit: 0))
        }
    }

    func testEmptyStreamsAndIdentity() throws {
        for (base64, encoding) in [
            ("H4sIAAAAAAAC/wMAAAAAAAAAAAA=", "gzip"), ("eJwDAAAAAAE=", "deflate"), ("AwA=", "deflate"),
        ] {
            XCTAssertEqual(
                try DiagnosticBodyDecoder.decode(Data(base64Encoded: base64)!, encoding: encoding, limit: 0), Data())
        }
        for encoding: String? in [nil, "", "identity", "IDENTITY"] {
            XCTAssertEqual(try DiagnosticBodyDecoder.decode(plaintext, encoding: encoding, limit: 0), plaintext)
        }
    }

    func testRejectsEveryTruncatedPrefixAndTrailingBytes() {
        for (body, encoding) in [(gzip, "gzip"), (optionalGzip, "gzip"), (zlib, "deflate"), (raw, "deflate")] {
            for count in 0..<body.count {
                XCTAssertThrowsError(
                    try DiagnosticBodyDecoder.decode(Data(body.prefix(count)), encoding: encoding, limit: 100),
                    "\(encoding), prefix \(count)")
            }
            XCTAssertThrowsError(try DiagnosticBodyDecoder.decode(body + Data([0]), encoding: encoding, limit: 100))
        }
        XCTAssertThrowsError(try DiagnosticBodyDecoder.decode(gzip + gzip, encoding: "gzip", limit: 100))
    }

    func testRejectsCorruptHeadersChecksumsAndSizes() {
        for index in [0, 1, 2, gzip.count - 8, gzip.count - 4] {
            var corrupt = gzip
            corrupt[index] ^= 1
            XCTAssertThrowsError(try DiagnosticBodyDecoder.decode(corrupt, encoding: "gzip", limit: 100))
        }
        var reservedFlags = gzip
        reservedFlags[3] = 0x20
        XCTAssertThrowsError(try DiagnosticBodyDecoder.decode(reservedFlags, encoding: "gzip", limit: 100))
        // The optional header includes extra data, filename, comment, and a header CRC16.
        for index in [10, 12, 14, 28] {
            var corrupt = optionalGzip
            corrupt[index] ^= 1
            XCTAssertThrowsError(try DiagnosticBodyDecoder.decode(corrupt, encoding: "gzip", limit: 100))
        }
        for index in [0, 1, zlib.count - 1] {
            var corrupt = zlib
            corrupt[index] ^= 1
            XCTAssertThrowsError(try DiagnosticBodyDecoder.decode(corrupt, encoding: "deflate", limit: 100))
        }
        // Valid zlib header declaring a preset dictionary, which is unsupported.
        let dictionaryStream = Data([0x78, 0x20, 0, 0, 0, 0]) + raw + zlib.suffix(4)
        XCTAssertThrowsError(try DiagnosticBodyDecoder.decode(dictionaryStream, encoding: "deflate", limit: 100))
    }

    func testLargeExpansionAndInvalidLimits() throws {
        let compressed = Data(
            base64Encoded:
                "H4sIAAAAAAAC/+3BMQEAAADCoGzrX8oaHkABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAArwbXn4oFoIYBAA=="
        )!
        XCTAssertThrowsError(try DiagnosticBodyDecoder.decode(compressed, encoding: "gzip", limit: 64))
        XCTAssertEqual(
            try DiagnosticBodyDecoder.decode(compressed, encoding: "gzip", limit: 100_000),
            Data(repeating: 65, count: 100_000))
        for limit in [-1, 4 * 1_024 * 1_024 + 1, Int.max] {
            XCTAssertThrowsError(try DiagnosticBodyDecoder.decode(gzip, encoding: "gzip", limit: limit))
        }
        XCTAssertThrowsError(try DiagnosticBodyDecoder.decode(gzip, encoding: "br", limit: 100))
    }

    func testStoredBlockContainingEveryByteValue() throws {
        let body = Data((0..<65_535).map { UInt8(truncatingIfNeeded: $0) })
        // Final uncompressed DEFLATE block: LEN=65535, NLEN=0, followed by literal bytes.
        let compressed = Data([1, 255, 255, 0, 0]) + body
        XCTAssertEqual(
            try DiagnosticBodyDecoder.decode(compressed, encoding: "deflate", limit: body.count), body)
        XCTAssertThrowsError(
            try DiagnosticBodyDecoder.decode(compressed, encoding: "deflate", limit: body.count - 1))
        XCTAssertThrowsError(
            try DiagnosticBodyDecoder.decode(compressed + Data([0]), encoding: "deflate", limit: body.count))
    }
}
