import Compression
import Foundation

/// Bounded diagnostic decoding using Apple's Compression framework, never used for forwarding.
enum DiagnosticBodyDecoder {
    static func decode(_ body: Data, encoding: String?, limit: Int) throws -> Data {
        guard let encoding, encoding.lowercased() != "identity", !encoding.isEmpty else { return body }
        guard ["gzip", "x-gzip", "deflate"].contains(encoding.lowercased()) else {
            throw ProxyError.unsupported("diagnostic content encoding")
        }
        guard (0...4 * 1_024 * 1_024).contains(limit), body.count <= Int(UInt32.max) else {
            throw ProxyError.invalidHTTP("invalid diagnostic decode bound")
        }
        let bytes = Array(body)
        if encoding.lowercased() == "deflate" {
            // Retain compatibility with HTTP peers sending raw rather than zlib-wrapped DEFLATE.
            do { return try decodeZlib(bytes, limit: limit) } catch {
                return try inflate(bytes[...], limit: limit)
            }
        }
        return try decodeGzip(bytes, limit: limit)
    }

    private static var invalidBody: ProxyError {
        .invalidHTTP("diagnostic decode failed or exceeded limit")
    }

    // COMPRESSION_ZLIB decodes raw RFC 1951 DEFLATE. RFC 1950/1952 framing and
    // checksums must be validated separately; successful inflation alone is insufficient.
    private static func inflate(_ bytes: ArraySlice<UInt8>, limit: Int) throws -> Data {
        guard !bytes.isEmpty else { throw invalidBody }
        // One extra byte distinguishes an exact-limit result from an oversized one.
        var output = [UInt8](repeating: 0, count: limit + 1)
        let count = try bytes.withUnsafeBufferPointer { input in
            try output.withUnsafeMutableBufferPointer { destination in
                var stream = compression_stream(
                    dst_ptr: destination.baseAddress!, dst_size: destination.count,
                    src_ptr: input.baseAddress!, src_size: input.count, state: nil)
                guard
                    compression_stream_init(&stream, COMPRESSION_STREAM_DECODE, COMPRESSION_ZLIB)
                        == COMPRESSION_STATUS_OK
                else { throw invalidBody }
                defer { compression_stream_destroy(&stream) }
                stream.src_ptr = input.baseAddress!
                stream.src_size = 0
                stream.dst_ptr = destination.baseAddress!
                stream.dst_size = destination.count
                var supplied = 0
                while true {
                    // Compression may read ahead past DEFLATE's end marker. Feeding one
                    // byte at a time makes the boundary observable, including for raw streams.
                    if stream.src_size == 0 && supplied < input.count {
                        stream.src_ptr = input.baseAddress!.advanced(by: supplied)
                        stream.src_size = 1
                        supplied += 1
                    }
                    let previousSourceSize = stream.src_size
                    let previousDestinationSize = stream.dst_size
                    let flags = supplied == input.count ? Int32(COMPRESSION_STREAM_FINALIZE.rawValue) : 0
                    let status = compression_stream_process(&stream, flags)
                    let written = destination.count - stream.dst_size
                    guard written <= limit else { throw invalidBody }
                    if status == COMPRESSION_STATUS_END {
                        guard stream.src_size == 0, supplied == input.count else { throw invalidBody }
                        return written
                    }
                    guard status == COMPRESSION_STATUS_OK,
                        stream.src_size < previousSourceSize || stream.dst_size < previousDestinationSize
                    else { throw invalidBody }
                }
            }
        }
        return Data(output.prefix(count))
    }

    private static func decodeZlib(_ bytes: [UInt8], limit: Int) throws -> Data {
        guard bytes.count >= 6,
            bytes[0] & 0x0F == 8, bytes[0] >> 4 <= 7,
            (Int(bytes[0]) * 256 + Int(bytes[1])) % 31 == 0,
            bytes[1] & 0x20 == 0
        else { throw invalidBody }
        let trailer = bytes.count - 4
        let decoded = try inflate(bytes[2..<trailer], limit: limit)
        let expected = bytes[trailer...].reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
        guard adler32(decoded) == expected else { throw invalidBody }
        return decoded
    }

    private static func decodeGzip(_ bytes: [UInt8], limit: Int) throws -> Data {
        guard bytes.count >= 18, bytes[0] == 0x1F, bytes[1] == 0x8B,
            bytes[2] == 8, bytes[3] & 0xE0 == 0
        else { throw invalidBody }
        let flags = bytes[3]
        let trailer = bytes.count - 8
        var offset = 10
        if flags & 0x04 != 0 {
            guard offset + 2 <= trailer else { throw invalidBody }
            let extraLength = Int(bytes[offset]) | (Int(bytes[offset + 1]) << 8)
            offset += 2 + extraLength
            guard offset <= trailer else { throw invalidBody }
        }
        for flag: UInt8 in [0x08, 0x10] where flags & flag != 0 {
            guard let end = bytes[offset..<trailer].firstIndex(of: 0) else { throw invalidBody }
            offset = end + 1
        }
        if flags & 0x02 != 0 {
            guard offset + 2 <= trailer else { throw invalidBody }
            let expected = UInt32(bytes[offset]) | (UInt32(bytes[offset + 1]) << 8)
            guard crc32(bytes[..<offset]) & 0xFFFF == expected else { throw invalidBody }
            offset += 2
        }
        let decoded = try inflate(bytes[offset..<trailer], limit: limit)
        guard crc32(decoded) == littleEndian32(bytes, at: trailer),
            UInt32(decoded.count) == littleEndian32(bytes, at: trailer + 4)
        else { throw invalidBody }
        return decoded
    }

    private static func littleEndian32(_ bytes: [UInt8], at offset: Int) -> UInt32 {
        (0..<4).reduce(UInt32(0)) { $0 | (UInt32(bytes[offset + $1]) << ($1 * 8)) }
    }

    private static func adler32(_ bytes: Data) -> UInt32 {
        var low: UInt32 = 1
        var high: UInt32 = 0
        for byte in bytes {
            low = (low + UInt32(byte)) % 65_521
            high = (high + low) % 65_521
        }
        return (high << 16) | low
    }

    private static let crcTable: [UInt32] = (0..<256).map { value in
        var crc = UInt32(value)
        for _ in 0..<8 {
            crc = (crc >> 1) ^ (crc & 1 == 0 ? 0 : 0xEDB8_8320)
        }
        return crc
    }

    private static func crc32(_ bytes: some Sequence<UInt8>) -> UInt32 {
        var crc = UInt32.max
        for byte in bytes {
            crc = (crc >> 8) ^ crcTable[Int((crc ^ UInt32(byte)) & 0xFF)]
        }
        return ~crc
    }
}
