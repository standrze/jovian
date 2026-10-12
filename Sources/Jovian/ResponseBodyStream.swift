import Darwin
import Foundation

/// A single-use response payload with a known byte length.
///
/// Reads must return at most `maximum` bytes.
public protocol ResponseBodyStream: Sendable {
    var length: Int { get }
    func read(maximum: Int) throws -> Data?
}

enum BodyPiece: Sendable {
    case bytes(Data)
    case range(Range<Int>)

    var count: Int {
        switch self {
        case .bytes(let data): return data.count
        case .range(let range): return range.count
        }
    }
}

/// Owns the already-validated file descriptor; path changes cannot redirect subsequent reads.
final class FileBodyStream: ResponseBodyStream, @unchecked Sendable {
    let length: Int
    private let descriptor: Int32
    private let pieces: [BodyPiece]
    private var pieceIndex = 0
    private var position = 0

    init(descriptor: Int32, pieces: [BodyPiece], length: Int) throws {
        self.descriptor = dup(descriptor)
        guard self.descriptor >= 0 else { throw ProxyError.connection("cannot retain static file descriptor") }
        self.pieces = pieces
        self.length = length
    }

    deinit { Darwin.close(descriptor) }

    func read(maximum: Int) throws -> Data? {
        guard maximum > 0 else { throw ProxyError.invalidHTTP("body read maximum must be positive") }
        while pieceIndex < pieces.count {
            let piece = pieces[pieceIndex]
            let count = min(maximum, piece.count - position)
            if count == 0 {
                pieceIndex += 1
                position = 0
                continue
            }
            let data: Data
            switch piece {
            case .bytes(let bytes):
                data = bytes.subdata(in: position..<(position + count))
            case .range(let range):
                var bytes = [UInt8](repeating: 0, count: count)
                var received: Int
                repeat {
                    received = pread(descriptor, &bytes, count, off_t(range.lowerBound + position))
                } while received < 0 && errno == EINTR
                guard received > 0 else { throw ProxyError.connection("static file changed or could not be read") }
                data = Data(bytes.prefix(received))
            }
            position += data.count
            return data
        }
        return nil
    }
}
