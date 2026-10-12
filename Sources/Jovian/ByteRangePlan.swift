import Foundation

/// Shared bounded range parsing and multipart framing for replacement bodies and static files.
struct ByteRangePlan {
    let status: Int
    let pieces: [BodyPiece]
    let length: Int
    let contentType: String
    let contentRange: String?

    init(size: Int, range: String?, contentType: String) {
        guard let range, !range.isEmpty else {
            self.init(
                status: 200, pieces: [.range(0..<size)], length: size,
                contentType: contentType, contentRange: nil)
            return
        }
        guard let ranges = Self.parse(range, size: size) else {
            self.init(
                status: 416, pieces: [], length: 0,
                contentType: contentType, contentRange: "bytes */\(size)")
            return
        }
        if ranges.count == 1, let selected = ranges.first {
            self.init(
                status: 206, pieces: [.range(selected)], length: selected.count,
                contentType: contentType, contentRange: Self.describe(selected, size: size))
            return
        }
        let boundary = "jovian-" + UUID().uuidString.lowercased()
        var pieces: [BodyPiece] = []
        for selected in ranges {
            let header =
                "--\(boundary)\r\nContent-Type: \(contentType)\r\n"
                + "Content-Range: \(Self.describe(selected, size: size))\r\n\r\n"
            pieces += [.bytes(Data(header.utf8)), .range(selected), .bytes(Data("\r\n".utf8))]
        }
        pieces.append(.bytes(Data("--\(boundary)--\r\n".utf8)))
        var length = 0
        for piece in pieces {
            let (next, overflow) = length.addingReportingOverflow(piece.count)
            if overflow {
                self.init(
                    status: 416, pieces: [], length: 0,
                    contentType: contentType, contentRange: "bytes */\(size)")
                return
            }
            length = next
        }
        self.init(
            status: 206, pieces: pieces, length: length,
            contentType: "multipart/byteranges; boundary=\(boundary)", contentRange: nil)
    }

    private init(status: Int, pieces: [BodyPiece], length: Int, contentType: String, contentRange: String?) {
        self.status = status
        self.pieces = pieces
        self.length = length
        self.contentType = contentType
        self.contentRange = contentRange
    }

    func apply(to response: inout ResponseContext, changeFullStatus: Bool = true) {
        if status != 200 || changeFullStatus { StatusModifier(statusCode: status).modify(response: &response) }
        for name in ["Content-Encoding", "Transfer-Encoding", "Trailer"] { response.head.remove(name) }
        response.head["Content-Type"] = contentType
        response.head["Content-Length"] = String(length)
        response.head.modifierContentLength = Int64(length)
        response.head["Content-Range"] = contentRange
        response.head["Accept-Ranges"] = "bytes"
    }

    func data(from body: Data) -> Data {
        var result = Data()
        for piece in pieces {
            switch piece {
            case .bytes(let bytes): result.append(bytes)
            case .range(let range): result.append(body.subdata(in: range))
            }
        }
        return result
    }

    private static func describe(_ range: Range<Int>, size: Int) -> String {
        "bytes \(range.lowerBound)-\(range.upperBound - 1)/\(size)"
    }

    private static func parse(_ value: String, size: Int) -> [Range<Int>]? {
        guard value.lowercased().hasPrefix("bytes="), size > 0 else { return nil }
        let fields = value.dropFirst(6).split(separator: ",", omittingEmptySubsequences: false)
        guard !fields.isEmpty, fields.count <= 16 else { return nil }
        var ranges: [Range<Int>] = []
        for field in fields {
            let pair = field.trimmingCharacters(in: .whitespaces)
                .split(separator: "-", omittingEmptySubsequences: false)
            guard pair.count == 2, pair.allSatisfy({ $0.utf8.allSatisfy { (48...57).contains($0) } }) else {
                return nil
            }
            if pair[0].isEmpty {
                guard let suffix = Int(pair[1]), suffix > 0 else { return nil }
                ranges.append(max(0, size - suffix)..<size)
            } else {
                guard let start = Int(pair[0]), let end = pair[1].isEmpty ? size - 1 : Int(pair[1]),
                    end >= start
                else { return nil }
                if start < size { ranges.append(start..<(min(end, size - 1) + 1)) }
            }
        }
        return ranges.isEmpty ? nil : ranges
    }
}
