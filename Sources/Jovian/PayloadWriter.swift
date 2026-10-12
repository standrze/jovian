import Foundation
import NIOCore
import NIOHTTP1

/// Applies shared rates and URL actions to payload offsets while NIO owns HTTP framing.
final class PayloadWriter {
    private let connection: ChannelConnection
    private let upload: Bool
    private let latencyConnection: ChannelConnection
    private let policy: TrafficShapePolicy?
    private let shape: CompiledTrafficShape?
    private let local = ShapingPacer(rate: TrafficShapePolicy.unlimited)
    private var legacy: TransferPacer
    private var offset: Int
    private var actions: [Int]
    private var actionPosition = 0
    private var started = false
    private let capture: StreamingMessageCapture?
    private(set) var bytesSent = 0

    init(
        connection: ChannelConnection, upload: Bool = false, controller: TrafficShapingController?,
        target: String, head: HTTPHead, rate: Int?, capture: StreamingMessageCapture? = nil,
        latencyConnection: ChannelConnection? = nil
    ) throws {
        self.connection = connection
        self.latencyConnection = latencyConnection ?? connection
        self.upload = upload
        self.policy = controller?.snapshot()
        let start = Self.rangeStart(head)
        self.offset = start ?? 0
        self.shape = upload || start == nil ? nil : try policy?.matching(target)
        self.actions = shape?.actionIndices(from: offset) ?? []
        self.legacy = TransferPacer(bytesPerSecond: rate)
        self.capture = capture
    }

    func write(_ data: Data) async throws {
        if !started {
            started = true
            if let delay = policy?.latencyMilliseconds, delay > 0,
                try await latencyConnection.beginShaping(upload: upload)
            {
                try await Task.sleep(for: .milliseconds(delay))
            }
        }
        capture?.append(data)
        var position = data.startIndex
        try await performActions()
        while position < data.endIndex {
            let shared = upload ? policy?.upload : policy?.download
            let limits = shape?.limits(at: offset)
            var count = min(data.endIndex - position, shared?.quantum ?? 16_384)
            if let shape { count = min(count, shape.global.quantum) }
            if let limits {
                count = min(count, max(1, min(16_384, limits.rate / 20)))
                if let boundary = limits.nextBoundary { count = min(count, boundary - offset) }
            }
            if actionPosition < actions.count, let shape {
                count = min(count, shape.actionByte(actions[actionPosition]) - offset)
            }
            guard count > 0 else { throw ProxyError.invalidHTTP("invalid traffic action boundary") }
            var deadline = shared?.reserve(count) ?? .now
            if let shape, let limits {
                deadline = max(deadline, local.reserve(count, rate: limits.rate), shape.global.reserve(count))
            }
            try await ContinuousClock().sleep(until: deadline)
            try await legacy.pace(count)
            let piece = ByteBuffer(bytes: data[position..<(position + count)])
            if upload {
                try await connection.write(HTTPClientRequestPart.body(.byteBuffer(piece)))
            } else {
                try await connection.write(HTTPServerResponsePart.body(.byteBuffer(piece)))
            }
            position += count
            bytesSent += count
            let (next, overflow) = offset.addingReportingOverflow(count)
            guard !overflow else { throw ProxyError.invalidHTTP("traffic offset overflow") }
            offset = next
            try await performActions()
        }
    }

    private func performActions() async throws {
        guard let shape else { return }
        while actionPosition < actions.count, shape.actionByte(actions[actionPosition]) <= offset {
            let index = actions[actionPosition]
            actionPosition += 1
            guard let action = shape.claim(index) else { continue }
            switch action {
            case .halt(let milliseconds): try await Task.sleep(for: .milliseconds(milliseconds))
            case .close:
                connection.close()
                throw TrafficShapingError.forcedClose
            }
        }
    }

    private static func rangeStart(_ head: HTTPHead) -> Int? {
        guard head.startLine.split(separator: " ").dropFirst().first == "206" else { return 0 }
        guard head["Content-Type"]?.lowercased().contains("multipart/byteranges") != true,
            let range = head["Content-Range"], range.hasPrefix("bytes ")
        else { return nil }
        let parts = range.dropFirst(6).split(whereSeparator: { $0 == "-" || $0 == "/" })
        guard parts.count == 3, let start = Int(parts[0]), let end = Int(parts[1]), let total = Int(parts[2]),
            start >= 0, start <= end, end < total
        else { return nil }
        return start
    }
}
