import Foundation

/// Martian's /shape-traffic JSON envelope.
///
/// Bandwidths are bytes/second; durations are milliseconds.
public struct TrafficShapingDocument: Codable, Sendable {
    public struct Bandwidth: Codable, Sendable {
        public var up: Int?
        public var down: Int?
    }

    public struct Defaults: Codable, Sendable {
        public var bandwidth: Bandwidth?
        public var latency: Int?
    }

    public struct Throttle: Codable, Sendable {
        public var bytes: String
        public var bandwidth: Int
    }

    public struct Halt: Codable, Sendable {
        public var byte: Int
        public var duration: Int
        public var count: Int
    }

    public struct CloseConnection: Codable, Sendable {
        public var byte: Int
        public var count: Int
    }

    public struct Shape: Codable, Sendable {
        public var urlRegex: String
        public var maxGlobalBandwidth: Int?
        public var throttles: [Throttle]?
        public var halts: [Halt]?
        public var closeConnections: [CloseConnection]?

        enum CodingKeys: String, CodingKey {
            case urlRegex = "url_regex"
            case maxGlobalBandwidth = "max_global_bandwidth"
            case closeConnections = "close_connections"
            case throttles, halts
        }
    }

    public struct Configuration: Codable, Sendable {
        public var defaults: Defaults?
        public var shapes: [Shape]?

        enum CodingKeys: String, CodingKey {
            case defaults = "default"
            case shapes
        }
    }

    public var trafficshape: Configuration
}

/// Atomically replaces traffic policy independently of modifier/verifier configuration.
public final class TrafficShapingController: @unchecked Sendable {
    private let lock = NSLock()
    private var policy = TrafficShapePolicy()
    private var document = Data("{\"trafficshape\":{}}".utf8)
    let cancellation = ShapingCancellation()

    public init() {}

    public func replace(json: Data) throws {
        let parsed = try JSONDecoder().decode(TrafficShapingDocument.self, from: json)
        let next = try TrafficShapePolicy(parsed.trafficshape)
        let normalized = try JSONSerialization.data(
            withJSONObject: JSONSerialization.jsonObject(with: json),
            options: [.sortedKeys])
        lock.withLock {
            policy = next
            document = normalized
        }
    }

    public func encodedConfiguration() -> Data { lock.withLock { document } }

    func snapshot() -> TrafficShapePolicy { lock.withLock { policy } }

    func stop() { cancellation.cancel() }
}

final class TrafficShapePolicy {
    // Martian's default is 500 Gbit/s, represented in this API as bytes/second.
    static let unlimited = 62_500_000_000
    let upload: ShapingPacer
    let download: ShapingPacer
    let latencyMilliseconds: Int
    let shapes: [CompiledTrafficShape]

    init() {
        upload = ShapingPacer(rate: Self.unlimited)
        download = ShapingPacer(rate: Self.unlimited)
        latencyMilliseconds = 0
        shapes = []
    }

    init(_ config: TrafficShapingDocument.Configuration) throws {
        let up = config.defaults?.bandwidth?.up ?? 0
        let down = config.defaults?.bandwidth?.down ?? 0
        let latency = config.defaults?.latency ?? 0
        guard up >= 0, down >= 0, (0...60_000).contains(latency), (config.shapes?.count ?? 0) <= 256 else {
            throw ProxyError.invalidHTTP("invalid traffic shaping defaults or shape count")
        }
        upload = ShapingPacer(rate: up == 0 ? Self.unlimited : up)
        download = ShapingPacer(rate: down == 0 ? Self.unlimited : down)
        latencyMilliseconds = latency
        let sources = config.shapes ?? []
        guard Set(sources.map(\.urlRegex)).count == sources.count else {
            throw ProxyError.invalidHTTP("duplicate traffic shaping URL regex")
        }
        shapes = try sources.map(CompiledTrafficShape.init)
    }

    func matching(_ target: String) throws -> CompiledTrafficShape? {
        for shape in shapes where try shape.matches(target) { return shape }
        return nil
    }
}

final class CompiledTrafficShape {
    struct Interval {
        let start: Int
        let end: Int?
        let rate: Int
    }

    struct Action {
        enum Kind {
            case halt(milliseconds: Int)
            case close
        }
        let byte: Int
        let kind: Kind
        var remaining: Int
    }

    let regex: NSRegularExpression
    let intervals: [Interval]
    let global: ShapingPacer
    private let lock = NSLock()
    private var actions: [Action]

    init(_ shape: TrafficShapingDocument.Shape) throws {
        guard !shape.urlRegex.isEmpty, shape.urlRegex.utf8.count <= 4096,
            (shape.maxGlobalBandwidth ?? 0) >= 0,
            (shape.halts?.count ?? 0) + (shape.closeConnections?.count ?? 0) <= 2048
        else {
            throw ProxyError.invalidHTTP("invalid traffic shape")
        }
        regex = try NSRegularExpression(pattern: shape.urlRegex)
        let rate = shape.maxGlobalBandwidth ?? 0
        global = ShapingPacer(rate: rate == 0 ? TrafficShapePolicy.unlimited : rate)
        intervals = try (shape.throttles ?? []).map { source in
            let parts = source.bytes.split(separator: "-", omittingEmptySubsequences: false)
            guard parts.count == 2, parts.allSatisfy({ $0.allSatisfy(\.isNumber) }), source.bandwidth > 0,
                let start = parts[0].isEmpty ? 0 : Int(parts[0])
            else {
                throw ProxyError.invalidHTTP("invalid traffic throttle byte interval or bandwidth")
            }
            let end = parts[1].isEmpty ? nil : Int(parts[1])
            guard parts[1].isEmpty || (end != nil && end! > start) else {
                throw ProxyError.invalidHTTP("invalid traffic throttle end")
            }
            return Interval(start: start, end: end, rate: source.bandwidth)
        }.sorted { $0.start < $1.start }
        for pair in zip(intervals, intervals.dropFirst()) {
            guard let end = pair.0.end, end <= pair.1.start else {
                throw ProxyError.invalidHTTP("overlapping traffic throttle intervals")
            }
        }
        var actions: [Action] = []
        for halt in shape.halts ?? [] {
            guard halt.byte >= 0, (0...60_000).contains(halt.duration), halt.count == -1 || halt.count > 0 else {
                throw ProxyError.invalidHTTP("invalid traffic halt byte, duration or count")
            }
            actions.append(Action(byte: halt.byte, kind: .halt(milliseconds: halt.duration), remaining: halt.count))
        }
        for close in shape.closeConnections ?? [] {
            guard close.byte >= 0, close.count == -1 || close.count > 0 else {
                throw ProxyError.invalidHTTP("invalid traffic close byte or count")
            }
            actions.append(Action(byte: close.byte, kind: .close, remaining: close.count))
        }
        self.actions = actions.enumerated().sorted {
            $0.element.byte == $1.element.byte ? $0.offset < $1.offset : $0.element.byte < $1.element.byte
        }.map(\.element)
    }

    func matches(_ target: String) throws -> Bool {
        let deadline = ContinuousClock.now.advanced(by: .milliseconds(50))
        var matched = false
        var timedOut = false
        regex.enumerateMatches(in: target, options: [.reportProgress], range: NSRange(target.startIndex..., in: target))
        {
            match, _, stop in
            if ContinuousClock.now >= deadline {
                timedOut = true
                stop.pointee = true
            } else if match != nil {
                matched = true
                stop.pointee = true
            }
        }
        if timedOut { throw ProxyError.invalidHTTP("traffic shape regex exceeded its time budget") }
        return matched
    }

    func limits(at offset: Int) -> (rate: Int, nextBoundary: Int?) {
        var rate = global.rate
        var next: Int?
        for interval in intervals {
            if interval.start > offset {
                next = interval.start
                break
            }
            if interval.end == nil || interval.end! > offset {
                rate = interval.rate
                next = interval.end
                break
            }
        }
        return (rate, next)
    }

    func actionIndices(from offset: Int) -> [Int] {
        lock.withLock { actions.indices.filter { actions[$0].byte >= offset } }
    }

    func actionByte(_ index: Int) -> Int { lock.withLock { actions[index].byte } }

    func claim(_ index: Int) -> Action.Kind? {
        lock.withLock {
            guard actions[index].remaining != 0 else { return nil }
            if actions[index].remaining > 0 { actions[index].remaining -= 1 }
            return actions[index].kind
        }
    }
}
