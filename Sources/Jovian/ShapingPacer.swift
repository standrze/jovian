import Foundation

enum TrafficShapingError: Error {
    case forcedClose, recordedClose, cancelled
}

/// One cancellation signal wakes all rate/latency/halt waits owned by a proxy.
final class ShapingCancellation: @unchecked Sendable {
    private let condition = NSCondition()
    private var cancelled = false

    func cancel() {
        condition.lock()
        cancelled = true
        condition.broadcast()
        condition.unlock()
    }

    func wait(until deadline: ContinuousClock.Instant) throws {
        condition.lock()
        defer { condition.unlock() }
        while !cancelled {
            let remaining = ContinuousClock.now.duration(to: deadline)
            if remaining <= .zero { return }
            let parts = remaining.components
            let seconds = Double(parts.seconds) + Double(parts.attoseconds) / 1e18
            _ = condition.wait(until: Date().addingTimeInterval(seconds))
        }
        throw TrafficShapingError.cancelled
    }

    func pause(milliseconds: Int) throws {
        try wait(until: .now.advanced(by: .milliseconds(milliseconds)))
    }
}

/// Strict shared pacing.
///
/// Reservations are atomic; concurrent transfers share one rate budget.
final class ShapingPacer: @unchecked Sendable {
    let rate: Int
    private let lock = NSLock()
    private var deadline = ContinuousClock.now

    init(rate: Int) { self.rate = rate }

    var quantum: Int { max(1, min(16_384, rate / 20)) }

    func reserve(_ bytes: Int, rate override: Int? = nil) -> ContinuousClock.Instant {
        let rate = override ?? self.rate
        guard bytes > 0, rate < TrafficShapePolicy.unlimited else { return .now }
        return lock.withLock {
            let now = ContinuousClock.now
            if deadline < now { deadline = now }
            deadline = deadline.advanced(by: .seconds(Double(bytes) / Double(rate)))
            return deadline
        }
    }
}
