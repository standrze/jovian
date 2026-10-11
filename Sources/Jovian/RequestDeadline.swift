import Foundation
import NIOCore

/// A socket deadline shared by one request's client and upstream channels.
///
/// The lock protects registration racing with the timer; cancellation also wakes paced transfers.
final class RequestDeadline: @unchecked Sendable {
    private let lock = NSLock()
    private var channels: [Channel] = []
    private var expired = false
    private var finished = false
    private var timer: Scheduled<Void>?

    init(client: Channel, seconds: TimeInterval, cancelTask: @escaping @Sendable () -> Void) {
        channels = [client]
        guard seconds > 0 else { return }
        let milliseconds = Int64(min(seconds, 31_536_000) * 1_000)
        timer = client.eventLoop.scheduleTask(in: .milliseconds(milliseconds)) { [weak self] in
            guard let self else { return }
            self.lock.withLock {
                guard !self.finished else { return }
                self.expired = true
                cancelTask()
                for channel in self.channels { channel.close(promise: nil) }
            }
        }
    }

    func add(_ channel: Channel) {
        let shouldClose = lock.withLock {
            if expired { return true }
            channels.append(channel)
            return false
        }
        if shouldClose { channel.close(promise: nil) }
    }

    func finish() {
        lock.withLock {
            finished = true
            channels.removeAll()
            timer?.cancel()
        }
    }
    deinit { timer?.cancel() }
}
