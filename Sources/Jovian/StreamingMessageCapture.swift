import Foundation

/// One bounded payload tee shared by all reached log modifiers in a message direction.
///
/// The exchange's worker owns all mutations; each callback runs exactly once.
final class StreamingMessageCapture: @unchecked Sendable {
    private var bytes = Data()
    private var limit = 0
    private var exceeded = false
    private var finished = false
    private var callbacks: [(Data, Bool, Bool) -> Void] = []

    func register(limit: Int, emit: @escaping (Data, Bool, Bool) -> Void) {
        guard !finished else { return }
        self.limit = max(self.limit, limit)
        callbacks.append(emit)
    }

    func append(_ data: Data) {
        guard !finished else { return }
        let available = max(0, limit - bytes.count)
        bytes.append(data.prefix(available))
        if data.count > available { exceeded = true }
    }

    func finish(complete: Bool) {
        guard !finished else { return }
        finished = true
        let pending = callbacks
        callbacks.removeAll()
        for callback in pending { callback(bytes, exceeded, complete) }
        bytes = Data()
    }
}
