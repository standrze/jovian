import Foundation

/// Basic credentials consumed at the proxy boundary and never forwarded to an origin.
public struct ProxyCredentials: Sendable {
    public let username: String
    public let password: String

    /// Store credentials for constant-time comparison of the decoded authorization bytes.
    public init(username: String, password: String) {
        self.username = username
        self.password = password
    }

    func authorizes(_ head: HTTPHead) -> Bool {
        guard let value = head["Proxy-Authorization"] else { return false }
        let pieces = value.split(separator: " ", maxSplits: 1).map(String.init)
        guard pieces.count == 2, pieces[0].caseInsensitiveCompare("Basic") == .orderedSame,
            let decoded = Data(base64Encoded: pieces[1])
        else { return false }
        return Self.constantTimeEqual(decoded, Data("\(username):\(password)".utf8))
    }

    private static func constantTimeEqual(_ left: Data, _ right: Data) -> Bool {
        let count = max(left.count, right.count)
        var difference = left.count ^ right.count
        for index in 0..<count {
            let lhs = index < left.count ? left[index] : 0
            let rhs = index < right.count ? right[index] : 0
            difference |= Int(lhs ^ rhs)
        }
        return difference == 0
    }
}

/// Per-direction pacing suspends its transfer task instead of sleeping on a NIO event loop.
struct TransferPacer {
    private let bytesPerSecond: Int?
    private var deadline = ContinuousClock.now

    init(bytesPerSecond: Int?) {
        self.bytesPerSecond = bytesPerSecond.flatMap { $0 > 0 ? $0 : nil }
    }

    mutating func pace(_ bytes: Int) async throws {
        guard let bytesPerSecond, bytes > 0 else { return }
        let now = ContinuousClock.now
        if deadline < now { deadline = now }
        let nanoseconds = Int64((Double(bytes) / Double(bytesPerSecond)) * 1_000_000_000)
        deadline += .nanoseconds(nanoseconds)
        try await ContinuousClock().sleep(until: deadline)
    }
}
