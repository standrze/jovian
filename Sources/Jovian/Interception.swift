import Foundation

/// The interceptor decision to forward a request or return a local response.
public enum InterceptionAction: Sendable {
    case forward(RequestContext)
    case drop(SyntheticResponse)
}

/// Synchronous interception invoked on proxy workers, potentially for concurrent requests.
public protocol RequestInterceptor: Sendable {
    /// Returns the forwarding decision, optionally waiting until the caller releases the request.
    func intercept(_ request: RequestContext) -> InterceptionAction
    /// Wake pending interception and prevent new calls from blocking during shutdown.
    ///
    /// Implementations must support repeated calls from concurrent stopping callers.
    func cancelPending()
}

public extension RequestInterceptor {
    /// Leaves shutdown unchanged for interceptors that never wait.
    func cancelPending() {}
}
