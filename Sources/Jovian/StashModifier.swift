import Foundation

/// Snapshots the URL at this point in the request chain and echoes that header on the response.
public struct StashModifier: Modifier {
    public let headerName: String

    public init(headerName: String) throws {
        guard HTTPHead.isValidHeader(name: headerName, value: "") else {
            throw ProxyError.invalidHTTP("stash requires a valid headerName")
        }
        self.headerName = headerName
    }

    public func modify(request: inout RequestContext) { request.head[headerName] = request.target }
    public func modify(response: inout ResponseContext) {
        response.head[headerName] = response.requestHead?[headerName] ?? ""
    }
}
