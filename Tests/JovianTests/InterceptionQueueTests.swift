import XCTest

@testable import Jovian

final class InterceptionQueueTests: XCTestCase {
    private func request() -> RequestContext {
        RequestContext(
            method: "GET", target: "http://localhost/original",
            head: HTTPHead(startLine: "GET /original HTTP/1.1"))
    }
    private func waitForPending(_ queue: RequestInterceptionQueue) throws -> HeldRequest {
        let deadline = Date().addingTimeInterval(2)
        while Date() < deadline {
            if let held = queue.pending().first { return held }
            Thread.sleep(forTimeInterval: 0.005)
        }
        throw NSError(domain: "InterceptionQueueTests", code: 1)
    }
    func testDefaultPassThrough() {
        let queue = RequestInterceptionQueue()
        XCTAssertFalse(queue.isEnabled)
        guard case .forward(let forwarded) = queue.intercept(request()) else {
            return XCTFail("Default should forward")
        }
        XCTAssertEqual(forwarded.target, "http://localhost/original")
        XCTAssertTrue(queue.pending().isEmpty)
    }
    func testEditAndForwardRejectStaleRevision() throws {
        let queue = RequestInterceptionQueue()
        queue.setEnabled(true)
        let original = request()
        let finished = expectation(description: "forwarded")
        DispatchQueue.global().async {
            guard case .forward(let forwarded) = queue.intercept(original) else {
                XCTFail("Expected forward")
                finished.fulfill()
                return
            }
            XCTAssertEqual(forwarded.method, "POST")
            XCTAssertEqual(forwarded.target, "http://localhost/edited")
            XCTAssertEqual(forwarded.body, Data("changed".utf8))
            finished.fulfill()
        }
        defer { queue.cancelPending() }
        let held = try waitForPending(queue)
        try queue.edit(
            id: held.id, revision: 0, method: "POST", url: "http://localhost/edited", body: Data("changed".utf8))
        XCTAssertThrowsError(try queue.decide(id: held.id, revision: 0, forward: true))
        try queue.decide(id: held.id, revision: 1, forward: true)
        XCTAssertThrowsError(try queue.decide(id: held.id, revision: 1, forward: true))
        wait(for: [finished], timeout: 2)
    }
    func testToggleOffReleasesCurrentDraft() throws {
        let queue = RequestInterceptionQueue()
        queue.setEnabled(true)
        let original = request()
        let finished = expectation(description: "released")
        DispatchQueue.global().async {
            if case .forward(let forwarded) = queue.intercept(original) {
                XCTAssertEqual(forwarded.target, "http://localhost/edited")
            } else {
                XCTFail("Expected forward")
            }
            finished.fulfill()
        }
        defer { queue.cancelPending() }
        let held = try waitForPending(queue)
        try queue.edit(id: held.id, revision: held.revision, url: "http://localhost/edited")
        queue.setEnabled(false)
        wait(for: [finished], timeout: 2)
        XCTAssertFalse(queue.isEnabled)
    }
    func testTimeoutDrops() {
        let queue = RequestInterceptionQueue(timeout: 0.05)
        queue.setEnabled(true)
        guard case .drop(let response) = queue.intercept(request()) else { return XCTFail("Expected timeout") }
        XCTAssertEqual(response.statusCode, 504)
        XCTAssertTrue(queue.pending().isEmpty)
    }
    func testCancellationDrops() throws {
        let queue = RequestInterceptionQueue()
        queue.setEnabled(true)
        let original = request()
        let finished = expectation(description: "cancelled")
        DispatchQueue.global().async {
            if case .drop(let response) = queue.intercept(original) {
                XCTAssertEqual(response.statusCode, 499)
            } else {
                XCTFail("Expected drop")
            }
            finished.fulfill()
        }
        defer { queue.cancelPending() }
        let held = try waitForPending(queue)
        queue.cancel(held.id)
        wait(for: [finished], timeout: 2)
    }
}
