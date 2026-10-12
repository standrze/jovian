import ArgumentParser
import Foundation
import Jovian

struct SessionsCommand: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "sessions", abstract: "Manage bounded origin-scoped sessions.")
    enum Operation: String, ExpressibleByArgument { case list, new, show, close, resume, delete, retention }
    @Argument var operation: Operation = .list
    @Argument var selector: String?
    @Option var origin: String?
    @Option var directory: String?
    @Flag var retainBodies = false

    func run() throws {
        let store = try JovianSessionStore(
            directory: directory.map { URL(fileURLWithPath: $0) } ?? JovianSessionStore.defaultDirectory)
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        encoder.dateEncodingStrategy = .iso8601
        let data: Data
        switch operation {
        case .list: data = try encoder.encode(store.list())
        case .new:
            guard let selector, let origin else { throw ValidationError("sessions new NAME requires --origin URL") }
            data = try encoder.encode(store.create(name: selector, origin: origin, retainBodies: retainBodies))
        default:
            guard let selector else { throw ValidationError("session name or ID required") }
            let session = try store.resolve(selector)
            switch operation {
            case .close: try store.close(session.id)
            case .resume: try store.resume(session.id)
            case .delete: try store.delete(session.id)
            case .retention: try store.setBodyRetention(session.id, enabled: retainBodies)
            default: break
            }
            data =
                operation == .delete
                ? try encoder.encode(["deleted": session.id.uuidString]) : try encoder.encode(store.load(session.id))
        }
        print(String(decoding: data, as: UTF8.self))
    }
}
