import ArgumentParser
import Foundation
import Jovian

struct CACommand: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "ca", abstract: "Create, inspect, and issue local proxy certificates.")
    enum Operation: String, ExpressibleByArgument { case create, inspect, issue }
    @Argument var operation: Operation
    @Option var directory: String
    @Argument var hostname: String?
    @Option var host: String?

    func run() throws {
        let directory = URL(fileURLWithPath: directory, isDirectory: true)
        switch operation {
        case .create:
            try CertificateAuthority.create(directory: directory)
            print(directory.appendingPathComponent("ca-cert.pem").path)
        case .inspect:
            let authority = try CertificateAuthority(directory: directory)
            print(String(decoding: authority.certificatePEM, as: UTF8.self))
        case .issue:
            guard let host = host ?? hostname else { throw ValidationError("ca issue requires --host") }
            let authority = try CertificateAuthority(directory: directory)
            let identity = try authority.exportIdentity(for: host)
            let destination = directory.appendingPathComponent("hosts", isDirectory: true).appendingPathComponent(
                host, isDirectory: true)
            guard !host.contains("/"), !host.contains("\\"), host != ".", host != ".." else {
                throw ValidationError("invalid host")
            }
            try FileManager.default.createDirectory(
                at: destination, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
            try identity.certificateChainPEM.write(to: destination.appendingPathComponent("cert.pem"), options: .atomic)
            try identity.privateKeyPEM.write(to: destination.appendingPathComponent("key.pem"), options: .atomic)
            try FileManager.default.setAttributes(
                [.posixPermissions: 0o600], ofItemAtPath: destination.appendingPathComponent("key.pem").path)
            print(destination.path)
        }
    }
}
