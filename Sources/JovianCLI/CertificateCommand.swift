import ArgumentParser
import Foundation
import Jovian

/// Local certificate diagnostics, independent of the proxy listener.
struct CertificateCommand: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "certificate", abstract: "Inspect a local X.509 certificate or PEM bundle.",
        discussion: "Prints certificate metadata as JSON. Trust and TLS connections are not evaluated.")

    @Argument(help: "Path to a DER certificate or PEM certificate bundle.")
    var path: String

    func run() throws {
        let file = URL(fileURLWithPath: path)
        guard try file.resourceValues(forKeys: [.isRegularFileKey]).isRegularFile == true else {
            throw ValidationError("certificate path must be a regular file")
        }
        let handle = try FileHandle(forReadingFrom: file)
        defer { try? handle.close() }
        let data = try handle.read(upToCount: CertificateInspection.maximumInputBytes + 1) ?? Data()
        let inspections = try CertificateInspection.inspect(data)
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        var output = try encoder.encode(inspections)
        output.append(0x0A)
        try FileHandle.standardOutput.write(contentsOf: output)
    }
}
