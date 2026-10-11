import Foundation
import Testing

@testable import JovianCLI

@Test func certificateSubcommandAcceptsOneLocalPath() throws {
    let command = try JovianCommand.parseAsRoot(["certificate", "/fixture/local certificate.pem"])
    let options = try #require(command as? CertificateCommand)
    #expect(options.path == "/fixture/local certificate.pem")

    let escapedOption = try CertificateCommand.parse(["--", "-local.der"])
    #expect(escapedOption.path == "-local.der")
}

@Test func certificateSubcommandRejectsMissingExtraAndUnknownArguments() {
    for arguments in [[], ["first.pem", "second.pem"], ["--unknown", "fixture.pem"], ["--port", "8080"]] {
        #expect(throws: (any Error).self) { try CertificateCommand.parse(arguments) }
    }
}

@Test func certificateSubcommandRejectsDirectoriesBeforeReading() throws {
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
    defer { try? FileManager.default.removeItem(at: directory) }
    let command = try CertificateCommand.parse([directory.path])
    #expect(throws: (any Error).self) { try command.run() }
}

@Test func certificateSubcommandReportsMissingFiles() throws {
    let absent = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    let command = try CertificateCommand.parse([absent.path])
    #expect(throws: (any Error).self) { try command.run() }
}
