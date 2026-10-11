import Crypto
import Foundation
import Jovian
import SwiftASN1
import Testing
import X509

@Suite("local certificate inspection")
struct CertificateInspectionTests {
    @Test func pemAndDERProduceTheSameMetadataAndFingerprint() throws {
        let fixture = try LocalCertificate()
        let pem = try CertificateInspection.inspect(fixture.pemData, at: LocalCertificate.referenceDate)
        let der = try CertificateInspection.inspect(fixture.derData, at: LocalCertificate.referenceDate)
        let inspection = try #require(der.first)

        #expect(pem == der)
        #expect(der.count == 1)
        #expect(inspection.subject == "CN=localhost")
        #expect(inspection.issuer == "CN=localhost")
        #expect(inspection.serialNumber == "1")
        #expect(inspection.version == "X509v3")
        #expect(inspection.signatureAlgorithm == "SignatureAlgorithm.ecdsaWithSHA256")
        #expect(inspection.publicKey == "P256.PublicKey")
        #expect(inspection.notValidBefore == LocalCertificate.notBefore)
        #expect(inspection.notValidAfter == LocalCertificate.notAfter)
        #expect(inspection.inspectedAt == LocalCertificate.referenceDate)
        #expect(inspection.subjectAlternativeNames == ["DNSName(\"localhost\")"])
        #expect(inspection.criticalExtensionOIDs == ["2.5.29.19"])
        #expect(inspection.sha256 == SHA256.hash(data: fixture.derData).map { String(format: "%02x", $0) }.joined())
        #expect(inspection.sha256.count == 64)
        #expect(inspection.trust == "not evaluated")
    }

    @Test func pemBundlePreservesCertificateOrder() throws {
        let first = try LocalCertificate(commonName: "first.localhost", serial: 1)
        let second = try LocalCertificate(commonName: "second.localhost", serial: 2)
        let bundle = first.pemData + Data("\n\n".utf8) + second.pemData
        let inspections = try CertificateInspection.inspect(bundle, at: LocalCertificate.referenceDate)

        #expect(inspections.map(\.subject) == ["CN=first.localhost", "CN=second.localhost"])
        #expect(inspections.map(\.serialNumber) == ["1", "2"])
        try #require(inspections.count == 2)
        #expect(inspections[0].sha256 != inspections[1].sha256)
    }

    @Test func validityIncludesBothBoundariesWithoutClaimingTrust() throws {
        let fixture = try LocalCertificate()
        let cases: [(Date, CertificateInspection.TimeValidity)] = [
            (LocalCertificate.notBefore.addingTimeInterval(-1), .notYetValid),
            (LocalCertificate.notBefore, .withinValidityPeriod),
            (LocalCertificate.referenceDate, .withinValidityPeriod),
            (LocalCertificate.notAfter, .withinValidityPeriod),
            (LocalCertificate.notAfter.addingTimeInterval(1), .expired),
        ]
        for (date, expected) in cases {
            let inspection = try #require(try CertificateInspection.inspect(fixture.derData, at: date).first)
            #expect(inspection.timeValidity == expected)
            #expect(inspection.inspectedAt == date)
            #expect(inspection.trust == "not evaluated")
        }
    }

    @Test func emptyAndOversizedInputsFailBeforeParsing() {
        #expect(throws: CertificateInspectionError.self) {
            try CertificateInspection.inspect(Data())
        }
        #expect(throws: CertificateInspectionError.self) {
            try CertificateInspection.inspect(Data(repeating: 0, count: CertificateInspection.maximumInputBytes + 1))
        }
    }

    @Test func malformedCertificatesAreRejected() throws {
        let fixture = try LocalCertificate()
        let malformedPEM = "-----BEGIN CERTIFICATE-----\nnot base64\n-----END CERTIFICATE-----"
        let unterminatedPEM = "-----BEGIN CERTIFICATE-----\nAA=="
        let nonCertificateDER = Data([0x30, 0x00])
        for input in [
            Data("not a certificate".utf8), Data(malformedPEM.utf8), Data(unterminatedPEM.utf8),
            nonCertificateDER, Data(fixture.derData.dropLast()), fixture.derData + Data([0]),
        ] {
            #expect(throws: (any Error).self) { try CertificateInspection.inspect(input) }
        }
    }

    @Test func nonCertificatePEMIsRejectedEvenInsideACertificateBundle() throws {
        let fixture = try LocalCertificate()
        let otherDocument = PEMDocument(type: "PUBLIC KEY", derBytes: [0x30, 0x00])
        let otherData = Data(otherDocument.pemString.utf8)
        for input in [otherData, fixture.pemData + Data("\n".utf8) + otherData] {
            #expect(throws: CertificateInspectionError.self) {
                try CertificateInspection.inspect(input)
            }
        }
    }

    @Test func certificateNamesRemainSafeJSONData() throws {
        let fixture = try LocalCertificate(commonName: "localhost\tfixture\n\u{001B}")
        let inspection = try #require(
            try CertificateInspection.inspect(fixture.derData, at: LocalCertificate.referenceDate).first)
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        let encoded = try encoder.encode(inspection)
        let object = try #require(try JSONSerialization.jsonObject(with: encoded) as? [String: Any])

        #expect(!encoded.contains { $0 < 0x20 })
        #expect(object["subject"] as? String == inspection.subject)
        #expect(object["trust"] as? String == "not evaluated")
        #expect(object["timeValidity"] as? String == "within validity period")
        #expect(object["inspectedAt"] as? String == "2026-01-01T01:00:00Z")
    }
}

/// Synthetic localhost certificates generated in memory; no trust stores or external services are used.
private struct LocalCertificate {
    static let notBefore = Date(timeIntervalSince1970: 1_767_225_600)
    static let referenceDate = notBefore.addingTimeInterval(3600)
    static let notAfter = notBefore.addingTimeInterval(7200)

    let pemData: Data
    let derData: Data

    init(commonName: String = "localhost", serial: UInt8 = 1) throws {
        let key = P256.Signing.PrivateKey()
        let name = try DistinguishedName { CommonName(commonName) }
        let certificate = try Certificate(
            version: .v3, serialNumber: .init(bytes: [serial]), publicKey: .init(key.publicKey),
            notValidBefore: Self.notBefore, notValidAfter: Self.notAfter, issuer: name, subject: name,
            signatureAlgorithm: .ecdsaWithSHA256,
            extensions: Certificate.Extensions {
                Critical(BasicConstraints.notCertificateAuthority)
                SubjectAlternativeNames([.dnsName("localhost")])
            }, issuerPrivateKey: .init(key))
        let pem = try certificate.serializeAsPEM()
        pemData = Data(pem.pemString.utf8)
        derData = Data(pem.derBytes)
    }
}
