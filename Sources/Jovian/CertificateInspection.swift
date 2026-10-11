import Crypto
import Foundation
import SwiftASN1
import X509

/// Parsed certificate metadata.
///
/// Inspection does not evaluate signatures, hostname, or trust.
public struct CertificateInspection: Encodable, Equatable, Sendable {
    /// Only the certificate's date interval is considered by this value.
    public enum TimeValidity: String, Codable, Sendable {
        case notYetValid = "not yet valid"
        case withinValidityPeriod = "within validity period"
        case expired
    }

    public let subject: String
    public let issuer: String
    public let serialNumber: String
    public let version: String
    public let signatureAlgorithm: String
    public let publicKey: String
    public let notValidBefore: Date
    public let notValidAfter: Date
    public let inspectedAt: Date
    public let timeValidity: TimeValidity
    public let subjectAlternativeNames: [String]
    public let criticalExtensionOIDs: [String]
    /// Lowercase SHA-256 fingerprint of the original DER certificate bytes.
    public let sha256: String
    public let trust = "not evaluated"

    /// Parses one DER certificate or a PEM certificate bundle in file order.
    ///
    /// Uses Apple's X509 and SwiftASN1 parsers. Rejects empty, oversized, malformed,
    /// and non-certificate input. No network or trust-store operations are performed.
    public static func inspect(_ data: Data, at date: Date = Date()) throws -> [CertificateInspection] {
        guard !data.isEmpty else { throw CertificateInspectionError.emptyInput }
        guard data.count <= maximumInputBytes else { throw CertificateInspectionError.inputTooLarge }

        let documents: [[UInt8]]
        if let text = String(data: data, encoding: .utf8), text.contains("-----BEGIN ") {
            let pemDocuments = try PEMDocument.parseMultiple(pemString: text)
            guard !pemDocuments.isEmpty else { throw CertificateInspectionError.emptyInput }
            guard pemDocuments.allSatisfy({ $0.discriminator == Certificate.defaultPEMDiscriminator }) else {
                throw CertificateInspectionError.nonCertificateDocument
            }
            documents = pemDocuments.map(\.derBytes)
        } else {
            documents = [Array(data)]
        }
        return try documents.map { bytes in
            let certificate = try Certificate(derEncoded: bytes)
            let validity: TimeValidity
            if date < certificate.notValidBefore {
                validity = .notYetValid
            } else if date > certificate.notValidAfter {
                validity = .expired
            } else {
                validity = .withinValidityPeriod
            }
            return try CertificateInspection(
                subject: String(describing: certificate.subject),
                issuer: String(describing: certificate.issuer),
                serialNumber: String(describing: certificate.serialNumber),
                version: String(describing: certificate.version),
                signatureAlgorithm: String(describing: certificate.signatureAlgorithm),
                publicKey: String(describing: certificate.publicKey),
                notValidBefore: certificate.notValidBefore,
                notValidAfter: certificate.notValidAfter,
                inspectedAt: date, timeValidity: validity,
                subjectAlternativeNames: certificate.extensions.subjectAlternativeNames?.map { String(describing: $0) }
                    ?? [],
                criticalExtensionOIDs: certificate.extensions.filter(\.critical).map { String(describing: $0.oid) },
                sha256: SHA256.hash(data: bytes).map { String(format: "%02x", $0) }.joined())
        }
    }

    /// Maximum accepted PEM/DER input size, in bytes, including a whole PEM bundle.
    public static let maximumInputBytes = 1_048_576
}

/// Input boundary failures for local certificate inspection.
public enum CertificateInspectionError: Error, LocalizedError {
    case emptyInput
    case inputTooLarge
    case nonCertificateDocument

    /// A description suitable for reporting a local input failure.
    public var errorDescription: String? {
        switch self {
        case .emptyInput: "certificate input is empty"
        case .inputTooLarge: "certificate input exceeds 1 MiB"
        case .nonCertificateDocument: "expected a PEM bundle containing only certificates"
        }
    }
}
