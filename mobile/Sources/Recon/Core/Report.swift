import Foundation
import SwiftUI

/// Einheitliches Ergebnis aller Recon-Module. Die Oberfläche (ReportView) rendert nur dieses Modell.
enum Tone: Equatable {
    case normal, good, warn, bad, accent

    var color: Color {
        switch self {
        case .normal: return Theme.text
        case .good: return Theme.mint
        case .warn: return Theme.amber
        case .bad: return Theme.red
        case .accent: return Theme.cyan
        }
    }
}

struct ReportRow: Identifiable, Equatable {
    let id = UUID()
    let key: String
    let value: String
    var tone: Tone = .normal
}

struct ReportSection: Identifiable, Equatable {
    let id = UUID()
    let title: String
    let icon: String
    var rows: [ReportRow] = []
    var list: [String] = []
    var listLimit = 60
}

struct Finding: Identifiable, Equatable {
    let id = UUID()
    let level: String      // HIGH, REVIEW, INFO, OK
    let title: String
    let detail: String
    let fix: String

    var tone: Tone {
        switch level {
        case "HIGH": return .bad
        case "REVIEW": return .warn
        case "OK": return .good
        default: return .accent
        }
    }
}

struct ReportLink: Identifiable, Equatable {
    let id = UUID()
    let title: String
    let url: URL
}

struct Report: Identifiable, Equatable {
    let id = UUID()
    let module: ReconModule
    let target: String
    let status: String
    let statusTone: Tone
    var sections: [ReportSection] = []
    var findings: [Finding] = []
    var notes: [String] = []
    var links: [ReportLink] = []
    var json: String = "{}"
}

enum ReconError: LocalizedError {
    case input(String)
    case service(String)

    var errorDescription: String? {
        switch self {
        case .input(let message), .service(let message): return message
        }
    }
}

enum JSON {
    static func string(_ object: [String: Any]) -> String {
        guard JSONSerialization.isValidJSONObject(object),
              let data = try? JSONSerialization.data(withJSONObject: object, options: [.prettyPrinted, .sortedKeys]),
              let text = String(data: data, encoding: .utf8) else { return "{}" }
        return text
    }

    /// Optionalen Wert JSON-tauglich machen (nil → null).
    static func v(_ value: Any?) -> Any { value ?? NSNull() }

    static let iso: ISO8601DateFormatter = {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime]
        return formatter
    }()

    /// Liest ISO-Datumsangaben aus RDAP (mit oder ohne Sekundenbruchteile).
    static func date(_ text: String?) -> Date? {
        guard let text else { return nil }
        if let date = iso.date(from: text) { return date }
        let fractional = ISO8601DateFormatter()
        fractional.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return fractional.date(from: text)
    }

    static func short(_ text: String?) -> String {
        guard let date = date(text) else { return text ?? "—" }
        return date.formatted(date: .abbreviated, time: .omitted)
    }
}
