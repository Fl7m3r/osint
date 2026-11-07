import Foundation

/// Was der Nutzer ins Suchfeld eingegeben hat.
enum TikTokInput: Equatable {
    case username(String)
    case video(username: String?, videoID: String)
    case shortLink(URL)
}

/// Ergebnis der lokalen Formatprüfung – analog zu `check_discord_username` im Python-Tool.
struct UsernameCheck: Equatable {
    let input: String
    let normalized: String
    let length: Int
    let issues: [String]
    var isPlausible: Bool { issues.isEmpty }
}

enum TikTokParser {
    /// Laut TikTok-Hilfe: Buchstaben, Zahlen, Unterstriche und Punkte; kein Punkt am Ende; max. 24 Zeichen.
    static let minLength = 2
    static let maxLength = 24
    private static let allowed = Set("abcdefghijklmnopqrstuvwxyz0123456789_.")

    private static let videoURL = try! NSRegularExpression(
        pattern: #"tiktok\.com/@([A-Za-z0-9_.]+)/(?:video|photo)/(\d{8,25})"#,
        options: [.caseInsensitive]
    )
    private static let profileURL = try! NSRegularExpression(
        pattern: #"tiktok\.com/@([A-Za-z0-9_.]+)"#,
        options: [.caseInsensitive]
    )
    private static let shortHosts = ["vm.tiktok.com", "vt.tiktok.com"]

    static func parse(_ raw: String) -> TikTokInput? {
        let text = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !text.isEmpty else { return nil }

        if let url = URL(string: text.hasPrefix("http") ? text : "https://\(text)"),
           let host = url.host?.lowercased() {
            if shortHosts.contains(host) || (host.hasSuffix("tiktok.com") && url.path.hasPrefix("/t/")) {
                return .shortLink(url)
            }
        }
        if let match = firstMatch(videoURL, in: text), match.count == 2 {
            return .video(username: match[0].lowercased(), videoID: match[1])
        }
        if let match = firstMatch(profileURL, in: text), match.count == 1 {
            return .username(match[0].lowercased())
        }
        if text.count >= 15, text.allSatisfy(\.isNumber) {
            return .video(username: nil, videoID: text)
        }
        let handle = text.hasPrefix("@") ? String(text.dropFirst()) : text
        return .username(handle)
    }

    static func check(_ value: String) -> UsernameCheck {
        let supplied = value.trimmingCharacters(in: .whitespacesAndNewlines)
        let candidate = supplied.hasPrefix("@") ? String(supplied.dropFirst()) : supplied
        let normalized = candidate.lowercased()
        var issues: [String] = []

        if !(minLength...maxLength).contains(candidate.count) {
            issues.append("Länge muss zwischen \(minLength) und \(maxLength) Zeichen liegen (aktuell \(candidate.count)).")
        }
        if !normalized.allSatisfy({ allowed.contains($0) }) {
            issues.append("Nur lateinische Buchstaben, Zahlen, Unterstriche und Punkte sind erlaubt.")
        }
        if normalized.hasSuffix(".") {
            issues.append("Ein Username darf nicht mit einem Punkt enden.")
        }
        return UsernameCheck(input: supplied, normalized: normalized, length: candidate.count, issues: issues)
    }

    /// TikTok-Video-IDs enthalten in den oberen 32 Bit einen Unix-Zeitstempel (Sekunden).
    /// Gleiche Idee wie der Discord-Snowflake-Decoder im Python-Tool.
    static func timestamp(fromVideoID id: String) -> Date? {
        guard let value = UInt64(id) else { return nil }
        let seconds = TimeInterval(value >> 32)
        let date = Date(timeIntervalSince1970: seconds)
        let earliest = Date(timeIntervalSince1970: 1_451_606_400) // 01.01.2016
        guard date > earliest, date < Date().addingTimeInterval(86_400) else { return nil }
        return date
    }

    private static func firstMatch(_ regex: NSRegularExpression, in text: String) -> [String]? {
        let range = NSRange(text.startIndex..., in: text)
        guard let result = regex.firstMatch(in: text, range: range) else { return nil }
        return (1..<result.numberOfRanges).compactMap { index in
            Range(result.range(at: index), in: text).map { String(text[$0]) }
        }
    }
}
