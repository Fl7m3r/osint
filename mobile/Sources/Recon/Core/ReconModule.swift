import SwiftUI

/// Alle Module des FLMP-Sentinel-Tools, wie im Terminal-Menü bzw. Dashboard.
enum ReconModule: String, CaseIterable, Identifiable, Hashable {
    case email, domain, ip, phone, discord, tiktok, scan, config

    var id: String { rawValue }

    var title: String {
        switch self {
        case .email: return "Email Intel"
        case .domain: return "Domain Recon"
        case .ip: return "IP Trace"
        case .phone: return "Phone Intel"
        case .discord: return "Discord Decode"
        case .tiktok: return "TikTok Lookup"
        case .scan: return "Server Scan"
        case .config: return "Config Audit"
        }
    }

    var command: String {
        switch self {
        case .email: return "flmp email"
        case .domain: return "flmp domain"
        case .ip: return "flmp ip"
        case .phone: return "flmp phone"
        case .discord: return "flmp discord"
        case .tiktok: return "flmp tiktok"
        case .scan: return "flmp scan"
        case .config: return "flmp audit-config"
        }
    }

    var icon: String {
        switch self {
        case .email: return "envelope.badge.shield.half.filled"
        case .domain: return "globe.europe.africa"
        case .ip: return "network"
        case .phone: return "phone.connection"
        case .discord: return "number.square"
        case .tiktok: return "music.note"
        case .scan: return "dot.radiowaves.left.and.right"
        case .config: return "doc.text.magnifyingglass"
        }
    }

    var tint: Color {
        switch self {
        case .email: return Theme.cyan
        case .domain: return Theme.mint
        case .ip: return Theme.violet
        case .phone: return Theme.amber
        case .discord: return Color(hex: 0x7289FF)
        case .tiktok: return Theme.red
        case .scan: return Theme.red
        case .config: return Theme.amber
        }
    }

    var placeholder: String {
        switch self {
        case .email: return "name@example.org"
        case .domain: return "example.org"
        case .ip: return "8.8.8.8"
        case .phone: return "+442083661177"
        case .discord: return "123456789012345678"
        case .tiktok: return "@username"
        case .scan: return "203.0.113.10"
        case .config: return "server.cfg wählen"
        }
    }

    var summary: String {
        switch self {
        case .email: return "MX-, SPF- und DMARC-Einträge der Domain. Kein Postfach-Check."
        case .domain: return "A, AAAA, MX, NS, TXT, CAA, SOA + RDAP-Registrar, optional CT-Subdomains (crt.sh)."
        case .ip: return "RDAP-Netzdaten, Reverse-DNS (PTR), optional ungefähre Geo-Lage (ipwho.is)."
        case .phone: return "Offline-Nummernplan: Land, Typ, Formate. Kein Inhaber, kein Standort."
        case .discord: return "Snowflake → Erstellungsdatum, Kontoalter. Username-/Anzeigename-Formatcheck lokal."
        case .tiktok: return "Öffentliches Profil über offizielles oEmbed, Video-ID → Upload-Zeit."
        case .scan: return "TCP-Connect-Check + HTTP/TLS-Header auf eigenem Server. Nur mit Berechtigung."
        case .config: return "Lokaler, read-only Check einer FiveM server.cfg. Geheimnisse werden nie angezeigt."
        }
    }

    /// Automatische Erkennung wie im Dashboard. Ein führendes @ erzwingt einen Username-Check.
    static func detect(_ raw: String) -> ReconModule? {
        let text = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !text.isEmpty else { return nil }
        let lower = text.lowercased()
        if lower.contains("tiktok.com") || text.hasPrefix("@") { return .tiktok }
        if lower.contains("discord.com/users/") || text.hasPrefix("<@") { return .discord }
        if EmailCheck.matches(text) { return .email }
        if IPTools.parse(text) != nil { return .ip }
        if text.hasPrefix("+") { return .phone }
        if (17...20).contains(text.count), text.allSatisfy(\.isNumber) { return .discord }
        if (try? DomainCheck.normalize(text)) != nil { return .domain }
        return nil
    }
}

/// Einstellungen pro Modul.
struct ReconOptions: Equatable {
    var includeCT = false
    var includeGeo = true
    var ports = "80,443,30120,40120"
    var authorized = false
    var discordMode: DiscordMode = .id
    var configText: String?
    var configName: String?

    enum DiscordMode: String, CaseIterable, Identifiable {
        case id = "ID", username = "Username", displayName = "Anzeigename"
        var id: String { rawValue }
    }
}

enum ReconRunner {
    static func run(_ module: ReconModule, input: String, options: ReconOptions) async throws -> Report {
        let value = input.trimmingCharacters(in: .whitespacesAndNewlines)
        switch module {
        case .email: return try await EmailCheck.run(value)
        case .domain: return try await DomainCheck.run(value, includeCT: options.includeCT)
        case .ip: return try await IPCheck.run(value, includeGeo: options.includeGeo)
        case .phone: return try PhoneCheck.run(value)
        case .discord:
            switch options.discordMode {
            case .id: return try DiscordCheck.snowflake(value)
            case .username: return DiscordCheck.username(value)
            case .displayName: return DiscordCheck.displayName(value)
            }
        case .scan:
            guard options.authorized else {
                throw ReconError.input("Bestätige zuerst, dass du dieses System prüfen darfst.")
            }
            return try await ServerScan.run(value, portSpec: options.ports)
        case .config:
            guard let text = options.configText else { throw ReconError.input("Wähle zuerst eine server.cfg aus.") }
            return ConfigAudit.run(text: text, fileName: options.configName ?? "server.cfg")
        case .tiktok:
            throw ReconError.input("TikTok läuft im eigenen Tab.")
        }
    }
}
