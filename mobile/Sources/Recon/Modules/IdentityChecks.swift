import Foundation
import Network
import PhoneNumberKit

// MARK: - IP-Hilfen

enum IPTools {
    enum Address {
        case v4([UInt8])
        case v6([UInt8])

        var bytes: [UInt8] {
            switch self { case .v4(let b), .v6(let b): return b }
        }
    }

    static func parse(_ text: String) -> Address? {
        let value = text.trimmingCharacters(in: .whitespacesAndNewlines)
        if let v4 = IPv4Address(value), value.contains(".") { return .v4([UInt8](v4.rawValue)) }
        if let v6 = IPv6Address(value), value.contains(":") { return .v6([UInt8](v6.rawValue)) }
        return nil
    }

    /// Wie `ipaddress.is_global`: private, Loopback, Link-Local, CGNAT, Multicast usw. sind ausgeschlossen.
    static func isGlobal(_ address: Address) -> Bool {
        switch address {
        case .v4(let b):
            if b[0] == 0 || b[0] == 10 || b[0] == 127 || b[0] >= 224 { return false }
            if b[0] == 100 && (64...127).contains(b[1]) { return false }
            if b[0] == 169 && b[1] == 254 { return false }
            if b[0] == 172 && (16...31).contains(b[1]) { return false }
            if b[0] == 192 && b[1] == 168 { return false }
            if b[0] == 192 && b[1] == 0 && (b[2] == 0 || b[2] == 2) { return false }
            if b[0] == 198 && (b[1] == 18 || b[1] == 19) { return false }
            if b[0] == 198 && b[1] == 51 && b[2] == 100 { return false }
            if b[0] == 203 && b[1] == 0 && b[2] == 113 { return false }
            return true
        case .v6(let b):
            if b.allSatisfy({ $0 == 0 }) { return false }                       // ::
            if b.dropLast().allSatisfy({ $0 == 0 }) && b[15] == 1 { return false } // ::1
            if b[0] & 0xFE == 0xFC { return false }                              // fc00::/7
            if b[0] == 0xFE && b[1] & 0xC0 == 0x80 { return false }              // fe80::/10
            if b[0] == 0xFF { return false }                                     // Multicast
            if b[0] == 0x20 && b[1] == 0x01 && b[2] == 0x0D && b[3] == 0xB8 { return false } // Doku
            return true
        }
    }

    static func string(_ address: Address) -> String {
        switch address {
        case .v4(let b):
            return b.map(String.init).joined(separator: ".")
        case .v6:
            return IPv6Address(Data(address.bytes)).map { "\($0)" } ?? "?"
        }
    }

    static func reversePointer(_ address: Address) -> String {
        switch address {
        case .v4(let b):
            return b.reversed().map(String.init).joined(separator: ".") + ".in-addr.arpa"
        case .v6(let b):
            let nibbles = b.flatMap { [String($0 >> 4, radix: 16), String($0 & 0x0F, radix: 16)] }
            return nibbles.reversed().joined(separator: ".") + ".ip6.arpa"
        }
    }
}

// MARK: - IP (Port von check_ip)

enum IPCheck {
    static func run(_ value: String, includeGeo: Bool) async throws -> Report {
        guard let address = IPTools.parse(value) else { throw ReconError.input("Ungültige IP-Adresse.") }
        guard IPTools.isGlobal(address) else {
            throw ReconError.input("Nur öffentlich routbare IP-Adressen können abgefragt werden.")
        }
        let ip = IPTools.string(address)
        let encoded = Net.encode(ip)

        async let rdapLookup = Net.object(URL(string: "https://rdap.org/ip/\(encoded)")!)
        async let ptrLookup = DNS.query(IPTools.reversePointer(address), .PTR)
        let rdap = try await rdapLookup
        let ptr = await ptrLookup

        var entities: [[String: Any]] = []
        var entityLines: [String] = []
        for case let entity as [String: Any] in rdap["entities"] as? [Any] ?? [] {
            let roles = entity["roles"] as? [String] ?? []
            let name = DomainCheck.vcardName(entity)
            if name != nil || !roles.isEmpty {
                var item: [String: Any] = ["roles": roles]
                item["name"] = name
                entities.append(item)
                entityLines.append("\(name ?? "—")  [\(roles.joined(separator: ", "))]")
            }
        }

        var report = Report(module: .ip, target: ip, status: "NETWORK IDENTIFIED", statusTone: .good)
        report.sections = [
            ReportSection(title: "RDAP Network", icon: "building.2", rows: [
                ReportRow(key: "Netz", value: rdap["name"] as? String ?? "—", tone: .accent),
                ReportRow(key: "Bereich", value: "\(rdap["startAddress"] as? String ?? "?") – \(rdap["endAddress"] as? String ?? "?")"),
                ReportRow(key: "Handle", value: rdap["handle"] as? String ?? "—"),
                ReportRow(key: "Land", value: rdap["country"] as? String ?? "—"),
                ReportRow(key: "Version", value: { () -> String in if case .v4 = address { return "IPv4" } else { return "IPv6" } }())
            ], list: entityLines),
            ReportSection(title: "Reverse DNS (PTR)", icon: "arrow.uturn.left",
                          list: { () -> [String] in switch ptr {
                              case .records(let values): return values.isEmpty ? ["(kein PTR)"] : values
                              case .nxdomain: return ["(kein PTR)"]
                              case .error(let message): return ["! \(message)"]
                          } }())
        ]

        var json: [String: Any] = [
            "input": ip,
            "reverse_dns_ptr": ptr.values,
            "rdap": [
                "network_name": JSON.v(rdap["name"]),
                "start_address": JSON.v(rdap["startAddress"]),
                "end_address": JSON.v(rdap["endAddress"]),
                "handle": JSON.v(rdap["handle"]),
                "country": JSON.v(rdap["country"]),
                "entities": entities,
                "source": "https://rdap.org"
            ] as [String: Any],
            "scope_note": "RDAP network data does not identify an end user."
        ]

        if includeGeo {
            do {
                let geo = try await Net.object(URL(string: "https://ipwho.is/\(encoded)")!)
                if geo["success"] as? Bool == false {
                    let message = geo["message"] as? String ?? "nicht verfügbar"
                    report.sections.append(ReportSection(title: "Geo", icon: "location", rows: [ReportRow(key: "Status", value: message, tone: .warn)]))
                    json["geolocation"] = ["status": "unavailable", "message": message]
                } else {
                    let connection = geo["connection"] as? [String: Any] ?? [:]
                    let lat = geo["latitude"] as? Double
                    let lon = geo["longitude"] as? Double
                    report.sections.append(ReportSection(title: "Geo (ungefähr)", icon: "location.viewfinder", rows: [
                        ReportRow(key: "Land", value: geo["country"] as? String ?? "—", tone: .accent),
                        ReportRow(key: "Region", value: geo["region"] as? String ?? "—"),
                        ReportRow(key: "Stadt", value: geo["city"] as? String ?? "—"),
                        ReportRow(key: "Koordinaten", value: lat.map { String(format: "%.3f, %.3f", $0, lon ?? 0) } ?? "—"),
                        ReportRow(key: "ASN", value: (connection["asn"]).map { "AS\($0)" } ?? "—"),
                        ReportRow(key: "ISP", value: connection["isp"] as? String ?? "—")
                    ]))
                    json["geolocation"] = [
                        "status": "available",
                        "country": JSON.v(geo["country"]),
                        "region": JSON.v(geo["region"]),
                        "city": JSON.v(geo["city"]),
                        "latitude": JSON.v(lat),
                        "longitude": JSON.v(lon),
                        "asn": JSON.v(connection["asn"]),
                        "isp": JSON.v(connection["isp"]),
                        "source": "https://ipwho.is"
                    ] as [String: Any]
                    report.notes.append("Geo-Daten sind ungefähr und zeigen evtl. nur einen VPN- oder Proxy-Ausgang.")
                }
            } catch {
                report.sections.append(ReportSection(title: "Geo", icon: "location", rows: [ReportRow(key: "ipwho.is", value: error.localizedDescription, tone: .warn)]))
            }
        }
        report.notes.insert("RDAP-Netzdaten identifizieren keinen Endnutzer.", at: 0)
        report.json = JSON.string(json)
        return report
    }
}

// MARK: - Telefon (Port von check_phone_number, Offline-Metadaten via PhoneNumberKit)

enum PhoneCheck {
    private static let kit = PhoneNumberKit()

    static func run(_ value: String) throws -> Report {
        let text = value.trimmingCharacters(in: .whitespacesAndNewlines)
        guard text.hasPrefix("+") else {
            throw ReconError.input("Internationales Format mit + und Ländervorwahl verwenden, z. B. +442083661177.")
        }
        var valid = true
        let number: PhoneNumber
        do {
            number = try kit.parse(text)
        } catch {
            valid = false
            do {
                number = try kit.parse(text, ignoreType: true)
            } catch {
                throw ReconError.input("Nummer konnte nicht gelesen werden.")
            }
        }
        let region = kit.getRegionCode(of: number) ?? "unknown"
        let type = valid ? "\(number.type)" : "unknown"
        let international = kit.format(number, toType: .international)
        let e164 = kit.format(number, toType: .e164)
        let countryName = Locale.current.localizedString(forRegionCode: region) ?? region

        var report = Report(module: .phone, target: text,
                            status: valid ? "VALID NUMBERING PLAN" : "POSSIBLE / UNVERIFIED",
                            statusTone: valid ? .good : .warn)
        report.sections = [
            ReportSection(title: "Number", icon: "phone", rows: [
                ReportRow(key: "International", value: international, tone: .accent),
                ReportRow(key: "E.164", value: e164),
                ReportRow(key: "Ländervorwahl", value: "+\(number.countryCode)"),
                ReportRow(key: "Region", value: "\(countryName) (\(region))"),
                ReportRow(key: "Typ", value: type),
                ReportRow(key: "Nummernplan", value: valid ? "passt" : "passt nicht sicher", tone: valid ? .good : .warn)
            ])
        ]
        report.notes = ["Nur Offline-Nummernplan. Nicht geprüft: ob die Nummer aktiv ist, wem sie gehört, aktueller Anbieter oder Standort."]
        report.json = JSON.string([
            "input": text,
            "international_format": international,
            "e164_format": e164,
            "country_calling_code": Int(number.countryCode),
            "numbering_region": region,
            "valid_numbering_plan_match": valid,
            "number_type": type,
            "scope_note": "Offline numbering-plan metadata only."
        ])
        return report
    }
}

// MARK: - Discord (Port von check_discord_id, check_discord_username, check_discord_display_name)

enum DiscordCheck {
    static let epochMS: UInt64 = 1_420_070_400_000
    private static let idPattern = try! NSRegularExpression(
        pattern: #"^(?:<@!?(\d{17,20})>|(?:https?://)?(?:www\.)?discord\.com/users/(\d{17,20})/?|(\d{17,20}))$"#,
        options: [.caseInsensitive]
    )
    private static let usernameAllowed = Set("abcdefghijklmnopqrstuvwxyz0123456789_.")

    static func snowflake(_ value: String) throws -> Report {
        let text = value.trimmingCharacters(in: .whitespacesAndNewlines)
        let range = NSRange(text.startIndex..., in: text)
        guard let match = idPattern.firstMatch(in: text, range: range),
              let idString = (1...3).compactMap({ (group: Int) -> String? in
                  guard let r = Range(match.range(at: group), in: text) else { return nil }
                  return String(text[r])
              }).first else {
            throw ReconError.input("Discord-ID, Erwähnung (<@ID>) oder discord.com/users/<ID> eingeben.")
        }
        guard let id = UInt64(idString) else { throw ReconError.input("ID liegt außerhalb des gültigen Snowflake-Bereichs.") }
        let timestampPart = id >> 22
        let created = Date(timeIntervalSince1970: Double(timestampPart + epochMS) / 1000)
        guard created <= Date().addingTimeInterval(300) else {
            throw ReconError.input("Die ID enthält einen Zeitstempel in der Zukunft – ID prüfen.")
        }
        let ageDays = max(0, Calendar.current.dateComponents([.day], from: created, to: Date()).day ?? 0)
        let format = text.hasPrefix("<@") ? "mention" : text.lowercased().contains("discord.com/users/") ? "profile_url" : "numeric_id"

        var report = Report(module: .discord, target: idString, status: "SNOWFLAKE DECODED", statusTone: .good)
        report.sections = [
            ReportSection(title: "Account Timestamp", icon: "clock.badge.checkmark", rows: [
                ReportRow(key: "Erstellt (UTC)", value: JSON.iso.string(from: created), tone: .accent),
                ReportRow(key: "Erstellt", value: created.formatted(date: .long, time: .shortened)),
                ReportRow(key: "Kontoalter", value: "\(ageDays) Tage", tone: .good),
                ReportRow(key: "Eingabe", value: format)
            ]),
            ReportSection(title: "Snowflake Bits", icon: "cpu", rows: [
                ReportRow(key: "Timestamp (ms)", value: "\(timestampPart)"),
                ReportRow(key: "Worker", value: "\((id >> 17) & 0x1F)"),
                ReportRow(key: "Process", value: "\((id >> 12) & 0x1F)"),
                ReportRow(key: "Increment", value: "\(id & 0xFFF)")
            ])
        ]
        report.links = [
            ReportLink(title: "Profil-URL", url: URL(string: "https://discord.com/users/\(idString)")!),
            ReportLink(title: "Discord: Username-Regeln", url: URL(string: "https://support.discord.com/hc/en-us/articles/12620128861463-New-Usernames-and-Display-Names")!),
            ReportLink(title: "Discord: Datenpaket (für Kontoinhaber)", url: URL(string: "https://support.discord.com/hc/en-us/articles/360004957991-Your-Discord-Data-Package")!)
        ]
        report.notes = ["Snowflake-Felder sind technische ID-Metadaten. Sie bestätigen kein aktives Konto und identifizieren keine Person; E-Mail, IP, Nachrichten oder Server bleiben unbekannt."]
        report.json = JSON.string([
            "discord_id": idString,
            "input_format": format,
            "account_created_utc": JSON.iso.string(from: created),
            "account_age_days": ageDays,
            "snowflake_metadata": [
                "timestamp_ms_since_discord_epoch": timestampPart,
                "worker_id": (id >> 17) & 0x1F,
                "process_id": (id >> 12) & 0x1F,
                "increment": id & 0xFFF
            ] as [String: Any],
            "profile_url": "https://discord.com/users/\(idString)"
        ])
        return report
    }

    static func username(_ value: String) -> Report {
        let supplied = value.trimmingCharacters(in: .whitespacesAndNewlines)
        let candidate = supplied.hasPrefix("@") ? String(supplied.dropFirst()) : supplied
        let normalized = candidate.lowercased()
        var issues: [String] = []
        if !(2...32).contains(candidate.count) { issues.append("Länge muss zwischen 2 und 32 Zeichen liegen.") }
        let allowed = !normalized.isEmpty && normalized.allSatisfy { usernameAllowed.contains($0) }
        if !allowed { issues.append("Nur lateinische Buchstaben, Zahlen, Punkte und Unterstriche.") }
        if normalized.contains("..") { issues.append("Zwei Punkte hintereinander sind nicht erlaubt.") }

        var report = Report(module: .discord, target: supplied,
                            status: issues.isEmpty ? "FORMAT PLAUSIBLE" : "FORMAT INVALID",
                            statusTone: issues.isEmpty ? .good : .bad)
        report.sections = [ReportSection(title: "Username Format", icon: "textformat", rows: [
            ReportRow(key: "Normalisiert", value: normalized, tone: .accent),
            ReportRow(key: "Länge", value: "\(candidate.count) / 32"),
            ReportRow(key: "Zeichen", value: allowed ? "erlaubt" : "unzulässig", tone: allowed ? .good : .bad)
        ], list: issues.isEmpty ? ["[OK] Entspricht den Discord-Regeln"] : issues.map { "[!!] " + $0 })]
        report.notes = ["Nur lokaler Formatcheck. Keine Discord-Anfrage, keine Suche, keine plattformübergreifende Zuordnung."]
        report.json = JSON.string([
            "input": supplied,
            "normalized_handle": normalized,
            "length": candidate.count,
            "format_status": issues.isEmpty ? "plausible" : "invalid",
            "format_issues": issues,
            "availability": "not checked"
        ])
        return report
    }

    static func displayName(_ value: String) -> Report {
        let normalized = value.trimmingCharacters(in: .whitespacesAndNewlines).precomposedStringWithCanonicalMapping
        var issues: [String] = []
        if !(1...32).contains(normalized.count) { issues.append("Anzeigename muss 1–32 Zeichen haben.") }
        if normalized.unicodeScalars.contains(where: { $0.properties.generalCategory == .control }) {
            issues.append("Enthält ein Steuerzeichen.")
        }
        var report = Report(module: .discord, target: value,
                            status: issues.isEmpty ? "WITHIN LIMITS" : "REVIEW",
                            statusTone: issues.isEmpty ? .good : .warn)
        report.sections = [ReportSection(title: "Display Name", icon: "person.text.rectangle", rows: [
            ReportRow(key: "Normalisiert", value: normalized, tone: .accent),
            ReportRow(key: "Länge", value: "\(normalized.count) / 32")
        ], list: issues.isEmpty ? ["[OK] Innerhalb der Grundregeln"] : issues.map { "[!!] " + $0 })]
        report.notes = ["Nur lokale Formatierung. Keine Kontosuche, keine Identitätszuordnung."]
        report.json = JSON.string([
            "input": value,
            "normalized_display_name": normalized,
            "length": normalized.count,
            "format_status": issues.isEmpty ? "within_basic_limits" : "review",
            "format_issues": issues
        ])
        return report
    }
}
