import Foundation

// MARK: - E-Mail (Port von check_email)

enum EmailCheck {
    private static let regex = try! NSRegularExpression(pattern: #"^[^\s@<>]+@([^\s@<>]+\.[^\s@<>]+)$"#)

    static func matches(_ text: String) -> Bool { domain(of: text) != nil }

    static func domain(of text: String) -> String? {
        let range = NSRange(text.startIndex..., in: text)
        guard let match = regex.firstMatch(in: text, range: range),
              let domainRange = Range(match.range(at: 1), in: text) else { return nil }
        var domain = String(text[domainRange]).lowercased()
        if domain.hasSuffix(".") { domain.removeLast() }
        return domain
    }

    static func run(_ address: String) async throws -> Report {
        guard let domain = domain(of: address) else { throw ReconError.input("Ungültiges E-Mail-Format.") }
        guard domain.allSatisfy(\.isASCII) else {
            throw ReconError.input("Bitte die Domain in Punycode (xn--…) eingeben.")
        }

        async let mxLookup = DNS.query(domain, .MX)
        async let spfLookup = DNS.query(domain, .TXT)
        async let dmarcLookup = DNS.query("_dmarc.\(domain)", .TXT)
        let (mx, spfTXT, dmarcTXT) = await (mxLookup, spfLookup, dmarcLookup)

        let status: String
        var mxRecords: [(priority: Int, host: String)] = []
        switch mx {
        case .records(let values):
            mxRecords = values.compactMap(DNS.mx).sorted { ($0.priority, $0.host) < ($1.priority, $1.host) }
            status = mxRecords.isEmpty ? "no_mx_records" : "mx_found"
        case .nxdomain:
            status = "domain_not_found"
        case .error(let message):
            throw ReconError.service("DNS-Abfrage fehlgeschlagen: \(message)")
        }

        let spf = spfTXT.values.filter { $0.lowercased().hasPrefix("v=spf1") }
        let dmarc = dmarcTXT.values.filter { $0.lowercased().hasPrefix("v=dmarc1") }
        func policyStatus(_ outcome: DNS.Outcome, _ found: [String]) -> String {
            if case .error = outcome { return "lookup_error" }
            return found.isEmpty ? "not_found" : "published"
        }
        let spfStatus = policyStatus(spfTXT, spf)
        let dmarcStatus = policyStatus(dmarcTXT, dmarc)

        var report = Report(
            module: .email,
            target: address,
            status: status == "mx_found" ? "MX FOUND" : status == "domain_not_found" ? "DOMAIN NOT FOUND" : "NO MX",
            statusTone: status == "mx_found" ? .good : .warn
        )
        report.sections = [
            ReportSection(title: "Domain", icon: "at", rows: [
                ReportRow(key: "Domain", value: domain, tone: .accent),
                ReportRow(key: "Status", value: status)
            ]),
            ReportSection(title: "MX Records", icon: "tray.full",
                          list: mxRecords.map { "\($0.priority)  \($0.host)" }),
            ReportSection(title: "Mail Policy", icon: "lock.shield", rows: [
                ReportRow(key: "SPF", value: spfStatus, tone: spfStatus == "published" ? .good : .warn),
                ReportRow(key: "DMARC", value: dmarcStatus, tone: dmarcStatus == "published" ? .good : .warn)
            ], list: spf + dmarc)
        ]
        report.notes = [
            "Nur DNS der Domain geprüft. Ob das Postfach existiert oder wem es gehört, wurde nicht geprüft.",
            "Mail OSINT Framework ist ein Verzeichnis externer Tools – die App sendet die Adresse dort nicht hin."
        ]
        report.links = [ReportLink(title: "Mail OSINT Framework", url: URL(string: "https://mail.osintframework.com/")!)]
        report.json = JSON.string([
            "input": address,
            "domain": domain,
            "status": status,
            "mx_records": mxRecords.map { ["priority": $0.priority, "host": $0.host] as [String: Any] },
            "mail_dns_policy": [
                "spf": ["status": spfStatus, "records": spf] as [String: Any],
                "dmarc": ["status": dmarcStatus, "records": dmarc] as [String: Any]
            ] as [String: Any],
            "scope_note": "Domain DNS checked; mailbox existence and ownership were not checked."
        ])
        return report
    }
}

// MARK: - Domain (Port von check_domain, check_domain_rdap, check_ct_subdomains)

enum DomainCheck {
    private static let label = try! NSRegularExpression(pattern: #"^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$"#)

    static func normalize(_ value: String) throws -> String {
        var domain = value.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        if domain.hasSuffix(".") { domain.removeLast() }
        guard domain.allSatisfy(\.isASCII) else { throw ReconError.input("Bitte Punycode (xn--…) verwenden.") }
        let labels = domain.split(separator: ".", omittingEmptySubsequences: false).map(String.init)
        let valid = labels.count >= 2 && domain.count <= 253 && !(labels.last ?? "").allSatisfy(\.isNumber)
            && labels.allSatisfy { part in
                !part.isEmpty && part.count <= 63 &&
                    label.firstMatch(in: part, range: NSRange(part.startIndex..., in: part)) != nil
            }
        guard valid else { throw ReconError.input("Ungültiger Domainname.") }
        return domain
    }

    static func run(_ value: String, includeCT: Bool) async throws -> Report {
        let domain = try normalize(value)

        var outcomes: [DNS.RecordType: DNS.Outcome] = [:]
        await withTaskGroup(of: (DNS.RecordType, DNS.Outcome).self) { group in
            for type in [DNS.RecordType.A, .AAAA, .MX, .NS, .TXT, .CAA, .SOA] {
                group.addTask { let outcome = await DNS.query(domain, type); return (type, outcome) }
            }
            for await (type, outcome) in group { outcomes[type] = outcome }
        }
        let missing = outcomes.values.contains { if case .nxdomain = $0 { return true } else { return false } }

        var registration: [String: Any] = [:]
        var rdapRows: [ReportRow] = []
        do {
            registration = try await rdap(domain)
            rdapRows = [
                ReportRow(key: "Registrar", value: registration["registrar"] as? String ?? "—", tone: .accent),
                ReportRow(key: "Registriert", value: JSON.short(registration["registered"] as? String)),
                ReportRow(key: "Läuft ab", value: JSON.short(registration["expires"] as? String)),
                ReportRow(key: "Geändert", value: JSON.short(registration["last_changed"] as? String)),
                ReportRow(key: "Status", value: (registration["registry_status"] as? [String] ?? []).joined(separator: ", "))
            ]
        } catch {
            registration = ["status": "unavailable", "message": error.localizedDescription]
            rdapRows = [ReportRow(key: "RDAP", value: error.localizedDescription, tone: .warn)]
        }

        var report = Report(
            module: .domain,
            target: domain,
            status: missing ? "DOMAIN NOT FOUND" : "RECORDS RESOLVED",
            statusTone: missing ? .bad : .good
        )
        var dnsJSON: [String: Any] = [:]
        var dnsSection = ReportSection(title: "DNS Records", icon: "server.rack")
        for type in [DNS.RecordType.A, .AAAA, .MX, .NS, .TXT, .CAA, .SOA] {
            switch outcomes[type] ?? .records([]) {
            case .records(let values):
                dnsJSON[type.rawValue] = values
                dnsSection.list.append(contentsOf: values.map { "\(type.rawValue.padding(toLength: 5, withPad: " ", startingAt: 0)) \($0)" })
            case .nxdomain:
                dnsJSON[type.rawValue] = []
            case .error(let message):
                dnsJSON[type.rawValue] = ["lookup_error": message]
                dnsSection.list.append("\(type.rawValue) ! \(message)")
            }
        }
        if dnsSection.list.isEmpty { dnsSection.list = ["(keine Einträge)"] }
        report.sections = [dnsSection, ReportSection(title: "Registry (RDAP)", icon: "building.columns", rows: rdapRows,
                                                     list: registration["nameservers"] as? [String] ?? [])]

        var json: [String: Any] = [
            "domain": domain,
            "status": missing ? "domain_not_found" : "checked",
            "dns_records": dnsJSON,
            "registration": registration,
            "scope_note": "Public DNS and RDAP registry data only; redacted registrant contact data is not queried."
        ]

        if includeCT {
            do {
                let ct = try await certificateTransparency(domain)
                json["certificate_transparency"] = ct
                let hosts = ct["hostnames"] as? [String] ?? []
                report.sections.append(ReportSection(
                    title: "CT Subdomains (\(hosts.count))", icon: "list.bullet.indent",
                    rows: [ReportRow(key: "Zertifikate gesehen", value: "\(ct["certificates_seen"] as? Int ?? 0)")],
                    list: hosts, listLimit: 200
                ))
                report.notes.append("CT-Namen stammen aus ausgestellten Zertifikaten – sie können abgelaufen, intern oder nicht mehr auflösbar sein.")
            } catch {
                json["certificate_transparency"] = ["status": "unavailable", "message": error.localizedDescription]
                report.sections.append(ReportSection(title: "CT Subdomains", icon: "list.bullet.indent",
                                                     rows: [ReportRow(key: "crt.sh", value: error.localizedDescription, tone: .warn)]))
            }
        }
        report.notes.insert("Nur öffentliches DNS und RDAP. Geschwärzte Inhaberdaten werden nicht abgefragt.", at: 0)
        report.json = JSON.string(json)
        return report
    }

    static func rdap(_ domain: String) async throws -> [String: Any] {
        let rdap = try await Net.object(URL(string: "https://rdap.org/domain/\(Net.encode(domain))")!)
        var events: [String: String] = [:]
        for case let event as [String: Any] in rdap["events"] as? [Any] ?? [] {
            if let action = event["eventAction"] as? String, let date = event["eventDate"] as? String { events[action] = date }
        }
        var registrar: String?
        for case let entity as [String: Any] in rdap["entities"] as? [Any] ?? [] {
            if (entity["roles"] as? [String] ?? []).contains("registrar") {
                registrar = vcardName(entity)
                break
            }
        }
        let nameservers = (rdap["nameservers"] as? [[String: Any]] ?? [])
            .compactMap { ($0["ldhName"] as? String)?.lowercased() }
            .map { $0.hasSuffix(".") ? String($0.dropLast()) : $0 }
            .sorted()
        var result: [String: Any] = [
            "status": "available",
            "registry_status": rdap["status"] as? [String] ?? [],
            "nameservers": nameservers,
            "source": "https://rdap.org"
        ]
        result["registrar"] = registrar
        result["registered"] = events["registration"]
        result["expires"] = events["expiration"]
        result["last_changed"] = events["last changed"]
        return result
    }

    static func vcardName(_ entity: [String: Any]) -> String? {
        guard let vcard = entity["vcardArray"] as? [Any], vcard.count > 1, let fields = vcard[1] as? [[Any]] else { return nil }
        for field in fields where field.count > 3 && (field[0] as? String) == "fn" {
            return field[3] as? String
        }
        return nil
    }

    static func certificateTransparency(_ domain: String) async throws -> [String: Any] {
        let query = Net.encode("%." + domain)
        let url = URL(string: "https://crt.sh/?q=\(query)&output=json")!
        let raw: Any
        do {
            raw = try await Net.json(url, timeout: 30, maxBytes: 25_000_000)
        } catch {
            try? await Task.sleep(nanoseconds: 2_000_000_000) // crt.sh liefert oft kurz 502/503
            raw = try await Net.json(url, timeout: 30, maxBytes: 25_000_000)
        }
        guard let entries = raw as? [[String: Any]] else { throw ReconError.service("Unerwartete Antwort von crt.sh.") }
        var names = Set<String>()
        for entry in entries {
            for line in (entry["name_value"] as? String ?? "").split(separator: "\n") {
                var name = line.trimmingCharacters(in: .whitespaces).lowercased()
                if name.hasPrefix("*.") { name.removeFirst(2) }
                if name == domain || name.hasSuffix("." + domain) { names.insert(name) }
            }
        }
        let sorted = names.sorted()
        return [
            "status": "available",
            "certificates_seen": entries.count,
            "unique_hostnames": sorted.count,
            "hostnames": Array(sorted.prefix(500)),
            "truncated": sorted.count > 500,
            "source": "https://crt.sh"
        ]
    }
}
