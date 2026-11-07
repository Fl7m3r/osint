import Foundation
import Network
import Security

// MARK: - Server-Scan (Port von run_scan / probe_tcp / check_http aus fivem_remote_check.py)
//
// TCP-Connect-Checks und wenige HTTP/TLS-Anfragen an einen Server, den du prüfen darfst.
// Keine Exploits, keine Passworttests, kein UDP. Ein offener Port ist kein Beweis für eine Lücke.

enum ServerScan {
    static let maxPorts = 1024
    static let maxParallel = 16
    static let webPorts = [80, 443, 30120, 40120]
    static let webUIPorts: Set<Int> = [80, 443, 40120]
    static let securityHeaders = ["content-security-policy", "x-frame-options", "x-content-type-options", "referrer-policy"]
    static let certWarnDays = 21

    static let serviceHints: [Int: String] = [
        21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "domain", 80: "http", 110: "pop3", 143: "imap",
        443: "https", 445: "microsoft-ds", 587: "submission", 993: "imaps", 995: "pop3s", 3306: "mysql",
        3389: "ms-wbt-server", 5432: "postgresql", 6379: "redis", 8080: "http-alt", 27017: "mongodb",
        30120: "fivem", 40120: "txadmin"
    ]

    static let riskyPorts: [Int: (level: String, service: String, fix: String)] = [
        40120: ("HIGH", "txAdmin-Webpanel", "txAdmin nicht ins Internet stellen. An localhost binden und per VPN/SSH-Tunnel erreichen oder per Firewall auf Admin-IPs beschränken. Starkes Passwort + 2FA."),
        22: ("REVIEW", "SSH", "SSH nur von bekannten Admin-IPs erlauben, Passwort-Login zugunsten von Keys abschalten, PermitRootLogin no."),
        3389: ("HIGH", "Windows-Remotedesktop (RDP)", "RDP nie direkt ins Internet. Hinter VPN, Network Level Authentication erzwingen, Quell-IPs beschränken."),
        3306: ("HIGH", "MySQL/MariaDB", "Datenbank an 127.0.0.1 oder die App-Server-IP binden bzw. per Firewall beschränken."),
        5432: ("HIGH", "PostgreSQL", "An localhost/App-Server binden, nie öffentlich. pg_hba.conf und Firewall prüfen."),
        27017: ("HIGH", "MongoDB", "Nicht öffentlich. An localhost binden, Authentifizierung aktivieren, Port per Firewall sperren."),
        6379: ("HIGH", "Redis", "Redis hat standardmäßig keine Auth. An localhost binden, requirepass setzen, Port sperren."),
        21: ("REVIEW", "FTP", "FTP überträgt Zugangsdaten im Klartext. Durch SFTP/FTPS ersetzen und auf bekannte IPs beschränken."),
        23: ("HIGH", "Telnet", "Telnet ist unverschlüsselt und sollte komplett aus sein; SSH verwenden.")
    ]

    enum PortState: Equatable {
        case open, closed, filtered
        case unavailable(String)

        var label: String {
            switch self {
            case .open: return "open"
            case .closed: return "closed"
            case .filtered: return "filtered_or_timeout"
            case .unavailable: return "unavailable"
            }
        }
    }

    static func parsePorts(_ spec: String) throws -> [Int] {
        var ports = Set<Int>()
        for rawPart in spec.split(separator: ",") {
            let part = rawPart.trimmingCharacters(in: .whitespaces)
            guard !part.isEmpty else { continue }
            if part.contains("-") {
                let bounds = part.split(separator: "-", maxSplits: 1).map { Int($0.trimmingCharacters(in: .whitespaces)) }
                guard bounds.count == 2, let start = bounds[0], let end = bounds[1] else {
                    throw ReconError.input("Ungültiger Portbereich: \(part)")
                }
                guard start <= end else { throw ReconError.input("Portbereich ist verdreht: \(part)") }
                guard end - start < maxPorts else { throw ReconError.input("Maximal \(maxPorts) Ports pro Durchlauf.") }
                ports.formUnion(start...end)
            } else {
                guard let port = Int(part) else { throw ReconError.input("Ungültiger Port: \(part)") }
                ports.insert(port)
            }
            guard ports.allSatisfy({ (1...65535).contains($0) }) else { throw ReconError.input("Ports müssen zwischen 1 und 65535 liegen.") }
            guard ports.count <= maxPorts else { throw ReconError.input("Maximal \(maxPorts) Ports pro Durchlauf.") }
        }
        guard !ports.isEmpty else { throw ReconError.input("Mindestens einen Port angeben.") }
        return ports.sorted()
    }

    static func run(_ hostInput: String, portSpec: String, timeout: TimeInterval = 3) async throws -> Report {
        guard let address = IPTools.parse(hostInput) else {
            throw ReconError.input("IPv4- oder IPv6-Adresse eingeben; DNS-Namen werden nicht akzeptiert.")
        }
        let host = IPTools.string(address)
        let ports = try parsePorts(portSpec)

        // TCP-Probes, höchstens 16 gleichzeitig
        var results: [Int: PortState] = [:]
        await withTaskGroup(of: (Int, PortState).self) { group in
            var iterator = ports.makeIterator()
            for _ in 0..<min(maxParallel, ports.count) {
                if let port = iterator.next() { group.addTask { let state = await probe(host: host, port: port, timeout: timeout); return (port, state) } }
            }
            for await (port, state) in group {
                results[port] = state
                if let next = iterator.next() { group.addTask { let state = await probe(host: host, port: next, timeout: timeout); return (next, state) } }
            }
        }
        let openPorts = Set(results.filter { $0.value == .open }.keys)

        var webChecks: [(port: Int, checks: [HTTPCheck])] = []
        for port in webPorts where openPorts.contains(port) {
            let checks = await checkHTTP(host: host, port: port, timeout: timeout + 3)
            webChecks.append((port: port, checks: checks))
        }

        var findings = portFindings(openPorts)
        for web in webChecks {
            for check in web.checks {
                if let server = check.server, server.contains(where: \.isNumber) {
                    findings.append(Finding(level: "REVIEW", title: "Versionsartiger Server-Header auf Port \(web.port)",
                                            detail: "Eine Versionsnummer im Server-Header hilft Angreifern; ein Banner allein beweist keine verwundbare Version.",
                                            fix: "Version im Webserver ausblenden (nginx: server_tokens off; Apache: ServerTokens Prod) und Software aktuell halten."))
                }
            }
        }
        findings.append(contentsOf: webFindings(webChecks))
        let high = findings.contains { $0.level == "HIGH" }

        var report = Report(module: .scan, target: host,
                            status: high ? "EXPOSURE DETECTED" : openPorts.isEmpty ? "NO OPEN PORTS" : "SCAN COMPLETE",
                            statusTone: high ? .bad : .good)
        let portLines = ports.map { port -> String in
            let state = results[port] ?? .filtered
            let hint = state == .open ? "  " + (serviceHints[port] ?? "unknown") : ""
            return "\(String(port).padding(toLength: 6, withPad: " ", startingAt: 0)) \(state.label)\(hint)"
        }
        report.sections = [
            ReportSection(title: "Scope", icon: "scope", rows: [
                ReportRow(key: "Ziel", value: host, tone: .accent),
                ReportRow(key: "Ports", value: "\(ports.count) TCP"),
                ReportRow(key: "Offen", value: "\(openPorts.count)", tone: openPorts.isEmpty ? .normal : .warn),
                ReportRow(key: "Timeout", value: "\(Int(timeout)) s, max. \(maxParallel) parallel")
            ]),
            ReportSection(title: "Ports", icon: "list.number",
                          list: openPorts.count > 0 ? portLines.filter { $0.contains("open") } + portLines.filter { !$0.contains("open") } : portLines,
                          listLimit: 120)
        ]
        for web in webChecks {
            var section = ReportSection(title: "HTTP Port \(web.port)", icon: web.port == 443 ? "lock" : "globe")
            for check in web.checks {
                if let error = check.error {
                    section.rows.append(ReportRow(key: check.path, value: error, tone: .warn))
                    continue
                }
                section.rows.append(ReportRow(key: check.path, value: "HTTP \(check.status ?? 0)", tone: .accent))
                if let server = check.server { section.rows.append(ReportRow(key: "Server", value: server)) }
                if let cert = check.certificate {
                    section.rows.append(ReportRow(key: "Zertifikat", value: cert.subject ?? "—"))
                    section.rows.append(ReportRow(key: "Aussteller", value: cert.issuer ?? "—"))
                    if let days = cert.daysLeft {
                        section.rows.append(ReportRow(key: "Gültig noch", value: "\(days) Tage", tone: days < certWarnDays ? .bad : .good))
                    }
                }
                if !check.missingHeaders.isEmpty {
                    section.list.append(contentsOf: check.missingHeaders.map { "fehlt: \($0)" })
                }
            }
            report.sections.append(section)
        }
        report.findings = findings
        report.notes = [
            "Nur TCP-Verbindungschecks und begrenzte HTTP/TLS-Anfragen; kein UDP.",
            "Keine Exploit- oder Passworttests – das ist kein vollständiger Schwachstellenscan.",
            "Ein offener Port oder Banner ist kein Beweis für eine Schwachstelle."
        ]
        report.json = JSON.string([
            "target": host,
            "checked_at_utc": JSON.iso.string(from: Date()),
            "scope": ["protocol": "TCP", "ports_requested": ports, "timeout_seconds": timeout, "max_parallel_connections": maxParallel] as [String: Any],
            "ports": ports.map { ["port": $0, "protocol": "tcp", "state": (results[$0] ?? .filtered).label] as [String: Any] },
            "http_checks": webChecks.map { web in
                ["port": web.port, "checks": web.checks.map(\.json)] as [String: Any]
            },
            "findings": findings.map { ["level": $0.level, "title": $0.title, "detail": $0.detail, "fix": $0.fix] }
        ])
        return report
    }

    // MARK: TCP

    private final class Once: @unchecked Sendable {
        private let lock = NSLock()
        private var done = false
        func claim() -> Bool {
            lock.lock(); defer { lock.unlock() }
            if done { return false }
            done = true
            return true
        }
    }

    static func probe(host: String, port: Int, timeout: TimeInterval) async -> PortState {
        guard let nwPort = NWEndpoint.Port(rawValue: UInt16(port)) else { return .unavailable("Port") }
        return await withCheckedContinuation { (continuation: CheckedContinuation<PortState, Never>) in
            let connection = NWConnection(host: NWEndpoint.Host(host), port: nwPort, using: .tcp)
            let once = Once()
            let finish: (PortState) -> Void = { state in
                guard once.claim() else { return }
                connection.cancel()
                continuation.resume(returning: state)
            }
            connection.stateUpdateHandler = { state in
                switch state {
                case .ready:
                    finish(.open)
                case .waiting(let error):
                    if case .posix(let code) = error, code == .ECONNREFUSED { finish(.closed) }
                case .failed(let error):
                    if case .posix(let code) = error, code == .ECONNREFUSED { finish(.closed) }
                    else { finish(.unavailable(error.localizedDescription)) }
                default:
                    break
                }
            }
            connection.start(queue: .global(qos: .userInitiated))
            DispatchQueue.global().asyncAfter(deadline: .now() + timeout) { finish(.filtered) }
        }
    }

    // MARK: HTTP / TLS

    struct CertificateInfo {
        let subject: String?
        let issuer: String?
        let notAfter: Date?
        var daysLeft: Int? {
            notAfter.map { Calendar.current.dateComponents([.day], from: Date(), to: $0).day ?? 0 }
        }
    }

    struct HTTPCheck {
        let path: String
        var status: Int?
        var server: String?
        var contentType: String?
        var tls: Bool
        var missingHeaders: [String] = []
        var certificate: CertificateInfo?
        var error: String?

        var json: [String: Any] {
            var dict: [String: Any] = ["path": path, "tls": tls]
            dict["status"] = status
            dict["server_header"] = server
            dict["content_type"] = contentType
            dict["error"] = error
            if !missingHeaders.isEmpty { dict["missing_security_headers"] = missingHeaders }
            if let certificate {
                var cert: [String: Any] = [:]
                cert["subject"] = certificate.subject
                cert["issuer"] = certificate.issuer
                cert["not_after_utc"] = certificate.notAfter.map { JSON.iso.string(from: $0) }
                cert["days_left"] = certificate.daysLeft
                dict["certificate"] = cert
            }
            return dict
        }
    }

    /// Delegate: keine Weiterleitungen folgen; TLS-Kette prüfen, Hostname bei IP-Zielen aber nicht (wie im Python-Tool).
    private final class ProbeDelegate: NSObject, URLSessionTaskDelegate, @unchecked Sendable {
        var certificate: CertificateInfo?
        var trustError: String?

        func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse,
                        newRequest request: URLRequest) async -> URLRequest? {
            nil
        }

        func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge)
            async -> (URLSession.AuthChallengeDisposition, URLCredential?) {
            handle(challenge)
        }

        func urlSession(_ session: URLSession, task: URLSessionTask, didReceive challenge: URLAuthenticationChallenge)
            async -> (URLSession.AuthChallengeDisposition, URLCredential?) {
            handle(challenge)
        }

        private func handle(_ challenge: URLAuthenticationChallenge) -> (URLSession.AuthChallengeDisposition, URLCredential?) {
            guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
                  let trust = challenge.protectionSpace.serverTrust else {
                return (.performDefaultHandling, nil)
            }
            SecTrustSetPolicies(trust, SecPolicyCreateSSL(true, nil))
            var error: CFError?
            let trusted = SecTrustEvaluateWithError(trust, &error)
            if let chain = SecTrustCopyCertificateChain(trust) as? [SecCertificate], let leaf = chain.first {
                certificate = CertificateInfo(
                    subject: SecCertificateCopySubjectSummary(leaf) as String?,
                    issuer: chain.count > 1 ? SecCertificateCopySubjectSummary(chain[1]) as String? : nil,
                    notAfter: DERDates.notAfter(SecCertificateCopyData(leaf) as Data)
                )
            }
            if trusted { return (.useCredential, URLCredential(trust: trust)) }
            trustError = error.map { CFErrorCopyDescription($0) as String } ?? "Zertifikat nicht vertrauenswürdig"
            return (.cancelAuthenticationChallenge, nil)
        }
    }

    static func checkHTTP(host: String, port: Int, timeout: TimeInterval) async -> [HTTPCheck] {
        let secure = port == 443
        let paths = port == 30120 ? ["/", "/info.json"] : ["/"]
        let hostPart = host.contains(":") ? "[\(host)]" : host
        var checks: [HTTPCheck] = []

        for path in paths {
            let delegate = ProbeDelegate()
            let configuration = URLSessionConfiguration.ephemeral
            configuration.timeoutIntervalForRequest = timeout
            let session = URLSession(configuration: configuration, delegate: delegate, delegateQueue: nil)
            defer { session.finishTasksAndInvalidate() }

            var check = HTTPCheck(path: path, tls: secure)
            guard let url = URL(string: "\(secure ? "https" : "http")://\(hostPart):\(port)\(path)") else { continue }
            var request = URLRequest(url: url, timeoutInterval: timeout)
            request.setValue("flmp-authorized-check/0.1", forHTTPHeaderField: "User-Agent")
            do {
                let (_, response) = try await session.data(for: request)
                guard let http = response as? HTTPURLResponse else { continue }
                var headers: [String: String] = [:]
                for (key, value) in http.allHeaderFields {
                    headers[String(describing: key).lowercased()] = String(String(describing: value).prefix(256))
                }
                check.status = http.statusCode
                check.server = headers["server"]
                check.contentType = headers["content-type"]
                if webUIPorts.contains(port), path == "/", (200..<300).contains(http.statusCode) {
                    let expected = securityHeaders + (secure ? ["strict-transport-security"] : [])
                    check.missingHeaders = expected.filter { headers[$0] == nil }
                }
                check.certificate = delegate.certificate
                checks.append(check)
            } catch {
                check.error = delegate.trustError ?? String(error.localizedDescription.prefix(256))
                check.certificate = delegate.certificate
                checks.append(check)
                break
            }
        }
        return checks
    }

    // MARK: Findings

    static func portFindings(_ open: Set<Int>) -> [Finding] {
        var findings: [Finding] = []
        if open.contains(30120) {
            findings.append(Finding(level: "INFO", title: "FiveM-Port 30120 erreichbar",
                                    detail: "Erreichbarkeit bestätigt; das allein ist keine Schwachstelle.",
                                    fix: "Für einen öffentlichen FiveM-Server normal. FXServer aktuell halten und Ressourcen auf bekannte Lücken prüfen."))
        }
        for port in open.sorted() {
            guard let risk = riskyPorts[port] else { continue }
            findings.append(Finding(level: risk.level, title: "Sensibler Dienst auf TCP/\(port) (\(risk.service))",
                                    detail: "Port \(port) ist typischerweise \(risk.service) und von hier aus erreichbar. Offene Admin- und Datenbankdienste sind ein häufiger Einbruchsweg.",
                                    fix: risk.fix))
        }
        return findings
    }

    static func webFindings(_ webChecks: [(port: Int, checks: [HTTPCheck])]) -> [Finding] {
        var findings: [Finding] = []
        for web in webChecks {
            for check in web.checks {
                if check.error != nil && web.port == 443 {
                    findings.append(Finding(level: "REVIEW", title: "HTTPS/TLS konnte nicht validiert werden",
                                            detail: "Zertifikatskette und TLS-Konfiguration prüfen; der Hostname wird bei IP-Zielen nicht geprüft.",
                                            fix: "Gültiges Zertifikat einer vertrauenswürdigen CA (z. B. Let's Encrypt) und veraltete Protokolle (SSLv3, TLS 1.0/1.1) abschalten."))
                }
                if web.port == 40120 && !check.tls && check.status != nil {
                    findings.append(Finding(level: "HIGH", title: "txAdmin-Panel über unverschlüsseltes HTTP",
                                            detail: "Das Panel antwortet per HTTP; Zugangsdaten und Session-Cookies könnten mitgelesen werden.",
                                            fix: "Hinter einen HTTPS-Reverse-Proxy (Caddy/nginx mit gültigem Zertifikat) stellen – besser gar nicht öffentlich."))
                }
                if let days = check.certificate?.daysLeft, days < certWarnDays {
                    findings.append(Finding(level: "REVIEW", title: days < 0 ? "TLS-Zertifikat auf Port \(web.port) ist abgelaufen" : "TLS-Zertifikat auf Port \(web.port) läuft in \(days) Tagen ab",
                                            detail: "Ablaufdatum prüfen.",
                                            fix: "Zertifikat erneuern und automatische Erneuerung (certbot oder ACME des Proxys) einrichten."))
                }
                if !check.missingHeaders.isEmpty {
                    let missing = check.missingHeaders.joined(separator: ", ")
                    findings.append(Finding(level: "INFO", title: "Fehlende Browser-Sicherheitsheader auf Port \(web.port)",
                                            detail: "Nicht gesetzt: \(missing). Relevant für Web-UIs, nicht für Spielverkehr.",
                                            fix: "Header im Webserver/Reverse-Proxy setzen: \(missing). Mit X-Content-Type-Options: nosniff und X-Frame-Options: DENY anfangen, dann eine Content-Security-Policy."))
                }
            }
        }
        return findings
    }
}

/// Liest notBefore/notAfter aus einem DER-Zertifikat (iOS hat dafür keine öffentliche API).
enum DERDates {
    static func notAfter(_ der: Data) -> Date? {
        let bytes = [UInt8](der)
        var dates: [Date] = []
        var index = 0
        while index + 2 < bytes.count && dates.count < 2 {
            let tag = bytes[index], length = Int(bytes[index + 1])
            if (tag == 0x17 && length == 13) || (tag == 0x18 && length == 15), index + 2 + length <= bytes.count,
               let text = String(bytes: bytes[(index + 2)..<(index + 2 + length)], encoding: .ascii),
               let date = parse(text, generalized: tag == 0x18) {
                dates.append(date)
                index += 2 + length
            } else {
                index += 1
            }
        }
        return dates.count == 2 ? dates[1] : nil
    }

    private static func parse(_ text: String, generalized: Bool) -> Date? {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = TimeZone(identifier: "UTC")
        formatter.dateFormat = generalized ? "yyyyMMddHHmmss'Z'" : "yyMMddHHmmss'Z'"
        return formatter.date(from: text)
    }
}

// MARK: - Config-Audit (Port von fivem_config_audit.py)

enum ConfigAudit {
    static let placeholders: Set<String> = ["changeme", "change_me", "password", "yourpassword", "none", ""]

    static func parse(_ text: String) -> [String: [String]] {
        var settings: [String: [String]] = [:]
        let regex = try! NSRegularExpression(pattern: #"^([A-Za-z_]\w*)\s+(.+?)\s*$"#)
        for rawLine in text.components(separatedBy: .newlines) {
            let line = rawLine.trimmingCharacters(in: .whitespaces)
            guard !line.isEmpty, !line.hasPrefix("#"), !line.hasPrefix("//") else { continue }
            let range = NSRange(line.startIndex..., in: line)
            guard let match = regex.firstMatch(in: line, range: range),
                  let keyRange = Range(match.range(at: 1), in: line),
                  let valueRange = Range(match.range(at: 2), in: line) else { continue }
            let key = line[keyRange].lowercased()
            let value = line[valueRange].trimmingCharacters(in: .whitespaces).trimmingCharacters(in: CharacterSet(charactersIn: "\"'"))
            settings[key, default: []].append(value)
        }
        return settings
    }

    static func audit(_ settings: [String: [String]]) -> [Finding] {
        func last(_ key: String) -> String? { settings[key]?.last?.trimmingCharacters(in: .whitespaces) }
        var findings: [Finding] = []
        let on: Set<String> = ["1", "true", "yes", "on"]
        let off: Set<String> = ["0", "false", "no", "off"]

        let hooks = (last("sv_scripthookallowed") ?? "").lowercased()
        if on.contains(hooks) {
            findings.append(Finding(level: "HIGH", title: "sv_scriptHookAllowed ist aktiviert", detail: "", fix: "Auf false setzen, außer du brauchst es wirklich."))
        } else if off.contains(hooks) {
            findings.append(Finding(level: "OK", title: "sv_scriptHookAllowed ist deaktiviert", detail: "", fix: "Die Config blockiert clientseitige Script-Hooks."))
        } else {
            findings.append(Finding(level: "REVIEW", title: "sv_scriptHookAllowed fehlt oder ist unklar", detail: "", fix: "Explizit auf false setzen und gegen deine FXServer-Version prüfen."))
        }

        if let rcon = last("rcon_password") {
            if placeholders.contains(rcon.lowercased()) || rcon.count < 16 {
                findings.append(Finding(level: "HIGH", title: "RCON-Passwort fehlt, ist ein Platzhalter oder zu kurz", detail: "", fix: "Langes Zufallsgeheimnis verwenden; der Wert wird nicht angezeigt."))
            } else {
                findings.append(Finding(level: "REVIEW", title: "RCON-Passwort ist gesetzt", detail: "", fix: "Länge wirkt plausibel; Einmaligkeit und sichere Ablage von Hand prüfen."))
            }
        } else {
            findings.append(Finding(level: "OK", title: "Kein RCON-Passwort in dieser Config", detail: "", fix: "Falls RCON anderswo aktiv ist, diesen Zugang separat absichern."))
        }

        let license = last("sv_licensekey")
        if license == nil || placeholders.contains((license ?? "").lowercased()) {
            findings.append(Finding(level: "REVIEW", title: "sv_licenseKey fehlt oder ist ein Platzhalter", detail: "", fix: "Config und Startumgebung prüfen; den Key nie in Logs oder Screenshots teilen."))
        } else {
            findings.append(Finding(level: "OK", title: "sv_licenseKey ist gesetzt", detail: "", fix: "Der Wert wird nicht angezeigt."))
        }

        if on.contains((last("sv_endpointprivacy") ?? "").lowercased()) {
            findings.append(Finding(level: "OK", title: "sv_endpointPrivacy ist aktiviert", detail: "", fix: "Aktiviert lassen und Verhalten gegen deine Serverversion prüfen."))
        } else {
            findings.append(Finding(level: "REVIEW", title: "sv_endpointPrivacy ist nicht explizit aktiviert", detail: "", fix: "Aktivieren, um unnötige Endpoint-Daten nicht preiszugeben."))
        }

        if (settings["rcon_password"]?.count ?? 0) > 1 {
            findings.append(Finding(level: "REVIEW", title: "Mehrere rcon_password-Zeilen", detail: "", fix: "Duplikate entfernen und prüfen, welche Einstellung greift."))
        }
        if (settings["sv_licensekey"]?.count ?? 0) > 1 {
            findings.append(Finding(level: "REVIEW", title: "Mehrere sv_licenseKey-Zeilen", detail: "", fix: "Duplikate entfernen; Werte bleiben verborgen."))
        }
        return findings
    }

    static func run(text: String, fileName: String) -> Report {
        let settings = parse(text)
        let findings = audit(settings)
        let high = findings.contains { $0.level == "HIGH" }
        var report = Report(module: .config, target: fileName,
                            status: high ? "HIGH RISK FOUND" : "BASELINE CHECKED",
                            statusTone: high ? .bad : .good)
        report.sections = [ReportSection(title: "Datei", icon: "doc.text", rows: [
            ReportRow(key: "Datei", value: fileName, tone: .accent),
            ReportRow(key: "Direktiven", value: "\(settings.values.reduce(0) { $0 + $1.count })"),
            ReportRow(key: "HIGH", value: "\(findings.filter { $0.level == "HIGH" }.count)", tone: high ? .bad : .good),
            ReportRow(key: "REVIEW", value: "\(findings.filter { $0.level == "REVIEW" }.count)", tone: .warn)
        ])]
        report.findings = findings
        report.notes = ["Nur lokaler Config-Grundcheck auf dem iPhone – kein Netzwerkscan und keine vollständige Sicherheitsbewertung. Geheime Werte werden nie angezeigt oder exportiert."]
        report.json = JSON.string([
            "file": fileName,
            "findings": findings.map { ["level": $0.level, "title": $0.title, "advice": $0.fix] },
            "scope_note": "Local config baseline only; secret values are never included."
        ])
        return report
    }
}
