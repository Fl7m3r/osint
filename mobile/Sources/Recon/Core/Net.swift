import Foundation

/// HTTP-JSON-Abruf wie `fetch_json` im Python-Tool (Größenlimit, klare Fehlermeldungen).
enum Net {
    static let userAgent = "FLMPSentinelMobile/1.0 (public metadata lookup)"

    static let session: URLSession = {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.timeoutIntervalForRequest = 10
        configuration.httpCookieStorage = nil
        configuration.urlCache = nil
        return URLSession(configuration: configuration)
    }()

    static func json(_ url: URL, timeout: TimeInterval = 10, maxBytes: Int = 1_000_000,
                     accept: String = "application/json") async throws -> Any {
        var request = URLRequest(url: url, timeoutInterval: timeout)
        request.setValue(userAgent, forHTTPHeaderField: "User-Agent")
        request.setValue(accept, forHTTPHeaderField: "Accept")
        let data: Data
        let response: URLResponse
        do {
            (data, response) = try await session.data(for: request)
        } catch {
            throw ReconError.service("Abfrage fehlgeschlagen: \(error.localizedDescription)")
        }
        let status = (response as? HTTPURLResponse)?.statusCode ?? 0
        guard status == 200 else { throw ReconError.service("Dienst antwortete mit HTTP \(status).") }
        guard data.count <= maxBytes else { throw ReconError.service("Antwort des Dienstes ist zu groß.") }
        do {
            return try JSONSerialization.jsonObject(with: data)
        } catch {
            throw ReconError.service("Antwort war kein gültiges JSON.")
        }
    }

    static func object(_ url: URL, timeout: TimeInterval = 10) async throws -> [String: Any] {
        guard let object = try await json(url, timeout: timeout) as? [String: Any] else {
            throw ReconError.service("Unerwartete Antwort des Dienstes.")
        }
        return object
    }

    static func encode(_ component: String) -> String {
        component.addingPercentEncoding(withAllowedCharacters: .alphanumerics.union(CharacterSet(charactersIn: "-._~"))) ?? component
    }
}

// MARK: - DNS über HTTPS

/// iOS hat keinen Resolver für MX/TXT/CAA o. ä. Die App fragt deshalb öffentliches DNS über HTTPS ab
/// (Cloudflare, Fallback Google). Die abgefragten Namen sehen diese Anbieter.
enum DNS {
    enum RecordType: String, CaseIterable {
        case A, AAAA, MX, NS, TXT, CAA, SOA, PTR

        var code: Int {
            switch self {
            case .A: return 1
            case .NS: return 2
            case .SOA: return 6
            case .PTR: return 12
            case .MX: return 15
            case .TXT: return 16
            case .AAAA: return 28
            case .CAA: return 257
            }
        }
    }

    enum Outcome {
        case records([String])
        case nxdomain
        case error(String)

        var values: [String] {
            if case .records(let values) = self { return values }
            return []
        }
    }

    private struct Response: Decodable {
        struct Record: Decodable {
            let type: Int
            let data: String
        }
        let status: Int
        let answer: [Record]?

        enum CodingKeys: String, CodingKey {
            case status = "Status"
            case answer = "Answer"
        }
    }

    private static let resolvers = [
        "https://cloudflare-dns.com/dns-query",
        "https://dns.google/resolve"
    ]

    static func query(_ name: String, _ type: RecordType) async -> Outcome {
        var lastError = "DNS-Abfrage fehlgeschlagen."
        for base in resolvers {
            guard var components = URLComponents(string: base) else { continue }
            components.queryItems = [URLQueryItem(name: "name", value: name), URLQueryItem(name: "type", value: type.rawValue)]
            guard let url = components.url else { continue }
            var request = URLRequest(url: url, timeoutInterval: 8)
            request.setValue("application/dns-json", forHTTPHeaderField: "Accept")
            request.setValue(Net.userAgent, forHTTPHeaderField: "User-Agent")
            do {
                let (data, response) = try await Net.session.data(for: request)
                guard (response as? HTTPURLResponse)?.statusCode == 200 else { continue }
                let decoded = try JSONDecoder().decode(Response.self, from: data)
                if decoded.status == 3 { return .nxdomain }
                guard decoded.status == 0 else {
                    lastError = "DNS-Status \(decoded.status)"
                    continue
                }
                let values = (decoded.answer ?? [])
                    .filter { $0.type == type.code }
                    .map { clean($0.data, type: type) }
                return .records(values.sorted())
            } catch {
                lastError = error.localizedDescription
            }
        }
        return .error(lastError)
    }

    private static func clean(_ data: String, type: RecordType) -> String {
        switch type {
        case .TXT:
            // TXT kommt als "teil1" "teil2" – zusammensetzen wie dnspython.
            let parts = data.components(separatedBy: "\"").enumerated().filter { $0.offset % 2 == 1 }.map(\.element)
            return parts.isEmpty ? data : parts.joined()
        default:
            return data.hasSuffix(".") ? String(data.dropLast()) : data
        }
    }

    /// "10 mx.example.com." → (10, "mx.example.com")
    static func mx(_ value: String) -> (priority: Int, host: String)? {
        let parts = value.split(separator: " ")
        guard parts.count == 2, let priority = Int(parts[0]) else { return nil }
        var host = String(parts[1])
        if host.hasSuffix(".") { host.removeLast() }
        return (priority, host)
    }
}
