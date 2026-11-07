import Foundation

/// Antwort von TikToks offizieller oEmbed-Schnittstelle (https://developers.tiktok.com/doc/embed-creator-profiles).
struct OEmbedResponse: Decodable, Equatable {
    let title: String?
    let authorName: String?
    let authorURL: String?
    let html: String?
    let thumbnailURL: String?
    let providerName: String?

    enum CodingKeys: String, CodingKey {
        case title
        case authorName = "author_name"
        case authorURL = "author_url"
        case html
        case thumbnailURL = "thumbnail_url"
        case providerName = "provider_name"
    }
}

enum LookupError: LocalizedError, Equatable {
    case notFound
    case http(Int)
    case network(String)

    var errorDescription: String? {
        switch self {
        case .notFound:
            return "Kein öffentliches Profil gefunden. Der Name ist frei, das Konto ist privat/gesperrt, oder TikTok liefert dafür kein Embed."
        case .http(let code):
            return "TikTok hat mit HTTP \(code) geantwortet. Bitte später erneut versuchen."
        case .network(let message):
            return "Netzwerkfehler: \(message)"
        }
    }
}

/// Nutzt ausschließlich öffentliche, offiziell dokumentierte Endpunkte (oEmbed) – kein Scraping.
struct TikTokLookupService {
    private let session: URLSession
    private let userAgent = "FLMPSentinelMobile/1.0 (public oEmbed lookup)"

    init() {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.timeoutIntervalForRequest = 10
        configuration.httpCookieStorage = nil
        session = URLSession(configuration: configuration)
    }

    func profileEmbed(username: String) async throws -> OEmbedResponse {
        try await oEmbed(for: "https://www.tiktok.com/@\(username)")
    }

    func videoEmbed(username: String, videoID: String) async throws -> OEmbedResponse {
        try await oEmbed(for: "https://www.tiktok.com/@\(username)/video/\(videoID)")
    }

    /// Löst einen Kurzlink (vm.tiktok.com/…) über die Weiterleitung auf. Es wird nur die Ziel-URL gelesen.
    func resolveShortLink(_ url: URL) async throws -> URL {
        var request = URLRequest(url: url)
        request.httpMethod = "HEAD"
        request.setValue(userAgent, forHTTPHeaderField: "User-Agent")
        do {
            let (_, response) = try await session.data(for: request)
            return response.url ?? url
        } catch {
            throw LookupError.network(error.localizedDescription)
        }
    }

    private func oEmbed(for target: String) async throws -> OEmbedResponse {
        var components = URLComponents(string: "https://www.tiktok.com/oembed")!
        components.queryItems = [URLQueryItem(name: "url", value: target)]
        var request = URLRequest(url: components.url!)
        request.setValue(userAgent, forHTTPHeaderField: "User-Agent")
        request.setValue("application/json", forHTTPHeaderField: "Accept")

        let data: Data
        let response: URLResponse
        do {
            (data, response) = try await session.data(for: request)
        } catch {
            throw LookupError.network(error.localizedDescription)
        }
        let status = (response as? HTTPURLResponse)?.statusCode ?? 0
        switch status {
        case 200:
            guard let decoded = try? JSONDecoder().decode(OEmbedResponse.self, from: data),
                  decoded.html != nil || decoded.authorName != nil || decoded.title != nil else {
                throw LookupError.notFound
            }
            return decoded
        case 400, 404:
            throw LookupError.notFound
        default:
            throw LookupError.http(status)
        }
    }
}
