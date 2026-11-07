import Foundation
import Observation

struct VideoInfo: Equatable {
    let id: String
    let createdAt: Date?
    let title: String?
    let author: String?
    let thumbnail: URL?
}

enum ProfileStatus: Equatable {
    case found(OEmbedResponse)
    case notFound(String)
    case failed(String)
    case skipped(String)
}

struct LookupResult: Identifiable, Equatable {
    let id = UUID()
    let query: String
    let resolvedURL: URL?
    let username: String?
    let check: UsernameCheck?
    let profile: ProfileStatus
    let video: VideoInfo?
    let fetchedAt = Date()

    var profileURL: URL? {
        username.flatMap { URL(string: "https://www.tiktok.com/@\($0)") }
    }

    /// JSON-Bericht wie der Export im Dashboard des Python-Tools.
    var jsonReport: String {
        var dict: [String: Any] = [
            "query": query,
            "fetched_at": ISO8601DateFormatter().string(from: fetchedAt),
            "scope_note": "Nur öffentliche oEmbed-Daten von TikTok und lokale Prüfungen. Keine privaten Daten, keine Identitätszuordnung."
        ]
        if let resolvedURL { dict["resolved_url"] = resolvedURL.absoluteString }
        if let username { dict["username"] = username }
        if let check {
            dict["format"] = [
                "normalized_handle": check.normalized,
                "length": check.length,
                "format_status": check.isPlausible ? "plausible" : "invalid",
                "format_issues": check.issues
            ]
        }
        switch profile {
        case .found(let embed):
            dict["profile"] = [
                "status": "public_embed_found",
                "display_name": embed.authorName ?? embed.title ?? "",
                "profile_url": embed.authorURL ?? profileURL?.absoluteString ?? "",
                "source": "https://www.tiktok.com/oembed"
            ]
        case .notFound(let message):
            dict["profile"] = ["status": "not_found", "detail": message]
        case .failed(let message):
            dict["profile"] = ["status": "error", "detail": message]
        case .skipped(let message):
            dict["profile"] = ["status": "skipped", "detail": message]
        }
        if let video {
            var v: [String: Any] = ["video_id": video.id]
            if let createdAt = video.createdAt {
                v["created_at_utc"] = ISO8601DateFormatter().string(from: createdAt)
            }
            if let title = video.title { v["title"] = title }
            if let author = video.author { v["author"] = author }
            dict["video"] = v
        }
        guard let data = try? JSONSerialization.data(withJSONObject: dict, options: [.prettyPrinted, .sortedKeys]),
              let text = String(data: data, encoding: .utf8) else { return "{}" }
        return text
    }
}

@MainActor
@Observable
final class LookupViewModel {
    var query = ""
    var isLoading = false
    var result: LookupResult?
    var history: [String] = []

    private let service = TikTokLookupService()
    private let historyKey = "lookup.history"

    init() {
        history = UserDefaults.standard.stringArray(forKey: historyKey) ?? []
    }

    func clearHistory() {
        history = []
        UserDefaults.standard.removeObject(forKey: historyKey)
    }

    func run(_ text: String? = nil) async {
        if let text { query = text }
        let raw = query.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !raw.isEmpty, !isLoading else { return }
        isLoading = true
        defer { isLoading = false }

        // Nur Optik: Die Hacker-Animation soll kurz sichtbar sein, auch wenn TikTok schnell antwortet.
        let started = Date()
        remember(raw)
        await performLookup(raw)
        let elapsed = Date().timeIntervalSince(started)
        if elapsed < 1.8 {
            try? await Task.sleep(nanoseconds: UInt64((1.8 - elapsed) * 1_000_000_000))
        }
    }

    private func performLookup(_ raw: String) async {

        guard var input = TikTokParser.parse(raw) else { return }
        var resolvedURL: URL?

        if case .shortLink(let url) = input {
            do {
                let target = try await service.resolveShortLink(url)
                resolvedURL = target
                input = TikTokParser.parse(target.absoluteString) ?? .username("")
                if case .shortLink = input { input = .username("") }
            } catch {
                result = LookupResult(query: raw, resolvedURL: nil, username: nil, check: nil,
                                      profile: .failed(error.localizedDescription), video: nil)
                return
            }
        }

        switch input {
        case .username(let handle):
            result = await lookupProfile(query: raw, handle: handle, resolvedURL: resolvedURL, video: nil)

        case .video(let username, let videoID):
            var video = VideoInfo(id: videoID, createdAt: TikTokParser.timestamp(fromVideoID: videoID),
                                  title: nil, author: username, thumbnail: nil)
            if let username {
                if let embed = try? await service.videoEmbed(username: username, videoID: videoID) {
                    video = VideoInfo(id: videoID, createdAt: video.createdAt, title: embed.title,
                                      author: embed.authorName ?? username,
                                      thumbnail: embed.thumbnailURL.flatMap(URL.init(string:)))
                }
                result = await lookupProfile(query: raw, handle: username, resolvedURL: resolvedURL, video: video)
            } else {
                result = LookupResult(query: raw, resolvedURL: resolvedURL, username: nil, check: nil,
                                      profile: .skipped("Nur eine Video-ID ohne Username – Zeitstempel wurde lokal dekodiert."),
                                      video: video)
            }

        case .shortLink:
            break
        }
    }

    private func lookupProfile(query: String, handle: String, resolvedURL: URL?, video: VideoInfo?) async -> LookupResult {
        let check = TikTokParser.check(handle)
        guard check.isPlausible else {
            return LookupResult(query: query, resolvedURL: resolvedURL, username: check.normalized, check: check,
                                profile: .skipped("Ungültiges Format – es wurde keine Anfrage an TikTok gesendet."),
                                video: video)
        }
        let status: ProfileStatus
        do {
            status = .found(try await service.profileEmbed(username: check.normalized))
        } catch let error as LookupError where error == .notFound {
            status = .notFound(error.localizedDescription)
        } catch {
            status = .failed(error.localizedDescription)
        }
        return LookupResult(query: query, resolvedURL: resolvedURL, username: check.normalized, check: check,
                            profile: status, video: video)
    }

    private func remember(_ text: String) {
        history.removeAll { $0.caseInsensitiveCompare(text) == .orderedSame }
        history.insert(text, at: 0)
        history = Array(history.prefix(8))
        UserDefaults.standard.set(history, forKey: historyKey)
    }
}
