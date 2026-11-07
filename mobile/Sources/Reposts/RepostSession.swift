import Foundation
import Observation

struct RepostItem: Identifiable, Equatable {
    enum State: Equatable {
        case pending, working, removed
        case failed(String)
    }

    let id: String
    let author: String
    let url: URL
    let thumbnail: URL?
    var state: State = .pending
}

private struct ScanResponse: Decodable {
    struct Item: Decodable {
        let id: String
        let author: String
        let url: String
        let thumb: String?
    }
    let ok: Bool
    let error: String?
    let items: [Item]
}

private struct RemoveResponse: Decodable {
    let ok: Bool
    let error: String?
}

private struct UsernameResponse: Decodable {
    let username: String?
}

/// Steuert den assistierten Repost-Remover.
///
/// Absichtlich KEIN Massen-Automatikmodus: Jede Entfernung startet erst nach einem Tipp von dir,
/// und zwischen zwei Entfernungen liegt eine Pause. So bleibt es bei menschlichem Tempo,
/// wie es TikToks Nutzungsbedingungen verlangen.
@MainActor
@Observable
final class RepostSession {
    enum Phase: Equatable { case idle, loading, scanning, removing }

    @ObservationIgnored let browser = TikTokBrowser()

    var phase: Phase = .idle
    var isLoggedIn = false
    var ownUsername: String
    var items: [RepostItem] = []
    var status = "Bereit."
    var log: [String] = []
    var host = "—"
    var cooldownRemaining = 0

    /// Mindestabstand zwischen zwei Entfernungen (Sekunden).
    let cooldown = 6

    @ObservationIgnored private var lastRemoval: Date?

    var removedCount: Int { items.filter { $0.state == .removed }.count }
    var pendingCount: Int { items.filter { $0.state == .pending }.count }
    var isBusy: Bool { phase != .idle }

    init() {
        ownUsername = UserDefaults.standard.string(forKey: "repost.ownUsername") ?? ""
        browser.onChange = { [weak self] in
            Task { @MainActor in await self?.browserChanged() }
        }
    }

    // MARK: Anmeldung

    func openLogin() async {
        phase = .loading
        status = "Melde dich in der Live-Ansicht direkt bei TikTok an."
        await browser.load(URL(string: "https://www.tiktok.com/login")!)
        phase = .idle
    }

    func refreshLogin() async {
        isLoggedIn = await browser.hasSessionCookie()
        status = isLoggedIn ? "Angemeldet bei TikTok." : "Nicht angemeldet."
    }

    func detectUsername() async {
        guard isLoggedIn else { return }
        if browser.webView.url?.host()?.hasSuffix("tiktok.com") != true {
            await browser.load(URL(string: "https://www.tiktok.com/")!)
        }
        guard let json = try? await browser.run(RepostScripts.detectUsername),
              let data = json.data(using: .utf8),
              let response = try? JSONDecoder().decode(UsernameResponse.self, from: data),
              let name = response.username, !name.isEmpty else {
            status = "Username nicht erkannt – bitte von Hand eintragen."
            return
        }
        ownUsername = name
        saveUsername()
        status = "Erkannt: @\(name)"
    }

    func signOut() async {
        phase = .loading
        await browser.clearAllWebsiteData()
        items = []
        isLoggedIn = false
        log.removeAll()
        status = "TikTok-Sitzung und Website-Daten auf diesem iPhone gelöscht."
        phase = .idle
    }

    // MARK: Reposts laden

    func scan() async {
        let handle = normalizedUsername
        guard !handle.isEmpty, !isBusy else { return }
        phase = .scanning
        defer { phase = .idle }

        status = "Öffne @\(handle) …"
        await browser.load(URL(string: "https://www.tiktok.com/@\(handle)")!)
        try? await Task.sleep(nanoseconds: 2_500_000_000)

        status = "Lese den Reposts-Tab (scrollt langsam) …"
        do {
            let json = try await browser.run(RepostScripts.scanReposts, arguments: ["ownUser": handle, "maxRounds": 40])
            let response = try JSONDecoder().decode(ScanResponse.self, from: Data(json.utf8))
            guard response.ok else {
                status = "Reposts-Tab nicht gefunden. Ist das Profil richtig und bist du angemeldet? TikTok zeigt den Tab nur dem Kontoinhaber."
                append("Scan: Tab nicht gefunden")
                return
            }
            let known = Dictionary(uniqueKeysWithValues: items.map { ($0.id, $0) })
            items = response.items.compactMap { item in
                guard let url = URL(string: item.url) else { return nil }
                return known[item.id] ?? RepostItem(
                    id: item.id,
                    author: item.author,
                    url: url,
                    thumbnail: item.thumb.flatMap(URL.init(string:))
                )
            }
            status = items.isEmpty ? "Keine Reposts gefunden." : "\(items.count) Reposts gefunden. Prüfe die Liste und entferne sie einzeln."
            append("Scan: \(items.count) Einträge")
        } catch {
            status = "Scan fehlgeschlagen: \(error.localizedDescription)"
            append("Scan-Fehler: \(error.localizedDescription)")
        }
    }

    // MARK: Entfernen (immer nur eins, nach Tipp)

    func removeNext() async {
        guard let next = items.first(where: { $0.state == .pending }) else { return }
        await remove(next.id)
    }

    func remove(_ id: String) async {
        guard !isBusy, let index = items.firstIndex(where: { $0.id == id }) else { return }
        phase = .removing
        defer { phase = .idle; cooldownRemaining = 0 }

        await waitForCooldown()

        items[index].state = .working
        status = "Entferne Repost von @\(items[index].author) …"
        await browser.load(items[index].url)

        do {
            let json = try await browser.run(RepostScripts.removeRepost)
            let response = try JSONDecoder().decode(RemoveResponse.self, from: Data(json.utf8))
            lastRemoval = Date()
            if response.ok {
                items[index].state = .removed
                status = "Entfernt. \(pendingCount) übrig."
                append("Entfernt: \(items[index].id)")
            } else {
                let reason = response.error == "still-present"
                    ? "Button geklickt, aber Repost scheint noch aktiv."
                    : "Kein „Repost entfernen“-Button gefunden – evtl. schon entfernt oder Layout geändert."
                items[index].state = .failed(reason)
                status = reason + " Du kannst es in der Live-Ansicht von Hand erledigen."
                append("Fehlgeschlagen: \(items[index].id) (\(response.error ?? "?"))")
            }
        } catch {
            items[index].state = .failed(error.localizedDescription)
            status = "Fehler: \(error.localizedDescription)"
            append("Fehler: \(error.localizedDescription)")
        }
    }

    func markHandled(_ id: String) {
        guard let index = items.firstIndex(where: { $0.id == id }) else { return }
        items[index].state = .removed
    }

    func reset(_ id: String) {
        guard let index = items.firstIndex(where: { $0.id == id }) else { return }
        items[index].state = .pending
    }

    // MARK: Hilfen

    func saveUsername() {
        UserDefaults.standard.set(ownUsername, forKey: "repost.ownUsername")
    }

    private var normalizedUsername: String {
        var handle = ownUsername.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        if handle.hasPrefix("@") { handle.removeFirst() }
        return handle
    }

    private func waitForCooldown() async {
        guard let lastRemoval else { return }
        var remaining = cooldown - Int(Date().timeIntervalSince(lastRemoval))
        while remaining > 0 {
            cooldownRemaining = remaining
            status = "Kurze Pause (\(remaining) s) – schützt dein Konto vor zu vielen Aktionen am Stück."
            try? await Task.sleep(nanoseconds: 1_000_000_000)
            remaining -= 1
        }
        cooldownRemaining = 0
    }

    private func browserChanged() async {
        host = browser.currentHost
        let wasLoggedIn = isLoggedIn
        isLoggedIn = await browser.hasSessionCookie()
        if isLoggedIn && !wasLoggedIn {
            status = "Angemeldet. Trage jetzt deinen Username ein oder lass ihn erkennen."
            append("Anmeldung erkannt")
        }
    }

    private func append(_ line: String) {
        let time = Date().formatted(date: .omitted, time: .standard)
        log.insert("\(time)  \(line)", at: 0)
        if log.count > 30 { log.removeLast(log.count - 30) }
    }
}
