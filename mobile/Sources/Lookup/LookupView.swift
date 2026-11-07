import SwiftUI
import UIKit

struct LookupView: View {
    /// Vom Recon-Hub übergebenes Ziel (z. B. „@name“); wird einmal ausgeführt und dann geleert.
    @Binding var incoming: String?
    @State private var model = LookupViewModel()
    @State private var showEmbed = false
    @FocusState private var focused: Bool

    var body: some View {
        NavigationStack {
            ZStack {
                HackerBackground()
                ScrollView {
                    VStack(spacing: 18) {
                        ScreenHeader(
                            eyebrow: "FLMP Sentinel · OSINT",
                            title: "TikTok Lookup",
                            subtitle: "Username, Profil-Link, Video-Link oder Video-ID eingeben. Es werden nur öffentliche Daten über TikToks offizielle oEmbed-Schnittstelle abgefragt."
                        )
                        .padding(.top, 8)

                        searchField
                        if !model.history.isEmpty && model.result == nil { historyChips }

                        if model.isLoading {
                            ScanningIndicator()
                                .transition(.opacity.combined(with: .scale(scale: 0.95)))
                        }

                        if let result = model.result, !model.isLoading {
                            ResultSection(result: result, showEmbed: $showEmbed)
                                .transition(.move(edge: .bottom).combined(with: .opacity))
                        }

                        NoteText(
                            text: "Keine Personensuche, keine privaten Daten, keine plattformübergreifende Zuordnung. Ein öffentliches Profil sagt nichts darüber aus, wer dahintersteht.",
                            systemImage: "hand.raised"
                        )
                        .padding(.horizontal, 4)
                        .padding(.bottom, 24)
                    }
                    .padding(.horizontal, 16)
                    .animation(.spring(response: 0.45, dampingFraction: 0.85), value: model.result)
                    .animation(.easeInOut, value: model.isLoading)
                }
                .scrollDismissesKeyboard(.interactively)
            }
            .toolbar(.hidden, for: .navigationBar)
        }
        .onAppear(perform: consumeIncoming)
        .onChange(of: incoming) { consumeIncoming() }
    }

    private func consumeIncoming() {
        guard let value = incoming else { return }
        incoming = nil
        guard !value.isEmpty else { return }
        showEmbed = false
        Task { await model.run(value) }
    }

    private var searchField: some View {
        HStack(spacing: 10) {
            Text("target>")
                .font(.subheadline.monospaced().weight(.bold))
                .foregroundStyle(Theme.mint)
                .shadow(color: Theme.mint.opacity(0.7), radius: 4)
            TextField("@username", text: $model.query)
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()
                .keyboardType(.URL)
                .submitLabel(.search)
                .focused($focused)
                .onSubmit(search)
                .foregroundStyle(Theme.text)
            if model.query.isEmpty {
                Button {
                    if let text = UIPasteboard.general.string {
                        model.query = text
                        search()
                    }
                } label: {
                    Image(systemName: "doc.on.clipboard")
                }
                .foregroundStyle(Theme.muted)
                .accessibilityLabel("Einfügen und suchen")
            } else {
                Button { model.query = ""; model.result = nil } label: {
                    Image(systemName: "xmark.circle.fill")
                }
                .foregroundStyle(Theme.muted)
            }
            Button(action: search) {
                Text("RUN")
                    .font(.subheadline.monospaced().weight(.heavy))
                    .foregroundStyle(Color.black)
                    .frame(width: 52, height: 38)
                    .background(Theme.mint)
                    .shadow(color: Theme.mint.opacity(0.7), radius: 10)
            }
            .disabled(model.query.trimmingCharacters(in: .whitespaces).isEmpty || model.isLoading)
        }
        .padding(.leading, 12)
        .padding(.trailing, 5)
        .padding(.vertical, 5)
        .background(Color.black.opacity(0.85))
        .overlay(Rectangle().strokeBorder(focused ? Theme.mint : Theme.line, lineWidth: 1))
        .shadow(color: Theme.mint.opacity(focused ? 0.45 : 0), radius: 12)
        .animation(.easeOut(duration: 0.2), value: focused)
    }

    private var historyChips: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text("Zuletzt gesucht").font(.caption.weight(.semibold)).foregroundStyle(Theme.muted)
                Spacer()
                Button("Löschen") { model.clearHistory() }
                    .font(.caption)
                    .foregroundStyle(Theme.muted)
            }
            ScrollView(.horizontal, showsIndicators: false) {
                HStack(spacing: 8) {
                    ForEach(model.history, id: \.self) { item in
                        Button(item) { Task { await model.run(item) } }
                            .buttonStyle(ChipButtonStyle())
                    }
                }
            }
        }
    }

    private func search() {
        focused = false
        showEmbed = false
        Task { await model.run() }
    }
}

// MARK: - Lade-Animation

/// Optik: Radar + Fake-Terminal-Ausgabe, während die echte Abfrage läuft.
private struct ScanningIndicator: View {
    @State private var spin = false

    var body: some View {
        GlassCard {
            HStack(spacing: 14) {
                ZStack {
                    Circle().strokeBorder(Theme.line, lineWidth: 1)
                    Circle().strokeBorder(Theme.line, lineWidth: 1).padding(9)
                    AngularGradient(colors: [Theme.mint.opacity(0.7), .clear, .clear], center: .center)
                        .clipShape(Circle())
                        .rotationEffect(.degrees(spin ? 360 : 0))
                }
                .frame(width: 54, height: 54)
                VStack(alignment: .leading, spacing: 4) {
                    Text("SCANNING TARGET …")
                        .font(.subheadline.monospaced().weight(.bold))
                        .foregroundStyle(Theme.mint)
                    AsciiProgress()
                }
            }
            FakeTerminalLog()
        }
        .onAppear {
            withAnimation(.linear(duration: 1.6).repeatForever(autoreverses: false)) { spin = true }
        }
    }
}

// MARK: - Ergebnis

private struct ResultSection: View {
    let result: LookupResult
    @Binding var showEmbed: Bool
    @Environment(\.openURL) private var openURL

    var body: some View {
        VStack(spacing: 16) {
            profileCard
            if let video = result.video { videoCard(video) }
            if let check = result.check { formatCard(check) }
            if case .found(let embed) = result.profile, let html = embed.html { embedCard(html) }
            exportRow
        }
    }

    private var profileCard: some View {
        GlassCard(tint: tint) {
            HStack(alignment: .center, spacing: 14) {
                Avatar(name: displayName ?? result.username ?? "?", tint: tint)
                VStack(alignment: .leading, spacing: 4) {
                    Text(displayName ?? "Unbekannt")
                        .font(.title3.weight(.bold))
                        .foregroundStyle(Theme.text)
                        .lineLimit(2)
                    if let username = result.username, !username.isEmpty {
                        Text("@\(username)").font(Theme.mono).foregroundStyle(Theme.cyan)
                    }
                }
                Spacer(minLength: 0)
            }
            statusBadge
            if let detail = statusDetail { NoteText(text: detail) }
            if let resolved = result.resolvedURL {
                KeyValueRow(key: "Kurzlink-Ziel", value: resolved.host() ?? resolved.absoluteString, mono: true)
            }
            if let url = result.profileURL, case .found = result.profile {
                HStack(spacing: 10) {
                    Button { openURL(url) } label: {
                        Label("In TikTok öffnen", systemImage: "arrow.up.forward.app")
                    }
                    .buttonStyle(GlowButtonStyle())
                    ShareLink(item: url) {
                        Image(systemName: "square.and.arrow.up").frame(width: 22)
                    }
                    .buttonStyle(GlowButtonStyle(color: Theme.cyan, filled: false))
                    .frame(width: 70)
                }
            }
        }
    }

    private func videoCard(_ video: VideoInfo) -> some View {
        GlassCard(tint: Theme.violet) {
            CardTitle(title: "Video", systemImage: "play.rectangle", tint: Theme.violet)
            if let thumb = video.thumbnail {
                AsyncImage(url: thumb) { image in
                    image.resizable().scaledToFill()
                } placeholder: {
                    Rectangle().fill(Theme.panel)
                }
                .frame(height: 180)
                .frame(maxWidth: .infinity)
                .clipShape(RoundedRectangle(cornerRadius: 2, style: .continuous))
            }
            if let title = video.title, !title.isEmpty {
                Text(title).font(.subheadline).foregroundStyle(Theme.text).lineLimit(4)
            }
            KeyValueRow(key: "Video-ID", value: video.id, mono: true)
            if let created = video.createdAt {
                KeyValueRow(key: "Hochgeladen", value: created.formatted(date: .abbreviated, time: .shortened))
                KeyValueRow(key: "Alter", value: created.formatted(.relative(presentation: .named)), valueColor: Theme.violet)
                NoteText(text: "Aus der Video-ID dekodiert (obere 32 Bit = Unix-Zeit). Lokal berechnet, keine Anfrage nötig.")
            } else {
                NoteText(text: "Aus dieser ID ließ sich kein plausibler Zeitstempel lesen.")
            }
        }
    }

    private func formatCard(_ check: UsernameCheck) -> some View {
        GlassCard(tint: check.isPlausible ? Theme.mint : Theme.red) {
            CardTitle(title: "Formatprüfung (lokal)", systemImage: "textformat.abc",
                      tint: check.isPlausible ? Theme.mint : Theme.red)
            KeyValueRow(key: "Normalisiert", value: check.normalized, mono: true)
            KeyValueRow(key: "Länge", value: "\(check.length) / \(TikTokParser.maxLength)")
            if check.isPlausible {
                CheckRow(ok: true, text: "Entspricht den TikTok-Regeln (Buchstaben, Zahlen, _ und ., kein Punkt am Ende).")
            } else {
                ForEach(check.issues, id: \.self) { CheckRow(ok: false, text: $0) }
            }
        }
    }

    private func embedCard(_ html: String) -> some View {
        GlassCard(tint: Theme.cyan) {
            CardTitle(title: "Offizielle Profil-Vorschau", systemImage: "rectangle.inset.filled.and.person.filled", tint: Theme.cyan)
            if showEmbed {
                EmbedWebView(html: html)
                    .frame(height: 520)
                    .clipShape(RoundedRectangle(cornerRadius: 2, style: .continuous))
            } else {
                NoteText(text: "Lädt TikToks Embed-Skript (embed.js) direkt von tiktok.com. Dabei sieht TikTok deine IP-Adresse.")
                Button { withAnimation { showEmbed = true } } label: {
                    Label("Vorschau laden", systemImage: "eye")
                }
                .buttonStyle(GlowButtonStyle(color: Theme.cyan, filled: false))
            }
        }
    }

    private var exportRow: some View {
        HStack(spacing: 10) {
            ShareLink(item: result.jsonReport, preview: SharePreview("Sentinel-Bericht")) {
                Label("JSON-Bericht", systemImage: "curlybraces")
            }
            .buttonStyle(GlowButtonStyle(color: Theme.violet, filled: false))
            Button {
                UIPasteboard.general.string = result.username.map { "@\($0)" } ?? result.query
            } label: {
                Label("Kopieren", systemImage: "doc.on.doc")
            }
            .buttonStyle(GlowButtonStyle(color: Theme.muted, filled: false))
        }
    }

    // MARK: Hilfen

    private var displayName: String? {
        if case .found(let embed) = result.profile {
            return embed.authorName ?? embed.title
        }
        return result.video?.author
    }

    private var tint: Color {
        switch result.profile {
        case .found: return Theme.mint
        case .notFound: return Theme.amber
        case .failed: return Theme.red
        case .skipped: return Theme.violet
        }
    }

    @ViewBuilder private var statusBadge: some View {
        switch result.profile {
        case .found:
            StatusBadge(text: "Öffentliches Profil gefunden", color: Theme.mint, systemImage: "checkmark.seal.fill")
        case .notFound:
            StatusBadge(text: "Kein öffentliches Profil", color: Theme.amber, systemImage: "questionmark.circle")
        case .failed:
            StatusBadge(text: "Fehler", color: Theme.red, systemImage: "exclamationmark.triangle.fill")
        case .skipped:
            StatusBadge(text: "Keine Profilabfrage", color: Theme.violet, systemImage: "minus.circle")
        }
    }

    private var statusDetail: String? {
        switch result.profile {
        case .found: return nil
        case .notFound(let text), .failed(let text), .skipped(let text): return text
        }
    }
}

private struct Avatar: View {
    let name: String
    let tint: Color

    var body: some View {
        Text(String(name.prefix(1)).uppercased())
            .font(.system(size: 26, weight: .heavy, design: .rounded))
            .foregroundStyle(Theme.bg)
            .frame(width: 60, height: 60)
            .background(
                LinearGradient(colors: [tint, Theme.cyan], startPoint: .topLeading, endPoint: .bottomTrailing),
                in: RoundedRectangle(cornerRadius: 2, style: .continuous)
            )
            .shadow(color: tint.opacity(0.5), radius: 12)
    }
}
