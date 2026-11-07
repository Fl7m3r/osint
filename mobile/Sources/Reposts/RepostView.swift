import SwiftUI

struct RepostView: View {
    @State private var session = RepostSession()
    @AppStorage("repost.acknowledgedRisk") private var acknowledged = false
    @State private var browserExpanded = false
    @State private var confirmSignOut = false

    var body: some View {
        NavigationStack {
            ZStack {
                HackerBackground()
                ScrollView {
                    VStack(spacing: 18) {
                        ScreenHeader(
                            eyebrow: "Eigenes Konto",
                            title: "Repost-Remover",
                            subtitle: "Entfernt deine eigenen Reposts – eins nach dem anderen, jeweils nach deinem Tipp. Du meldest dich direkt bei TikTok an; die App sieht dein Passwort nie."
                        )
                        .padding(.top, 8)

                        riskCard

                        if acknowledged {
                            loginCard
                            browserCard
                            usernameCard
                            if !session.items.isEmpty { repostsCard }
                            if !session.log.isEmpty { logCard }
                            signOutButton
                        }
                    }
                    .padding(.horizontal, 16)
                    .padding(.bottom, 28)
                    .animation(.spring(response: 0.4, dampingFraction: 0.85), value: acknowledged)
                    .animation(.spring(response: 0.4, dampingFraction: 0.85), value: session.items)
                }
                .scrollDismissesKeyboard(.interactively)
            }
            .toolbar(.hidden, for: .navigationBar)
            .task { await session.refreshLogin() }
            .confirmationDialog("TikTok-Sitzung löschen?", isPresented: $confirmSignOut, titleVisibility: .visible) {
                Button("Abmelden & Daten löschen", role: .destructive) { Task { await session.signOut() } }
            } message: {
                Text("Löscht Cookies und Website-Daten von tiktok.com aus dieser App.")
            }
        }
    }

    // MARK: Risiko

    private var riskCard: some View {
        GlassCard(tint: Theme.amber) {
            CardTitle(title: "Bitte zuerst lesen", systemImage: "exclamationmark.triangle.fill", tint: Theme.amber)
            VStack(alignment: .leading, spacing: 8) {
                bullet("TikTok hat keine offizielle Schnittstelle für Reposts. Die App bedient deshalb die normale TikTok-Website für dich – das ist inoffiziell.")
                bullet("TikToks Nutzungsbedingungen verbieten automatisierte Zugriffe, die mehr Anfragen erzeugen, als ein Mensch könnte. Darum gibt es hier keinen „Alles löschen“-Knopf: jede Entfernung braucht deinen Tipp, dazwischen liegt eine Pause.")
                bullet("Trotzdem kann TikTok so etwas erkennen und dein Konto einschränken. Nutzung auf eigenes Risiko.")
                bullet("Wenn TikTok die Website ändert, findet die App die Buttons evtl. nicht mehr. Du kannst dann in der Live-Ansicht von Hand entfernen.")
            }
            Toggle(isOn: $acknowledged.animation()) {
                Text("Verstanden – ich nutze das nur für mein eigenes Konto.")
                    .font(.subheadline.weight(.semibold))
                    .foregroundStyle(Theme.text)
            }
            .tint(Theme.amber)
        }
    }

    private func bullet(_ text: String) -> some View {
        HStack(alignment: .top, spacing: 8) {
            Circle().fill(Theme.amber).frame(width: 5, height: 5).padding(.top, 7)
            Text(text).font(.footnote).foregroundStyle(Theme.text.opacity(0.9))
                .fixedSize(horizontal: false, vertical: true)
        }
    }

    // MARK: Schritt 1 – Anmeldung

    private var loginCard: some View {
        GlassCard(tint: session.isLoggedIn ? Theme.mint : Theme.cyan) {
            HStack {
                CardTitle(title: "1 · Bei TikTok anmelden", systemImage: "person.badge.key.fill",
                          tint: session.isLoggedIn ? Theme.mint : Theme.cyan)
                Spacer()
                StatusBadge(text: session.isLoggedIn ? "Angemeldet" : "Abgemeldet",
                            color: session.isLoggedIn ? Theme.mint : Theme.muted,
                            systemImage: session.isLoggedIn ? "checkmark.circle.fill" : "circle.dashed")
            }
            NoteText(text: "Die Anmeldung läuft auf tiktok.com in der Live-Ansicht unten. Die Sitzung bleibt nur auf diesem iPhone gespeichert.", systemImage: "lock.shield")
            HStack(spacing: 10) {
                Button {
                    browserExpanded = true
                    Task { await session.openLogin() }
                } label: {
                    Label(session.isLoggedIn ? "Erneut öffnen" : "Anmelden", systemImage: "arrow.right.circle.fill")
                }
                .buttonStyle(GlowButtonStyle(color: Theme.cyan, filled: !session.isLoggedIn))
                Button { Task { await session.refreshLogin() } } label: {
                    Label("Prüfen", systemImage: "arrow.clockwise")
                }
                .buttonStyle(GlowButtonStyle(color: Theme.muted, filled: false))
            }
            .disabled(session.isBusy)
        }
    }

    // MARK: Live-Ansicht

    private var browserCard: some View {
        GlassCard(tint: Theme.cyan) {
            HStack(spacing: 10) {
                Image(systemName: "globe").foregroundStyle(Theme.cyan)
                Text(session.host).font(Theme.mono).foregroundStyle(Theme.muted).lineLimit(1)
                Spacer()
                Button { session.browser.goBack() } label: { Image(systemName: "chevron.left") }
                Button { session.browser.reload() } label: { Image(systemName: "arrow.clockwise") }
                Button { withAnimation(.spring) { browserExpanded.toggle() } } label: {
                    Image(systemName: browserExpanded ? "arrow.down.right.and.arrow.up.left" : "arrow.up.left.and.arrow.down.right")
                }
            }
            .font(.subheadline.weight(.semibold))
            .foregroundStyle(Theme.text)

            BrowserContainer(browser: session.browser)
                .frame(height: browserExpanded ? 600 : 280)
                .clipShape(RoundedRectangle(cornerRadius: 2, style: .continuous))
                .overlay(
                    RoundedRectangle(cornerRadius: 2, style: .continuous)
                        .strokeBorder(Theme.line, lineWidth: 1)
                )
                .overlay(alignment: .bottom) {
                    if session.isBusy {
                        VStack(alignment: .leading, spacing: 6) {
                            Text("> " + session.status)
                                .font(.caption.monospaced().weight(.bold))
                                .foregroundStyle(Theme.mint)
                                .lineLimit(2)
                            FakeTerminalLog(maxVisible: 3)
                        }
                        .padding(10)
                        .background(Color.black.opacity(0.88))
                        .overlay(Rectangle().strokeBorder(Theme.mint.opacity(0.6), lineWidth: 1))
                        .padding(8)
                        .transition(.move(edge: .bottom).combined(with: .opacity))
                    }
                }
        }
    }

    // MARK: Schritt 2 – Username & Scan

    private var usernameCard: some View {
        GlassCard(tint: Theme.violet) {
            CardTitle(title: "2 · Reposts laden", systemImage: "square.stack.3d.down.right.fill", tint: Theme.violet)
            HStack(spacing: 8) {
                Text("@").font(.headline).foregroundStyle(Theme.violet)
                TextField("dein_username", text: $session.ownUsername)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                    .foregroundStyle(Theme.text)
                    .onSubmit { session.saveUsername() }
                Button("Erkennen") { Task { await session.detectUsername() } }
                    .buttonStyle(ChipButtonStyle())
                    .disabled(!session.isLoggedIn || session.isBusy)
            }
            .padding(12)
            .background(Theme.panel.opacity(0.6), in: RoundedRectangle(cornerRadius: 2, style: .continuous))

            Button {
                session.saveUsername()
                Task { await session.scan() }
            } label: {
                Label(session.phase == .scanning ? "Lese Reposts …" : "Meine Reposts laden",
                      systemImage: "arrow.down.doc.fill")
            }
            .buttonStyle(GlowButtonStyle(color: Theme.violet))
            .disabled(!session.isLoggedIn || session.ownUsername.isEmpty || session.isBusy)

            Text(session.status)
                .font(.footnote)
                .foregroundStyle(Theme.muted)
                .contentTransition(.opacity)
                .fixedSize(horizontal: false, vertical: true)
        }
    }

    // MARK: Schritt 3 – Liste

    private var repostsCard: some View {
        GlassCard(tint: Theme.mint) {
            CardTitle(title: "3 · Einzeln entfernen", systemImage: "trash.slash.fill")
            HStack(spacing: 12) {
                counter(value: session.items.count, label: "gefunden", color: Theme.cyan)
                counter(value: session.removedCount, label: "entfernt", color: Theme.mint)
                counter(value: session.pendingCount, label: "offen", color: Theme.amber)
            }

            Button { Task { await session.removeNext() } } label: {
                if session.cooldownRemaining > 0 {
                    Label("Pause … \(session.cooldownRemaining) s", systemImage: "hourglass")
                        .contentTransition(.numericText(countsDown: true))
                } else {
                    Label("Nächsten Repost entfernen", systemImage: "minus.circle.fill")
                }
            }
            .buttonStyle(GlowButtonStyle(color: Theme.red))
            .disabled(session.pendingCount == 0 || session.isBusy)
            .sensoryFeedback(.success, trigger: session.removedCount)

            VStack(spacing: 10) {
                ForEach(session.items) { item in
                    RepostRow(item: item, busy: session.isBusy) {
                        Task { await session.remove(item.id) }
                    } markDone: {
                        session.markHandled(item.id)
                    } retry: {
                        session.reset(item.id)
                    }
                }
            }
        }
    }

    private func counter(value: Int, label: String, color: Color) -> some View {
        VStack(spacing: 2) {
            Text("\(value)")
                .font(.system(.title2, design: .rounded).weight(.heavy))
                .foregroundStyle(color)
                .contentTransition(.numericText(value: Double(value)))
            Text(label).font(.caption).foregroundStyle(Theme.muted)
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, 10)
        .background(color.opacity(0.08), in: RoundedRectangle(cornerRadius: 2, style: .continuous))
    }

    // MARK: Protokoll & Abmelden

    private var logCard: some View {
        GlassCard(tint: Theme.line) {
            CardTitle(title: "Protokoll", systemImage: "list.bullet.rectangle", tint: Theme.muted)
            VStack(alignment: .leading, spacing: 4) {
                ForEach(session.log.prefix(8), id: \.self) { line in
                    Text(line).font(Theme.mono).foregroundStyle(Theme.muted).lineLimit(1)
                }
            }
        }
    }

    private var signOutButton: some View {
        Button(role: .destructive) { confirmSignOut = true } label: {
            Label("Abmelden & TikTok-Daten löschen", systemImage: "rectangle.portrait.and.arrow.right")
        }
        .buttonStyle(GlowButtonStyle(color: Theme.red, filled: false))
        .disabled(session.isBusy)
    }
}

// MARK: - Zeile

private struct RepostRow: View {
    let item: RepostItem
    let busy: Bool
    let remove: () -> Void
    let markDone: () -> Void
    let retry: () -> Void

    @Environment(\.openURL) private var openURL

    var body: some View {
        HStack(spacing: 12) {
            AsyncImage(url: item.thumbnail) { image in
                image.resizable().scaledToFill()
            } placeholder: {
                ZStack {
                    Theme.panel
                    Image(systemName: "play.fill").foregroundStyle(Theme.muted)
                }
            }
            .frame(width: 52, height: 70)
            .clipShape(RoundedRectangle(cornerRadius: 2, style: .continuous))
            .overlay {
                if item.state == .removed {
                    RoundedRectangle(cornerRadius: 2, style: .continuous).fill(.black.opacity(0.55))
                    Image(systemName: "checkmark").font(.headline.weight(.bold)).foregroundStyle(Theme.mint)
                }
            }

            VStack(alignment: .leading, spacing: 4) {
                Text("@\(item.author)").font(.subheadline.weight(.semibold)).foregroundStyle(Theme.text).lineLimit(1)
                Text(item.id).font(.caption2.monospaced()).foregroundStyle(Theme.muted).lineLimit(1)
                stateLabel
            }
            Spacer(minLength: 0)
            actions
        }
        .padding(10)
        .background(Theme.panel.opacity(0.55), in: RoundedRectangle(cornerRadius: 2, style: .continuous))
        .contextMenu {
            Button { openURL(item.url) } label: { Label("In TikTok öffnen", systemImage: "arrow.up.forward.app") }
            Button { markDone() } label: { Label("Als erledigt markieren", systemImage: "checkmark") }
            Button { retry() } label: { Label("Zurücksetzen", systemImage: "arrow.uturn.backward") }
        }
    }

    @ViewBuilder private var stateLabel: some View {
        switch item.state {
        case .pending: StatusBadge(text: "Repost", color: Theme.cyan)
        case .working: StatusBadge(text: "Wird entfernt …", color: Theme.amber, systemImage: "clock")
        case .removed: StatusBadge(text: "Entfernt", color: Theme.mint, systemImage: "checkmark")
        case .failed(let reason):
            Text(reason).font(.caption2).foregroundStyle(Theme.red).lineLimit(2)
        }
    }

    @ViewBuilder private var actions: some View {
        switch item.state {
        case .pending:
            Button(action: remove) {
                Image(systemName: "minus.circle.fill").font(.title2)
                    .foregroundStyle(Theme.red)
                    .symbolRenderingMode(.hierarchical)
            }
            .disabled(busy)
            .accessibilityLabel("Repost entfernen")
        case .working:
            ProgressView().tint(Theme.amber)
        case .removed:
            EmptyView()
        case .failed:
            Button(action: retry) {
                Image(systemName: "arrow.clockwise.circle.fill").font(.title2).foregroundStyle(Theme.amber)
            }
            .accessibilityLabel("Erneut versuchen")
        }
    }
}
