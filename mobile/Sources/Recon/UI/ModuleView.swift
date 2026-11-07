import SwiftUI
import UniformTypeIdentifiers

/// Ein Modul: Eingabe, Optionen, RUN, Fake-Terminal während der Abfrage, danach der Bericht.
struct ModuleView: View {
    let module: ReconModule
    let initialInput: String
    let autorun: Bool

    @Environment(\.dismiss) private var dismiss
    @State private var input = ""
    @State private var options = ReconOptions()
    @State private var isRunning = false
    @State private var report: Report?
    @State private var errorText: String?
    @State private var showImporter = false
    @State private var didAutorun = false
    @FocusState private var focused: Bool

    var body: some View {
        ZStack {
            HackerBackground()
            ScrollView {
                VStack(spacing: 16) {
                    topBar
                    ScreenHeader(eyebrow: module.command, title: module.title, subtitle: module.summary)

                    if module == .config { configPicker } else { inputField }
                    optionsCard

                    Button(action: start) {
                        Label(isRunning ? "running …" : "execute", systemImage: "play.fill")
                    }
                    .buttonStyle(GlowButtonStyle(color: module.tint))
                    .disabled(!canRun)

                    if isRunning {
                        RunningCard(module: module)
                            .transition(.opacity)
                    }
                    if let errorText, !isRunning {
                        GlassCard(tint: Theme.red) {
                            CardTitle(title: "Error", systemImage: "exclamationmark.triangle.fill", tint: Theme.red)
                            Text(errorText).font(.footnote.monospaced()).foregroundStyle(Theme.text)
                        }
                    }
                    if let report, !isRunning {
                        ReportView(report: report)
                            .transition(.move(edge: .bottom).combined(with: .opacity))
                    }
                }
                .padding(.horizontal, 16)
                .padding(.bottom, 28)
                .animation(.easeInOut(duration: 0.25), value: isRunning)
            }
            .scrollDismissesKeyboard(.interactively)
        }
        .toolbar(.hidden, for: .navigationBar)
        .fileImporter(isPresented: $showImporter, allowedContentTypes: [.plainText, .data, .item]) { result in
            loadConfig(result)
        }
        .onAppear {
            if input.isEmpty { input = initialInput }
            if autorun && !didAutorun && !initialInput.isEmpty {
                didAutorun = true
                start()
            }
        }
    }

    // MARK: Teile

    private var topBar: some View {
        HStack {
            Button { dismiss() } label: {
                Text("< cd ..").font(.subheadline.monospaced().weight(.bold)).foregroundStyle(Theme.mint)
            }
            Spacer()
            StatusBadge(text: isRunning ? "busy" : "ready", color: isRunning ? Theme.amber : Theme.mint)
        }
        .padding(.top, 8)
    }

    private var inputField: some View {
        HStack(spacing: 10) {
            Text("target>")
                .font(.subheadline.monospaced().weight(.bold))
                .foregroundStyle(module.tint)
            TextField(module.placeholder, text: $input)
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()
                .keyboardType(module == .phone ? .phonePad : .URL)
                .submitLabel(.go)
                .focused($focused)
                .onSubmit(start)
                .foregroundStyle(Theme.text)
            if !input.isEmpty {
                Button { input = "" } label: { Image(systemName: "xmark") }
                    .foregroundStyle(Theme.muted)
            }
        }
        .padding(12)
        .background(Color.black.opacity(0.85))
        .overlay(Rectangle().strokeBorder(focused ? module.tint : Theme.line, lineWidth: 1))
    }

    private var configPicker: some View {
        Button { showImporter = true } label: {
            Label(options.configName ?? "server.cfg auswählen", systemImage: "folder")
        }
        .buttonStyle(GlowButtonStyle(color: module.tint, filled: false))
    }

    @ViewBuilder private var optionsCard: some View {
        switch module {
        case .domain:
            GlassCard(tint: module.tint) {
                Toggle(isOn: $options.includeCT) { optionLabel("--ct", "Subdomains aus Certificate-Transparency-Logs (crt.sh)") }
                    .tint(module.tint)
            }
        case .ip:
            GlassCard(tint: module.tint) {
                Toggle(isOn: $options.includeGeo) { optionLabel("--geo", "Ungefähre Geo-Lage über ipwho.is (sendet die IP dorthin)") }
                    .tint(module.tint)
            }
        case .discord:
            GlassCard(tint: module.tint) {
                Picker("Modus", selection: $options.discordMode) {
                    ForEach(ReconOptions.DiscordMode.allCases) { Text($0.rawValue).tag($0) }
                }
                .pickerStyle(.segmented)
            }
        case .scan:
            GlassCard(tint: module.tint) {
                HStack(spacing: 8) {
                    Text("--ports").font(.caption.monospaced().weight(.bold)).foregroundStyle(module.tint)
                    TextField("80,443,30120,40120", text: $options.ports)
                        .font(.footnote.monospaced())
                        .keyboardType(.numbersAndPunctuation)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        .foregroundStyle(Theme.text)
                }
                Toggle(isOn: $options.authorized) {
                    optionLabel("--authorized", "Ich besitze dieses System oder habe schriftliche Erlaubnis, es zu prüfen.")
                }
                .tint(module.tint)
                NoteText(text: "TCP-Connect + HTTP/TLS-Header, max. 1024 Ports, 16 parallel. Kein UDP, keine Exploits.")
            }
        default:
            EmptyView()
        }
    }

    private func optionLabel(_ flag: String, _ text: String) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(flag).font(.caption.monospaced().weight(.bold)).foregroundStyle(Theme.text)
            Text(text).font(.caption2.monospaced()).foregroundStyle(Theme.muted)
        }
    }

    private var canRun: Bool {
        guard !isRunning else { return false }
        switch module {
        case .config: return options.configText != nil
        case .scan: return options.authorized && !input.trimmingCharacters(in: .whitespaces).isEmpty
        default: return !input.trimmingCharacters(in: .whitespaces).isEmpty
        }
    }

    // MARK: Aktionen

    private func start() {
        guard canRun else { return }
        focused = false
        isRunning = true
        errorText = nil
        let module = self.module, input = self.input, options = self.options
        Task {
            let started = Date()
            var newReport: Report?
            var newError: String?
            do {
                newReport = try await ReconRunner.run(module, input: input, options: options)
            } catch {
                newError = error.localizedDescription
            }
            // Optik: das Fake-Terminal soll kurz zu sehen sein
            let elapsed = Date().timeIntervalSince(started)
            if elapsed < 1.6 { try? await Task.sleep(nanoseconds: UInt64((1.6 - elapsed) * 1_000_000_000)) }
            withAnimation {
                report = newReport
                errorText = newError
                isRunning = false
            }
        }
    }

    private func loadConfig(_ result: Result<URL, Error>) {
        switch result {
        case .success(let url):
            let scoped = url.startAccessingSecurityScopedResource()
            defer { if scoped { url.stopAccessingSecurityScopedResource() } }
            do {
                let data = try Data(contentsOf: url)
                guard data.count < 2_000_000 else {
                    errorText = "Datei ist zu groß für eine server.cfg."
                    return
                }
                options.configText = String(decoding: data, as: UTF8.self)
                options.configName = url.lastPathComponent
                report = nil
                errorText = nil
            } catch {
                errorText = "Datei konnte nicht gelesen werden: \(error.localizedDescription)"
            }
        case .failure(let error):
            errorText = error.localizedDescription
        }
    }
}

/// Optik während der Abfrage: Radar, ASCII-Balken, Fake-Log.
private struct RunningCard: View {
    let module: ReconModule
    @State private var spin = false

    var body: some View {
        GlassCard(tint: module.tint) {
            HStack(spacing: 14) {
                ZStack {
                    Circle().strokeBorder(Theme.line, lineWidth: 1)
                    Circle().strokeBorder(Theme.line, lineWidth: 1).padding(9)
                    AngularGradient(colors: [module.tint.opacity(0.7), .clear, .clear], center: .center)
                        .clipShape(Circle())
                        .rotationEffect(.degrees(spin ? 360 : 0))
                }
                .frame(width: 54, height: 54)
                VStack(alignment: .leading, spacing: 4) {
                    Text("EXECUTING \(module.command.uppercased()) …")
                        .font(.caption.monospaced().weight(.bold))
                        .foregroundStyle(module.tint)
                        .lineLimit(1)
                        .minimumScaleFactor(0.7)
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
