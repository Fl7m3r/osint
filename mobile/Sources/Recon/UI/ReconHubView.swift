import SwiftUI

struct ReconRoute: Hashable {
    let module: ReconModule
    let input: String
    let autorun: Bool
}

/// Startseite: universelles Zielfeld mit Auto-Erkennung + Kacheln für alle Module.
struct ReconHubView: View {
    let openTikTok: (String) -> Void

    @State private var path: [ReconRoute] = []
    @State private var target = ""
    @State private var hint: String?
    @FocusState private var focused: Bool

    private let columns = [GridItem(.flexible(), spacing: 12), GridItem(.flexible(), spacing: 12)]

    var body: some View {
        NavigationStack(path: $path) {
            ZStack {
                HackerBackground()
                ScrollView {
                    VStack(spacing: 18) {
                        ScreenHeader(
                            eyebrow: "recon suite",
                            title: "FLMP Sentinel",
                            subtitle: "Ziel eingeben – E-Mail, Domain, IP, Telefon, Discord-ID oder @TikTok. Das passende Modul wird automatisch gewählt."
                        )
                        .padding(.top, 8)

                        targetField
                        if let hint {
                            Text("! " + hint).font(.caption.monospaced()).foregroundStyle(Theme.amber)
                                .frame(maxWidth: .infinity, alignment: .leading)
                        }

                        HStack {
                            Text("[ MODULES ]").font(.caption.monospaced().weight(.bold)).foregroundStyle(Theme.muted)
                            Spacer()
                            Text("\(ReconModule.allCases.count) loaded").font(.caption2.monospaced()).foregroundStyle(Theme.muted)
                        }

                        LazyVGrid(columns: columns, spacing: 12) {
                            ForEach(ReconModule.allCases) { module in
                                Button { open(module, input: "", autorun: false) } label: {
                                    ModuleTile(module: module)
                                }
                                .buttonStyle(.plain)
                            }
                        }

                        NoteText(text: "Nur öffentliche Metadaten und Checks an eigenen Systemen. Keine Personensuche, keine Identitätszuordnung.")
                            .padding(.bottom, 28)
                    }
                    .padding(.horizontal, 16)
                }
                .scrollDismissesKeyboard(.interactively)
            }
            .toolbar(.hidden, for: .navigationBar)
            .navigationDestination(for: ReconRoute.self) { route in
                ModuleView(module: route.module, initialInput: route.input, autorun: route.autorun)
            }
        }
    }

    private var targetField: some View {
        HStack(spacing: 10) {
            Text("target>")
                .font(.subheadline.monospaced().weight(.bold))
                .foregroundStyle(Theme.mint)
                .shadow(color: Theme.mint.opacity(0.7), radius: 4)
            TextField("8.8.8.8 · name@mail.de · +49…", text: $target)
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()
                .keyboardType(.URL)
                .submitLabel(.go)
                .focused($focused)
                .onSubmit(run)
                .foregroundStyle(Theme.text)
            Button(action: run) {
                Text("RUN")
                    .font(.subheadline.monospaced().weight(.heavy))
                    .foregroundStyle(Color.black)
                    .frame(width: 52, height: 38)
                    .background(Theme.mint)
                    .shadow(color: Theme.mint.opacity(0.7), radius: 10)
            }
            .disabled(target.trimmingCharacters(in: .whitespaces).isEmpty)
        }
        .padding(.leading, 12)
        .padding(.trailing, 5)
        .padding(.vertical, 5)
        .background(Color.black.opacity(0.85))
        .overlay(Rectangle().strokeBorder(focused ? Theme.mint : Theme.line, lineWidth: 1))
        .shadow(color: Theme.mint.opacity(focused ? 0.45 : 0), radius: 12)
    }

    private func run() {
        focused = false
        let value = target.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let module = ReconModule.detect(value) else {
            hint = "Zieltyp nicht erkannt. Wähle unten ein Modul."
            return
        }
        hint = nil
        open(module, input: value, autorun: true)
    }

    private func open(_ module: ReconModule, input: String, autorun: Bool) {
        if module == .tiktok {
            openTikTok(input)
        } else {
            path.append(ReconRoute(module: module, input: input, autorun: autorun))
        }
    }
}

private struct ModuleTile: View {
    let module: ReconModule

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Image(systemName: module.icon)
                    .font(.title3)
                    .foregroundStyle(module.tint)
                    .shadow(color: module.tint.opacity(0.8), radius: 6)
                Spacer()
                Circle().fill(module.tint).frame(width: 6, height: 6).shadow(color: module.tint, radius: 4)
            }
            Text(module.title.uppercased())
                .font(.footnote.monospaced().weight(.heavy))
                .foregroundStyle(Theme.text)
                .lineLimit(1)
                .minimumScaleFactor(0.7)
            Text("$ " + module.command)
                .font(.caption2.monospaced())
                .foregroundStyle(Theme.muted)
                .lineLimit(1)
                .minimumScaleFactor(0.7)
        }
        .padding(12)
        .frame(maxWidth: .infinity, minHeight: 96, alignment: .topLeading)
        .background(Color.black.opacity(0.78))
        .overlay(Rectangle().strokeBorder(module.tint.opacity(0.45), lineWidth: 1))
        .overlay(CornerBrackets(length: 10).stroke(module.tint, lineWidth: 1.5))
    }
}
