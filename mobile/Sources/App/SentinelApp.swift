import SwiftUI
import UIKit

@main
struct SentinelApp: App {
    init() {
        // Tab-Leiste im Terminal-Stil
        let appearance = UITabBarAppearance()
        appearance.configureWithOpaqueBackground()
        appearance.backgroundColor = .black
        appearance.shadowColor = UIColor(red: 0.06, green: 0.35, blue: 0.16, alpha: 1)
        let mono = UIFont.monospacedSystemFont(ofSize: 10, weight: .bold)
        let green = UIColor(red: 0.22, green: 1, blue: 0.08, alpha: 1)
        let dim = UIColor(red: 0.31, green: 0.64, blue: 0.42, alpha: 1)
        for layout in [appearance.stackedLayoutAppearance, appearance.inlineLayoutAppearance, appearance.compactInlineLayoutAppearance] {
            layout.normal.iconColor = dim
            layout.normal.titleTextAttributes = [.font: mono, .foregroundColor: dim]
            layout.selected.iconColor = green
            layout.selected.titleTextAttributes = [.font: mono, .foregroundColor: green]
        }
        UITabBar.appearance().standardAppearance = appearance
        UITabBar.appearance().scrollEdgeAppearance = appearance
    }

    var body: some Scene {
        WindowGroup {
            RootView()
                .preferredColorScheme(.dark)
                .tint(Theme.mint)
                .fontDesign(.monospaced)
        }
    }
}

struct RootView: View {
    @State private var selection: AppTab = .recon
    @State private var booted = false
    @State private var tiktokQuery: String?

    enum AppTab: Hashable { case recon, lookup, reposts, about }

    var body: some View {
        ZStack {
            TabView(selection: $selection) {
                ReconHubView { query in
                    tiktokQuery = query
                    selection = .lookup
                }
                .tabItem { Label("RECON", systemImage: "scope") }
                .tag(AppTab.recon)

                LookupView(incoming: $tiktokQuery)
                    .tabItem { Label("TIKTOK", systemImage: "music.note") }
                    .tag(AppTab.lookup)

                RepostView()
                    .tabItem { Label("PURGE", systemImage: "terminal") }
                    .tag(AppTab.reposts)

                AboutView()
                    .tabItem { Label("SYS", systemImage: "cpu") }
                    .tag(AppTab.about)
            }
            .sensoryFeedback(.selection, trigger: selection)

            if !booted {
                BootScreen { withAnimation(.easeOut(duration: 0.35)) { booted = true } }
                    .transition(.opacity)
                    .zIndex(1)
            }
        }
    }
}

/// Fake-Bootsequenz beim Start (reine Optik). Tippen überspringt sie.
struct BootScreen: View {
    let onFinish: () -> Void
    @State private var lines: [String] = []

    private let script = [
        "SENTINEL OS v4.2.0 (tty1)",
        "",
        "[ OK ] mounting /dev/recon",
        "[ OK ] loading kernel modules ........ 12/12",
        "[ OK ] starting crypto engine (AES-256)",
        "[ OK ] spawning proxy chain ... 3 nodes",
        "[ OK ] calibrating signal radar",
        "[ OK ] uplink online",
        "",
        "ACCESS GRANTED",
        "welcome, operator."
    ]

    var body: some View {
        ZStack(alignment: .topLeading) {
            Color.black.ignoresSafeArea()
            MatrixRain().opacity(0.18).ignoresSafeArea()
            Scanlines().ignoresSafeArea()
            VStack(alignment: .leading, spacing: 4) {
                ForEach(Array(lines.enumerated()), id: \.offset) { item in
                    Text(item.element)
                        .font(.system(item.element == "ACCESS GRANTED" ? .title2 : .footnote, design: .monospaced).weight(.bold))
                        .foregroundStyle(item.element == "ACCESS GRANTED" ? Theme.mint : Theme.text)
                        .shadow(color: Theme.mint.opacity(0.7), radius: item.element == "ACCESS GRANTED" ? 10 : 2)
                }
                HStack(spacing: 4) {
                    Text("$").font(.footnote.monospaced()).foregroundStyle(Theme.mint)
                    BlinkingCursor()
                }
                Spacer()
                AsciiProgress()
            }
            .padding(24)
            .padding(.top, 40)
        }
        .contentShape(Rectangle())
        .onTapGesture(perform: onFinish)
        .task {
            for line in script {
                try? await Task.sleep(nanoseconds: 180_000_000)
                lines.append(line)
            }
            try? await Task.sleep(nanoseconds: 700_000_000)
            onFinish()
        }
    }
}
