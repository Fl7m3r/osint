import SwiftUI

// MARK: - Terminal-Fenster (ersetzt die Glas-Karte)

struct GlassCard<Content: View>: View {
    var tint: Color = Theme.mint
    @ViewBuilder var content: Content

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            content
        }
        .padding(16)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color.black.opacity(0.78))
        .overlay(Rectangle().strokeBorder(tint.opacity(0.55), lineWidth: 1))
        .overlay(CornerBrackets().stroke(tint, lineWidth: 2))
        .shadow(color: tint.opacity(0.25), radius: 14)
    }
}

/// Eckklammern wie bei einem HUD.
struct CornerBrackets: Shape {
    var length: CGFloat = 14

    func path(in rect: CGRect) -> Path {
        var p = Path()
        p.move(to: CGPoint(x: rect.minX, y: rect.minY + length)); p.addLine(to: CGPoint(x: rect.minX, y: rect.minY)); p.addLine(to: CGPoint(x: rect.minX + length, y: rect.minY))
        p.move(to: CGPoint(x: rect.maxX - length, y: rect.minY)); p.addLine(to: CGPoint(x: rect.maxX, y: rect.minY)); p.addLine(to: CGPoint(x: rect.maxX, y: rect.minY + length))
        p.move(to: CGPoint(x: rect.maxX, y: rect.maxY - length)); p.addLine(to: CGPoint(x: rect.maxX, y: rect.maxY)); p.addLine(to: CGPoint(x: rect.maxX - length, y: rect.maxY))
        p.move(to: CGPoint(x: rect.minX + length, y: rect.maxY)); p.addLine(to: CGPoint(x: rect.minX, y: rect.maxY)); p.addLine(to: CGPoint(x: rect.minX, y: rect.maxY - length))
        return p
    }
}

// MARK: - Überschriften

struct ScreenHeader: View {
    let eyebrow: String
    let title: String
    let subtitle: String

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 6) {
                Text("root@sentinel:~$ ./\(eyebrow.lowercased().replacingOccurrences(of: " ", with: "_"))")
                    .font(.caption.monospaced())
                    .foregroundStyle(Theme.muted)
                    .lineLimit(1)
                BlinkingCursor().scaleEffect(0.7)
            }
            GlitchText(text: title.uppercased().replacingOccurrences(of: " ", with: "_"))
                .lineLimit(1)
                .minimumScaleFactor(0.5)
            Text("// " + subtitle)
                .font(.footnote.monospaced())
                .foregroundStyle(Theme.muted)
                .fixedSize(horizontal: false, vertical: true)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}

struct CardTitle: View {
    let title: String
    let systemImage: String
    var tint: Color = Theme.mint

    var body: some View {
        HStack(spacing: 8) {
            Image(systemName: systemImage)
                .font(.subheadline.weight(.bold))
                .foregroundStyle(tint)
            Text("[ \(title.uppercased()) ]")
                .font(.subheadline.monospaced().weight(.bold))
                .foregroundStyle(tint)
                .shadow(color: tint.opacity(0.6), radius: 4)
        }
    }
}

// MARK: - Badges & Zeilen

struct StatusBadge: View {
    let text: String
    var color: Color = Theme.mint
    var systemImage: String? = nil

    var body: some View {
        HStack(spacing: 5) {
            if let systemImage { Image(systemName: systemImage) }
            Text(text.uppercased())
        }
        .font(.caption2.monospaced().weight(.bold))
        .padding(.horizontal, 8)
        .padding(.vertical, 4)
        .foregroundStyle(color)
        .background(color.opacity(0.12))
        .overlay(Rectangle().strokeBorder(color.opacity(0.7), lineWidth: 1))
    }
}

struct KeyValueRow: View {
    let key: String
    let value: String
    var mono = false
    var valueColor: Color = Theme.text

    var body: some View {
        HStack(alignment: .firstTextBaseline) {
            Text("> " + key.uppercased())
                .font(.caption.monospaced())
                .foregroundStyle(Theme.muted)
            Spacer(minLength: 12)
            Text(value)
                .font(.subheadline.monospaced())
                .foregroundStyle(valueColor)
                .multilineTextAlignment(.trailing)
                .textSelection(.enabled)
        }
    }
}

struct CheckRow: View {
    let ok: Bool
    let text: String

    var body: some View {
        HStack(alignment: .top, spacing: 8) {
            Text(ok ? "[OK]" : "[!!]")
                .font(.footnote.monospaced().weight(.bold))
                .foregroundStyle(ok ? Theme.mint : Theme.red)
            Text(text)
                .font(.footnote.monospaced())
                .foregroundStyle(Theme.text)
                .fixedSize(horizontal: false, vertical: true)
        }
    }
}

struct NoteText: View {
    let text: String
    var systemImage = "info.circle"

    var body: some View {
        Text("# " + text)
            .font(.caption.monospaced())
            .foregroundStyle(Theme.muted)
            .fixedSize(horizontal: false, vertical: true)
    }
}

// MARK: - Fake-Terminal (reine Deko, keine echten Aktionen)

struct FakeTerminalLog: View {
    var lines: [String] = FakeTerminalLog.defaultLines
    var maxVisible = 6
    @State private var shown: [String] = []
    @State private var index = 0

    static let defaultLines = [
        "[*] initializing sentinel core v4.2.0",
        "[*] loading modules: net, crypto, recon",
        "[+] handshake ... OK",
        "[*] decrypting payload ███████░░░ 72%",
        "[*] tracing route: 10.0.0.1 -> 172.16.4.2 -> ***",
        "[+] tunnel layer 3 ... established",
        "[*] parsing response frames ...",
        "[*] hashing: 9f2c1e7ab04d55e1c3...",
        "[+] uplink stable @ 1337 kb/s",
        "[*] compiling results ..."
    ]

    var body: some View {
        VStack(alignment: .leading, spacing: 3) {
            ForEach(Array(shown.enumerated()), id: \.offset) { item in
                Text(item.element)
                    .font(.caption2.monospaced())
                    .foregroundStyle(item.element.hasPrefix("[+]") ? Theme.mint : Theme.muted)
                    .lineLimit(1)
                    .transition(.opacity)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .task {
            while !Task.isCancelled {
                try? await Task.sleep(nanoseconds: UInt64.random(in: 150_000_000...450_000_000))
                withAnimation(.easeOut(duration: 0.1)) {
                    shown.append(lines[index % lines.count])
                    if shown.count > maxVisible { shown.removeFirst() }
                }
                index += 1
            }
        }
    }
}

/// Fake-Fortschrittsbalken im ASCII-Stil.
struct AsciiProgress: View {
    @State private var value = 0

    var body: some View {
        let filled = value % 21
        Text("[" + String(repeating: "█", count: filled) + String(repeating: "░", count: 20 - filled) + "] \(filled * 5)%")
            .font(.caption.monospaced())
            .foregroundStyle(Theme.mint)
            .task {
                while !Task.isCancelled {
                    try? await Task.sleep(nanoseconds: 90_000_000)
                    value += 1
                }
            }
    }
}

// MARK: - Buttons

struct GlowButtonStyle: ButtonStyle {
    var color: Color = Theme.mint
    var filled = true

    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(.subheadline.monospaced().weight(.bold))
            .textCase(.uppercase)
            .padding(.vertical, 13)
            .padding(.horizontal, 14)
            .frame(maxWidth: .infinity)
            .foregroundStyle(filled ? Color.black : color)
            .background(filled ? color : color.opacity(0.08))
            .overlay(Rectangle().strokeBorder(color, lineWidth: 1))
            .shadow(color: color.opacity(configuration.isPressed ? 0.9 : 0.45), radius: configuration.isPressed ? 16 : 8)
            .scaleEffect(configuration.isPressed ? 0.98 : 1)
            .animation(.easeOut(duration: 0.12), value: configuration.isPressed)
    }
}

struct ChipButtonStyle: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(.caption.monospaced())
            .padding(.horizontal, 10)
            .padding(.vertical, 6)
            .foregroundStyle(Theme.mint)
            .background(Color.black.opacity(0.7))
            .overlay(Rectangle().strokeBorder(Theme.line, lineWidth: 1))
            .opacity(configuration.isPressed ? 0.6 : 1)
    }
}
