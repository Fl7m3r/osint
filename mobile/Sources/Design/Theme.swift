import SwiftUI

/// Hacker-/Terminal-Look. Alle Effekte hier sind reine Optik – sie tun nichts.
enum Theme {
    static let bg = Color.black
    static let bg2 = Color(hex: 0x020A04)
    static let panel = Color(hex: 0x03110A)
    static let line = Color(hex: 0x0F5A2A)
    static let mint = Color(hex: 0x39FF14)      // Neon-Grün (Hauptfarbe)
    static let cyan = Color(hex: 0x00E5FF)
    static let amber = Color(hex: 0xFFB000)
    static let red = Color(hex: 0xFF2A4F)
    static let violet = Color(hex: 0xC77DFF)
    static let text = Color(hex: 0xC8FFD0)
    static let muted = Color(hex: 0x4FA36A)

    static let accentGradient = LinearGradient(
        colors: [mint, Color(hex: 0x00C853)],
        startPoint: .topLeading,
        endPoint: .bottomTrailing
    )

    static let mono = Font.system(.footnote, design: .monospaced)
}

extension Color {
    init(hex: UInt32, opacity: Double = 1) {
        self.init(
            .sRGB,
            red: Double((hex >> 16) & 0xFF) / 255,
            green: Double((hex >> 8) & 0xFF) / 255,
            blue: Double(hex & 0xFF) / 255,
            opacity: opacity
        )
    }
}

// MARK: - Hintergrund: Matrix-Regen + Scanlines (nur Deko)

struct HackerBackground: View {
    var body: some View {
        ZStack {
            Theme.bg
            MatrixRain().opacity(0.35)
            RadialGradient(colors: [.clear, .black.opacity(0.85)], center: .center, startRadius: 120, endRadius: 520)
            Scanlines()
        }
        .ignoresSafeArea()
        .allowsHitTesting(false)
    }
}

struct MatrixRain: View {
    private static let glyphs = Array("アイウエオカキクケコサシスセソタチツテトナニヌネノ0123456789ABCDEF$#@%&*<>/\\")
    private let columnWidth: CGFloat = 16
    @State private var seeds: [Double] = (0..<64).map { _ in Double.random(in: 0...1) }

    var body: some View {
        TimelineView(.animation(minimumInterval: 1.0 / 20.0)) { timeline in
            Canvas { context, size in
                let t = timeline.date.timeIntervalSinceReferenceDate
                let columns = Int(size.width / columnWidth) + 1
                let rows = Int(size.height / columnWidth) + 1
                for column in 0..<columns {
                    let seed = seeds[column % seeds.count]
                    let speed = 6 + seed * 10
                    let length = 8 + Int(seed * 14)
                    let head = Int((t * speed + seed * 100).truncatingRemainder(dividingBy: Double(rows + length)))
                    for offset in 0..<length {
                        let row = head - offset
                        guard row >= 0, row < rows else { continue }
                        let index = (column * 31 + row * 17 + Int(t * 4) * (offset == 0 ? 7 : 0)) % Self.glyphs.count
                        let alpha = offset == 0 ? 1.0 : max(0, 1 - Double(offset) / Double(length))
                        let color = offset == 0 ? Color.white : Theme.mint.opacity(alpha * 0.9)
                        context.draw(
                            Text(String(Self.glyphs[index]))
                                .font(.system(size: 13, design: .monospaced))
                                .foregroundStyle(color),
                            at: CGPoint(x: CGFloat(column) * columnWidth + columnWidth / 2,
                                        y: CGFloat(row) * columnWidth)
                        )
                    }
                }
            }
        }
    }
}

struct Scanlines: View {
    var body: some View {
        Canvas { context, size in
            var y: CGFloat = 0
            while y < size.height {
                context.fill(Path(CGRect(x: 0, y: y, width: size.width, height: 1)), with: .color(.black.opacity(0.35)))
                y += 3
            }
        }
    }
}

// MARK: - Glitch-Text

/// Text mit gelegentlichem RGB-Versatz-Glitch.
struct GlitchText: View {
    let text: String
    var font: Font = .system(size: 30, weight: .black, design: .monospaced)

    var body: some View {
        TimelineView(.periodic(from: .now, by: 0.12)) { timeline in
            let tick = Int(timeline.date.timeIntervalSinceReferenceDate * 8)
            let glitching = tick % 23 == 0 || tick % 37 == 0
            ZStack {
                Text(text).font(font).foregroundStyle(Theme.red.opacity(glitching ? 0.8 : 0))
                    .offset(x: glitching ? -3 : 0)
                Text(text).font(font).foregroundStyle(Theme.cyan.opacity(glitching ? 0.8 : 0))
                    .offset(x: glitching ? 3 : 0)
                Text(text).font(font).foregroundStyle(Theme.mint)
                    .shadow(color: Theme.mint.opacity(0.8), radius: 8)
            }
        }
    }
}

/// Blinkender Terminal-Cursor.
struct BlinkingCursor: View {
    var body: some View {
        TimelineView(.periodic(from: .now, by: 0.5)) { timeline in
            let on = Int(timeline.date.timeIntervalSinceReferenceDate * 2) % 2 == 0
            Rectangle().fill(Theme.mint).frame(width: 9, height: 16).opacity(on ? 1 : 0)
        }
    }
}
