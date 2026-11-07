import SwiftUI
import UIKit

/// Rendert jeden Recon-Bericht im Terminal-Look.
struct ReportView: View {
    let report: Report
    @Environment(\.openURL) private var openURL

    var body: some View {
        VStack(spacing: 14) {
            GlassCard(tint: report.statusTone.color) {
                HStack(alignment: .firstTextBaseline) {
                    Text(">> " + report.status)
                        .font(.headline.monospaced().weight(.heavy))
                        .foregroundStyle(report.statusTone.color)
                        .shadow(color: report.statusTone.color.opacity(0.7), radius: 6)
                    Spacer()
                }
                Text(report.target)
                    .font(.subheadline.monospaced())
                    .foregroundStyle(Theme.text)
                    .textSelection(.enabled)
                Text("completed " + Date().formatted(date: .omitted, time: .standard))
                    .font(.caption2.monospaced())
                    .foregroundStyle(Theme.muted)
            }

            ForEach(report.sections) { section in
                GlassCard(tint: report.module.tint) {
                    CardTitle(title: section.title, systemImage: section.icon, tint: report.module.tint)
                    ForEach(section.rows) { row in
                        KeyValueRow(key: row.key, value: row.value, mono: true, valueColor: row.tone.color)
                    }
                    if !section.list.isEmpty {
                        VStack(alignment: .leading, spacing: 3) {
                            ForEach(Array(section.list.prefix(section.listLimit).enumerated()), id: \.offset) { item in
                                Text(item.element)
                                    .font(.caption.monospaced())
                                    .foregroundStyle(Theme.text.opacity(0.9))
                                    .textSelection(.enabled)
                                    .fixedSize(horizontal: false, vertical: true)
                            }
                            if section.list.count > section.listLimit {
                                Text("… +\(section.list.count - section.listLimit) weitere (siehe JSON)")
                                    .font(.caption2.monospaced()).foregroundStyle(Theme.muted)
                            }
                        }
                        .padding(10)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .background(Color.black.opacity(0.6))
                        .overlay(Rectangle().strokeBorder(Theme.line, lineWidth: 1))
                    }
                }
            }

            if !report.findings.isEmpty {
                GlassCard(tint: report.findings.contains { $0.level == "HIGH" } ? Theme.red : Theme.amber) {
                    CardTitle(title: "Findings (\(report.findings.count))", systemImage: "exclamationmark.shield.fill",
                              tint: report.findings.contains { $0.level == "HIGH" } ? Theme.red : Theme.amber)
                    ForEach(report.findings) { finding in
                        VStack(alignment: .leading, spacing: 5) {
                            HStack(alignment: .top, spacing: 8) {
                                StatusBadge(text: finding.level, color: finding.tone.color)
                                Text(finding.title)
                                    .font(.footnote.monospaced().weight(.bold))
                                    .foregroundStyle(Theme.text)
                                    .fixedSize(horizontal: false, vertical: true)
                            }
                            if !finding.detail.isEmpty {
                                Text(finding.detail).font(.caption.monospaced()).foregroundStyle(Theme.muted)
                                    .fixedSize(horizontal: false, vertical: true)
                            }
                            Text("fix> " + finding.fix).font(.caption.monospaced()).foregroundStyle(Theme.mint.opacity(0.9))
                                .fixedSize(horizontal: false, vertical: true)
                        }
                        .padding(.vertical, 4)
                    }
                }
            }

            if !report.links.isEmpty {
                GlassCard(tint: Theme.cyan) {
                    CardTitle(title: "Links", systemImage: "link", tint: Theme.cyan)
                    ForEach(report.links) { link in
                        Button { openURL(link.url) } label: {
                            Text("↗ " + link.title).font(.footnote.monospaced()).foregroundStyle(Theme.cyan)
                        }
                    }
                }
            }

            ForEach(report.notes, id: \.self) { NoteText(text: $0) }

            HStack(spacing: 10) {
                ShareLink(item: report.json, preview: SharePreview("FLMP-Bericht")) {
                    Label("json", systemImage: "curlybraces")
                }
                .buttonStyle(GlowButtonStyle(color: Theme.violet, filled: false))
                Button { UIPasteboard.general.string = report.json } label: {
                    Label("copy", systemImage: "doc.on.doc")
                }
                .buttonStyle(GlowButtonStyle(color: Theme.muted, filled: false))
            }
        }
    }
}
