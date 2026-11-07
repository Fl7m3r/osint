import SwiftUI

struct AboutView: View {
    var body: some View {
        NavigationStack {
            ZStack {
                HackerBackground()
                ScrollView {
                    VStack(spacing: 18) {
                        ScreenHeader(
                            eyebrow: "Datenschutz & Quellen",
                            title: "Sentinel Mobile",
                            subtitle: "Die iPhone-Version von FLMP Sentinel. Alles läuft lokal auf dem Gerät – kein eigener Server, keine Analyse, kein Tracking."
                        )
                        .padding(.top, 8)

                        GlassCard {
                            CardTitle(title: "Datenquellen", systemImage: "point.3.connected.trianglepath.dotted")
                            source("tiktok.com/oembed", "Offizielle, öffentliche oEmbed-Schnittstelle: Anzeigename und Profil-/Video-Link. Wird bei jedem gültigen Lookup abgefragt.")
                            source("tiktok.com/embed.js", "Nur wenn du „Vorschau laden“ tippst: TikToks offizielles Einbettungs-Widget.")
                            source("vm.tiktok.com", "Nur bei Kurzlinks: Die Weiterleitung wird aufgelöst, um Username/Video-ID zu lesen.")
                            source("Lokal", "Formatprüfung des Usernames und Zeitstempel aus der Video-ID – ohne Netzwerk.")
                            source("tiktok.com (Live-Ansicht)", "Nur im Repost-Remover: die normale TikTok-Website mit deiner eigenen Anmeldung.")
                            source("cloudflare-dns.com / dns.google", "DNS über HTTPS für E-Mail-, Domain- und PTR-Abfragen (iOS hat keinen MX/TXT-Resolver). Diese Anbieter sehen den abgefragten Namen.")
                            source("rdap.org", "Registry-Daten zu Domains und IP-Netzen. Inhaberkontakte werden nicht abgefragt.")
                            source("crt.sh", "Nur bei Domain mit --ct: Subdomains aus Certificate-Transparency-Logs.")
                            source("ipwho.is", "Nur bei IP mit --geo: ungefähre Geo-Lage. Die IP wird dorthin gesendet.")
                            source("Ziel-Server", "Nur beim Server-Scan mit Bestätigung: TCP-Verbindungen und HTTP/TLS-Anfragen direkt an die angegebene IP.")
                            source("Offline", "Telefonnummern (PhoneNumberKit), Discord-Snowflakes, Username-Formate und server.cfg-Audit – ohne Netzwerk.")
                        }

                        GlassCard(tint: Theme.violet) {
                            CardTitle(title: "Was die App nicht tut", systemImage: "hand.raised.fill", tint: Theme.violet)
                            CheckRow(ok: true, text: "Keine Suche nach realen Personen oder Zuordnung über Plattformen hinweg.")
                            CheckRow(ok: true, text: "Kein Scraping von Profilseiten, Followern oder privaten Daten.")
                            CheckRow(ok: true, text: "Kein Passwort, kein Token: Die Anmeldung passiert direkt auf tiktok.com.")
                            CheckRow(ok: true, text: "Keine Massen-Automatik: Reposts werden nur einzeln nach deinem Tipp entfernt.")
                        }

                        GlassCard(tint: Theme.amber) {
                            CardTitle(title: "Regeln", systemImage: "doc.text.magnifyingglass", tint: Theme.amber)
                            Link(destination: URL(string: "https://www.tiktok.com/legal/page/eea/terms-of-service/de")!) {
                                Label("TikTok-Nutzungsbedingungen", systemImage: "arrow.up.right.square")
                            }
                            Link(destination: URL(string: "https://developers.tiktok.com/doc/embed-creator-profiles")!) {
                                Label("TikTok-Doku: Creator-Profile einbetten", systemImage: "arrow.up.right.square")
                            }
                            Link(destination: URL(string: "https://support.tiktok.com/de/getting-started/setting-up-your-profile/changing-your-username")!) {
                                Label("TikTok-Hilfe: Username-Regeln", systemImage: "arrow.up.right.square")
                            }
                        }
                        .font(.subheadline.weight(.medium))

                        Text("Made by plbct0 & sauceyC4 · v\(Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "1.0")")
                            .font(.caption)
                            .foregroundStyle(Theme.muted)
                            .padding(.bottom, 28)
                    }
                    .padding(.horizontal, 16)
                }
            }
            .toolbar(.hidden, for: .navigationBar)
        }
    }

    private func source(_ name: String, _ detail: String) -> some View {
        VStack(alignment: .leading, spacing: 3) {
            Text(name).font(Theme.mono.weight(.semibold)).foregroundStyle(Theme.cyan)
            Text(detail).font(.footnote).foregroundStyle(Theme.text.opacity(0.85))
                .fixedSize(horizontal: false, vertical: true)
        }
    }
}
