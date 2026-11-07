# Sentinel Mobile (iPhone)

Die iPhone-App zu **FLMP Sentinel**. Sie ist in SwiftUI geschrieben und braucht iOS 17 oder neuer. Die Oberfläche sieht aus wie ein Hacking-Terminal: Matrix-Regen, Scanlines, Glitch-Titel, eine Boot-Sequenz beim Start und Fake-Terminal-Logs beim Laden. Das ist alles **reine Optik**. Die Effekte tun nichts, und die echten Ergebnisse sind davon nicht betroffen.

| Tab | Funktion |
| --- | --- |
| **Lookup** | TikTok-Username, Profil-Link, Video-Link, Kurzlink (`vm.tiktok.com`) oder Video-ID eingeben. Die App prüft das Username-Format lokal und fragt über TikToks offizielle **oEmbed**-Schnittstelle ab, ob es ein öffentliches Profil gibt (Anzeigename, Link). Aus einer Video-ID liest sie lokal das Upload-Datum (wie der Discord-Snowflake-Decoder im Python-Tool). Das Ergebnis lässt sich als JSON-Bericht teilen. Eine offizielle Profil-Vorschau (`embed.js`) wird nur auf Tipp geladen. |
| **Reposts** | Entfernt **deine eigenen** Reposts. Du meldest dich in einer eingebetteten tiktok.com-Ansicht selbst an. Die App liest dann den „Reposts“-Tab deines Profils und entfernt auf deinen Tipp jeweils **einen** Repost. Zwischen zwei Entfernungen liegt eine Pause von 6 Sekunden. |
| **Info** | Datenquellen, Datenschutz und Links zu TikToks Regeln. |

## Datenquellen (wie im Python-Tool, nur öffentlich)

- `https://www.tiktok.com/oembed`: offizielle, öffentliche Schnittstelle. Es gibt kein Scraping, keine Follower-Zahlen und keine privaten Daten.
- `vm.tiktok.com` / `tiktok.com/t/…`: Nur die Weiterleitung eines Kurzlinks wird aufgelöst.
- Username-Format und Video-Zeitstempel werden **lokal** berechnet, ohne Netzwerk.
- `tiktok.com` in der Live-Ansicht: nur im Repost-Remover, mit deiner eigenen Anmeldung.

Die App hat keinen eigenen Server, kein Tracking und keine Analyse.

## ⚠️ Wichtig zum Repost-Remover

- **TikTok hat keine offizielle API** zum Auflisten oder Entfernen von Reposts. Die Display API und die Content Posting API können das nicht. Der Remover bedient deshalb die normale TikTok-Website für dich. Das ist **inoffiziell**.
- TikToks Nutzungsbedingungen verbieten automatisierte Zugriffe, die mehr Anfragen erzeugen, als ein Mensch in derselben Zeit könnte. Deshalb ist die App so gebaut:
  - Es gibt **keinen „Alles löschen“-Knopf** und keine Schleife im Hintergrund. Jede Entfernung startet erst nach deinem Tipp.
  - Zwischen zwei Entfernungen liegt eine feste Pause. Beim Laden der Liste scrollt die App langsam.
  - Die App klickt nur den Button, den du auch selbst drücken würdest. Sie benutzt keine versteckten API-Aufrufe und keine gefälschten Tokens.
- **Trotzdem bleibt ein Risiko:** TikTok kann solche Hilfen erkennen und das Konto zeitweise einschränken. Du nutzt den Remover auf eigenes Risiko und nur für dein eigenes Konto.
- **Die Anmeldung läuft direkt auf tiktok.com.** Die App liest, speichert und überträgt weder Passwort noch Token. Sie prüft nur, *ob* ein TikTok-Sitzungscookie existiert. Den Inhalt des Cookies liest sie nicht. Mit **„Abmelden & TikTok-Daten löschen“** entfernst du alles wieder.
- **TikTok kann das Layout jederzeit ändern.** Dann findet die App den „Reposts“-Tab oder den Button „Repost entfernen“ eventuell nicht mehr und meldet einen Fehler. In der Live-Ansicht kannst du immer noch von Hand entfernen. Die Suchmuster stehen in [Sources/Reposts/RepostScripts.swift](Sources/Reposts/RepostScripts.swift).
- Die Live-Ansicht lädt die **Desktop-Version** von tiktok.com, wie „Desktop-Website anfordern“ in Safari. Nur dort zeigt das Profil den Reposts-Tab zuverlässig. Zum Bedienen kannst du die Ansicht mit dem Pfeil-Symbol vergrößern.

## IPA auf dem Windows-PC bekommen (ohne Mac)

Gebaut wird in der Cloud mit **GitHub Actions** auf einem macOS-Runner. Der Workflow liegt in [`.github/workflows/ios-ipa.yml`](../.github/workflows/ios-ipa.yml). Er erzeugt das Xcode-Projekt mit XcodeGen aus `project.yml`, baut unsigniert und packt `Payload/` zu `SentinelMobile.ipa`.

### 1. Repository auf GitHub anlegen (einmalig)

1. Auf <https://github.com/new> ein neues Repository anlegen, z. B. `osint`. Es kann **privat** sein. Setze **keinen** Haken bei README, `.gitignore` oder Lizenz.
2. Im Projektordner in PowerShell eingeben:

```powershell
Set-Location C:\Users\disof\Documents\osint
git add mobile .github
git commit -m "Sentinel Mobile: iPhone-App mit TikTok-Lookup und Repost-Remover"
git remote add origin https://github.com/Fl7m3r/osint.git
git push -u origin master
```

Beim ersten `git push` öffnet sich der Git Credential Manager im Browser. Dort meldest du dich bei GitHub an.

### 2. Build starten und IPA herunterladen

1. Der Push startet den Workflow automatisch, sobald sich etwas in `mobile/` ändert. Von Hand geht es so: GitHub → Repo → **Actions** → **iOS IPA (Sentinel Mobile)** → **Run workflow**.
2. Warten, bis der Lauf grün ist. Das dauert etwa 5 bis 10 Minuten.
3. Im Lauf unten bei **Artifacts** die Datei **SentinelMobile-ipa** herunterladen. Das ist eine ZIP-Datei mit `SentinelMobile.ipa` darin. Entpacken.

Wenn der Build fehlschlägt, lädt der Workflow `build-log` als Artifact hoch. Die Fehlerzeilen stehen außerdem direkt im Schritt „App bauen“.

> **Kosten:** In öffentlichen Repositorys sind macOS-Runner kostenlos. In privaten Repositorys zählen macOS-Minuten im Free-Tarif 10-fach. Bei 2.000 Freiminuten im Monat bleiben also etwa 200 macOS-Minuten, das reicht für rund 20 Builds.

### 3. Auf dem iPhone installieren (Sideloadly)

1. iPhone per USB anschließen. In iTunes bzw. in der Apple-Geräte-App muss es vertraut sein.
2. **Sideloadly** öffnen, `SentinelMobile.ipa` hineinziehen und deine Apple-ID eintragen. Starte mit **Start**.
3. Auf dem iPhone: **Einstellungen → Allgemein → VPN & Geräteverwaltung → deine Apple-ID → Vertrauen**.
4. Ab iOS 16 muss der **Entwicklermodus** an sein: **Einstellungen → Datenschutz & Sicherheit → Entwicklermodus**.

Mit einer kostenlosen Apple-ID läuft die Signatur nach **7 Tagen** ab. Dann installierst du die App einfach erneut mit Sideloadly. Deine Daten bleiben dabei erhalten.

## Projektaufbau

```
mobile/
├── project.yml               XcodeGen-Definition (Ziel iOS 17, Bundle-ID com.flmp.sentinelmobile)
├── Resources/Assets.xcassets App-Icon (Radar) und Akzentfarbe
└── Sources/
    ├── App/                  App-Einstieg und Tab-Leiste
    ├── Design/               Theme (Dashboard-Farben, Aurora-Hintergrund) und Glas-Komponenten
    ├── Lookup/               Parser und Formatprüfung, oEmbed-Service, ViewModel, Oberfläche, Embed-WebView
    ├── Reposts/              WebView-Steuerung, JS-Skripte, Session-Logik, Oberfläche
    └── Info/                 Datenschutz und Quellen
```

Mit einem Mac ginge es auch lokal: `brew install xcodegen`, dann `cd mobile && xcodegen generate` und `SentinelMobile.xcodeproj` öffnen. Unter Windows bleibt nur der Weg über GitHub Actions.
