import SwiftUI
import UIKit
import WebKit

/// Eine einzige, sichtbare WebView auf tiktok.com. Der Nutzer meldet sich darin selbst bei TikTok an –
/// die App sieht, speichert oder überträgt kein Passwort. Die Sitzung liegt nur im WebKit-Speicher auf dem iPhone.
@MainActor
final class TikTokBrowser: NSObject, WKNavigationDelegate {
    let webView: WKWebView
    var onChange: (() -> Void)?

    private var waiters: [CheckedContinuation<Void, Never>] = []

    /// Desktop-Ansicht von tiktok.com, weil nur sie den „Reposts“-Tab im Profil zuverlässig zeigt.
    /// (Entspricht „Desktop-Website anfordern“ in Safari.)
    static let desktopUserAgent =
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15"

    override init() {
        let configuration = WKWebViewConfiguration()
        configuration.websiteDataStore = .default()
        configuration.allowsInlineMediaPlayback = true
        configuration.mediaTypesRequiringUserActionForPlayback = .all
        webView = WKWebView(frame: .zero, configuration: configuration)
        super.init()
        webView.navigationDelegate = self
        webView.allowsBackForwardNavigationGestures = true
        webView.customUserAgent = Self.desktopUserAgent
        webView.isOpaque = false
        webView.backgroundColor = UIColor(red: 0.02, green: 0.03, blue: 0.035, alpha: 1)
    }

    var currentHost: String { webView.url?.host() ?? "—" }
    var currentPath: String { webView.url?.path ?? "" }

    func load(_ url: URL, timeout: TimeInterval = 20) async {
        webView.load(URLRequest(url: url))
        await waitForNavigation(timeout: timeout)
    }

    func reload() { webView.reload() }
    func goBack() { if webView.canGoBack { webView.goBack() } }

    /// Führt ein Skript in einer isolierten JavaScript-Welt aus (die Seite selbst kann es nicht verändern).
    func run(_ body: String, arguments: [String: Any] = [:]) async throws -> String {
        let value = try await webView.callAsyncJavaScript(body, arguments: arguments, in: nil, contentWorld: .defaultClient)
        return value as? String ?? ""
    }

    /// Prüft nur, ob ein TikTok-Sitzungscookie existiert. Der Cookie-Inhalt wird nicht gelesen.
    func hasSessionCookie() async -> Bool {
        let cookies = await webView.configuration.websiteDataStore.httpCookieStore.allCookies()
        let names: Set<String> = ["sessionid", "sessionid_ss", "sid_tt"]
        return cookies.contains { $0.domain.hasSuffix("tiktok.com") && names.contains($0.name) }
    }

    func clearAllWebsiteData() async {
        let store = webView.configuration.websiteDataStore
        await store.removeData(ofTypes: WKWebsiteDataStore.allWebsiteDataTypes(), modifiedSince: .distantPast)
        webView.load(URLRequest(url: URL(string: "about:blank")!))
    }

    private func waitForNavigation(timeout: TimeInterval) async {
        await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
            waiters.append(continuation)
            Task { @MainActor [weak self] in
                try? await Task.sleep(nanoseconds: UInt64(timeout * 1_000_000_000))
                self?.flushWaiters()
            }
        }
    }

    private func flushWaiters() {
        let pending = waiters
        waiters.removeAll()
        pending.forEach { $0.resume() }
    }

    // MARK: WKNavigationDelegate

    func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) {
        flushWaiters()
        onChange?()
    }

    func webView(_ webView: WKWebView, didFail navigation: WKNavigation!, withError error: Error) {
        flushWaiters()
        onChange?()
    }

    func webView(_ webView: WKWebView, didFailProvisionalNavigation navigation: WKNavigation!, withError error: Error) {
        flushWaiters()
        onChange?()
    }
}

/// Bettet die (eine) WebView in SwiftUI ein.
struct BrowserContainer: UIViewRepresentable {
    let browser: TikTokBrowser

    func makeUIView(context: Context) -> UIView {
        let container = UIView()
        container.backgroundColor = .clear
        attach(to: container)
        return container
    }

    func updateUIView(_ uiView: UIView, context: Context) {
        if browser.webView.superview !== uiView { attach(to: uiView) }
    }

    private func attach(to container: UIView) {
        let webView = browser.webView
        webView.removeFromSuperview()
        webView.frame = container.bounds
        webView.autoresizingMask = [.flexibleWidth, .flexibleHeight]
        container.addSubview(webView)
    }
}
