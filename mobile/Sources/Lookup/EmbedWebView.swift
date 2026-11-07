import SwiftUI
import UIKit
import WebKit

/// Zeigt TikToks offiziellen Embed-HTML-Code (aus der oEmbed-Antwort) an.
/// Links öffnen sich außerhalb der App, damit die Vorschau keine eigene Browser-Sitzung wird.
struct EmbedWebView: UIViewRepresentable {
    let html: String

    func makeCoordinator() -> Coordinator { Coordinator() }

    func makeUIView(context: Context) -> WKWebView {
        let configuration = WKWebViewConfiguration()
        configuration.websiteDataStore = .nonPersistent()
        configuration.allowsInlineMediaPlayback = true
        let webView = WKWebView(frame: .zero, configuration: configuration)
        webView.isOpaque = false
        webView.backgroundColor = .clear
        webView.scrollView.backgroundColor = .clear
        webView.navigationDelegate = context.coordinator
        webView.loadHTMLString(page, baseURL: URL(string: "https://www.tiktok.com"))
        return webView
    }

    func updateUIView(_ uiView: WKWebView, context: Context) {}

    private var page: String {
        """
        <!doctype html><html><head>
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <style>
          html,body{margin:0;padding:0;background:transparent;color:#d6f3ec;font-family:-apple-system,sans-serif}
          blockquote.tiktok-embed{margin:0 auto !important}
        </style></head><body>\(html)</body></html>
        """
    }

    final class Coordinator: NSObject, WKNavigationDelegate {
        @MainActor
        func webView(_ webView: WKWebView, decidePolicyFor navigationAction: WKNavigationAction) async -> WKNavigationActionPolicy {
            if navigationAction.navigationType == .linkActivated, let url = navigationAction.request.url {
                _ = await UIApplication.shared.open(url, options: [:])
                return .cancel
            }
            return .allow
        }
    }
}
