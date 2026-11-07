import Foundation

/// JavaScript, das in der isolierten Welt der WebView läuft.
///
/// WICHTIG: TikTok bietet keine offizielle API zum Auflisten oder Entfernen von Reposts.
/// Diese Skripte lesen nur die Seite, die du gerade selbst geöffnet hast, und klicken auf
/// genau den Button, den du auch von Hand drücken würdest. TikTok kann das Seitenlayout
/// jederzeit ändern – dann finden die Skripte die Elemente nicht mehr (die App meldet das,
/// und du kannst in der Live-Ansicht weiterhin von Hand entfernen).
enum RepostScripts {

    /// Liefert den Handle des angemeldeten Kontos (best effort) als JSON `{ "username": "…" }`.
    static let detectUsername = #"""
    const link = document.querySelector('a[data-e2e="nav-profile"]')
      || Array.from(document.querySelectorAll('nav a[href^="/@"], a[href^="/@"][data-e2e*="profile"]'))[0];
    let name = null;
    if (link) {
      const m = (link.getAttribute('href') || '').match(/^\/@([^/?#]+)/);
      if (m) name = decodeURIComponent(m[1]).toLowerCase();
    }
    return JSON.stringify({ username: name });
    """#

    /// Öffnet auf der eigenen Profilseite den Tab „Reposts“, scrollt langsam und sammelt die Links.
    /// Argumente: `ownUser` (String), `maxRounds` (Number).
    static let scanReposts = #"""
    const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
    const me = String(ownUser || '').toLowerCase();
    let tab = document.querySelector('[data-e2e="repost-tab"], [data-e2e="reposts-tab"]');
    if (!tab) {
      tab = Array.from(document.querySelectorAll('[role="tab"], p, span, div'))
        .find((el) => el.children.length <= 1 && /^(reposts?|erneut gepostet|repostet)$/i.test((el.textContent || '').trim()));
    }
    if (!tab) return JSON.stringify({ ok: false, error: 'tab', items: [] });
    (tab.closest('[role="tab"], button, div') || tab).click();
    await sleep(2500);

    const found = new Map();
    let stable = 0;
    for (let round = 0; round < maxRounds && stable < 3; round++) {
      const root = document.querySelector('[data-e2e="user-repost-item-list"]') || document.querySelector('main') || document;
      const before = found.size;
      root.querySelectorAll('a[href*="/video/"], a[href*="/photo/"]').forEach((a) => {
        const m = a.href.match(/\/@([^/?#]+)\/(video|photo)\/(\d+)/);
        if (!m) return;
        const author = decodeURIComponent(m[1]).toLowerCase();
        if (me && author === me) return;          // eigene Videos sind keine Reposts
        if (found.has(m[3])) return;
        const img = a.querySelector('img');
        found.set(m[3], {
          id: m[3],
          author: author,
          kind: m[2],
          url: 'https://www.tiktok.com/@' + m[1] + '/' + m[2] + '/' + m[3],
          thumb: img && img.src && img.src.startsWith('http') ? img.src : null
        });
      });
      stable = found.size === before ? stable + 1 : 0;
      window.scrollBy(0, Math.round(window.innerHeight * 0.9));
      await sleep(1600);                           // gemächlich – wie ein Mensch, der scrollt
    }
    return JSON.stringify({ ok: true, items: Array.from(found.values()) });
    """#

    /// Auf einer Video-Seite: den „Repost entfernen“-Button suchen, einmal klicken, Ergebnis prüfen.
    /// Gibt `{ ok, error }` zurück. Fehler: `not-reposted-or-not-found`, `still-present`.
    static let removeRepost = #"""
    const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
    const REMOVE = /(remove repost|undo repost|repost entfernen|reposting entfernen|repost rückgängig|nicht mehr reposten)/i;
    const labelOf = (el) => {
      const aria = (el.getAttribute && (el.getAttribute('aria-label') || el.getAttribute('title'))) || '';
      return aria + ' ' + (el.innerText || el.textContent || '');
    };
    const clickable = (el) => el.closest('button, [role="button"], a, [tabindex]') || el;
    const findRemove = () => {
      const hits = Array.from(document.querySelectorAll('button, [role="button"], [data-e2e], span, p, div'))
        .filter((el) => REMOVE.test(labelOf(el)) && (el.innerText || '').length < 60);
      hits.sort((a, b) => (a.innerText || '').length - (b.innerText || '').length);
      return hits[0] || null;
    };
    const shareButton = () => document.querySelector(
      '[data-e2e="share-icon"], [data-e2e="video-share-icon"], [data-e2e="browse-share-icon"], [data-e2e="share-button"]'
    );
    const escape = () => document.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', bubbles: true }));

    // Warten, bis die Seite (Single-Page-App) ihre Buttons gerendert hat.
    for (let i = 0; i < 16 && !findRemove() && !shareButton(); i++) await sleep(500);

    let usedShare = false;
    let target = findRemove();
    if (!target && shareButton()) {
      clickable(shareButton()).click();
      usedShare = true;
      await sleep(1200);
      target = findRemove();
    }
    if (!target) {
      if (usedShare) escape();
      return JSON.stringify({ ok: false, error: 'not-reposted-or-not-found' });
    }

    clickable(target).click();
    await sleep(1500);

    // Manche Varianten fragen nach einer Bestätigung.
    const dialog = document.querySelector('[role="dialog"], [role="alertdialog"]');
    if (dialog) {
      const confirm = Array.from(dialog.querySelectorAll('button, [role="button"]'))
        .find((b) => /^(remove|entfernen|bestätigen|confirm)$/i.test((b.innerText || '').trim()));
      if (confirm) { confirm.click(); await sleep(1200); }
    }

    // Prüfen: Ist der Entfernen-Button noch da?
    if (usedShare) {
      escape();
      await sleep(800);
      if (shareButton()) { clickable(shareButton()).click(); await sleep(1200); }
    }
    const still = !!findRemove();
    if (usedShare) escape();
    return JSON.stringify({ ok: !still, error: still ? 'still-present' : null });
    """#
}
