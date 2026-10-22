/* app-base.js – shared helpers for every EXNYA page.
 *
 * Every page used to duplicate its own auth guard, price fetch and clipboard
 * code, each with slightly different bugs. This file owns them once.
 *
 * Load BEFORE settings.js, AFTER the page's Supabase bootstrap:
 *     <script src="app-base.js"></script>
 *     <script src="settings.js"></script>
 *
 * It expects `SUPABASE_URL` and `SUPABASE_ANON_KEY` to already be declared on
 * the page (they are on every page) so it can talk to the same project.
 */
(function (global) {
    'use strict';

    // ─── Small utilities ────────────────────────────────────────────────

    /** Escape a value for safe interpolation into innerHTML (XSS guard). */
    function esc(value) {
        if (value === null || value === undefined) return '';
        return String(value)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#39;');
    }

    /** Format a number as USD-style money. Never returns "NaN". */
    function money(value, decimals) {
        const n = Number(value);
        if (!isFinite(n)) return '$0.00';
        const d = decimals === undefined ? 2 : decimals;
        return '$' + n.toLocaleString('en-US', {
            minimumFractionDigits: d,
            maximumFractionDigits: d
        });
    }

    /** Format a raw number, falling back to `fallback` when not finite. */
    function num(value, fallback) {
        const n = Number(value);
        return isFinite(n) ? n : (fallback === undefined ? 0 : fallback);
    }

    /** Copy text to the clipboard, with a fallback for non-HTTPS contexts. */
    async function copyText(text) {
        if (!text) return false;
        try {
            if (navigator.clipboard && global.isSecureContext) {
                await navigator.clipboard.writeText(text);
                return true;
            }
        } catch (e) { /* fall through to the legacy path */ }
        try {
            const ta = document.createElement('textarea');
            ta.value = text;
            ta.setAttribute('readonly', '');
            ta.style.position = 'fixed';
            ta.style.top = '-1000px';
            document.body.appendChild(ta);
            ta.select();
            const ok = document.execCommand('copy');
            document.body.removeChild(ta);
            return ok;
        } catch (e) {
            return false;
        }
    }

    // ─── Auth session guard ─────────────────────────────────────────────

    const LOGIN_PAGE = './pl.html';

    /**
     * Resolve the current session, refreshing only when it is actually
     * expired. Returns { user, session } or null (after redirecting to login).
     *
     * This is what fixes the redirect loops: the old code called
     * refreshSession() on every load, and a single failed refresh bounced the
     * user back to the login page even though a perfectly good session
     * existed. And the login page sent them straight back to a 2FA-less
     * dashboard, which bounced them out of any page they clicked.
     */
    async function requireSession(opts) {
        const options = opts || {};
        const client = global.supabaseClient;
        if (!client) {
            console.error('[app-base] supabaseClient is not defined yet');
            return null;
        }
        const { data: { session } } = await client.auth.getSession();
        if (!session) {
            global.location.href = options.redirect || LOGIN_PAGE;
            return null;
        }
        // Expired (or about to expire in the next 30s)? Refresh once.
        const expiresAt = session.expires_at ? session.expires_at * 1000 : 0;
        if (expiresAt && expiresAt - Date.now() < 30000) {
            const { data, error } = await client.auth.refreshSession();
            if (!error && data && data.session) {
                return { user: data.session.user, session: data.session };
            }
            // Only treat this as fatal if the session really is gone.
        }
        return { user: session.user, session: session };
    }

    /**
     * After login: every page with a 2FA setup lives behind this check, so it
     * has to agree with them. `/profile` is the only page that does not require
     * 2FA to be re-verified, which is why the login page used to send
     * 2FA-enabled users there and every other page then bounced them out.
     */
    function getPostLoginTarget() {
        return '/profile';
    }

    // ─── Live prices (cached, one request per 30s across pages) ────────

    const PRICE_URL = 'https://api.coinlore.net/api/tickers/?limit=100';
    const PRICE_TTL = 30000;
    const PRICE_CACHE_KEY = 'exnya_prices';

    function readPriceCache() {
        try {
            const raw = global.localStorage.getItem(PRICE_CACHE_KEY);
            if (!raw) return null;
            const parsed = JSON.parse(raw);
            if (!parsed || !parsed.at || !parsed.prices) return null;
            if (Date.now() - parsed.at > PRICE_TTL) return null;
            return parsed.prices;
        } catch (e) {
            return null;
        }
    }

    function writePriceCache(prices) {
        try {
            global.localStorage.setItem(PRICE_CACHE_KEY, JSON.stringify({ at: Date.now(), prices: prices }));
        } catch (e) { /* quota / private mode – not fatal */ }
    }

    let pricePromise = null;

    /**
     * Resolve `{ SYMBOL: { usd, change24h } }`.
     * Never throws: returns null when the API is unreachable, and callers have
     * to cope (the old code silently priced everything at 0 and printed $0.00).
     */
    async function getPrices(force) {
        if (!force) {
            const cached = readPriceCache();
            if (cached) return cached;
        }
        if (pricePromise) return pricePromise;

        pricePromise = (async () => {
            try {
                const res = await fetch(PRICE_URL, { cache: 'no-store' });
                if (!res.ok) throw new Error('HTTP ' + res.status);
                const json = await res.json();
                if (!json || !Array.isArray(json.data)) throw new Error('unexpected payload');
                const prices = {};
                json.data.forEach(function (coin) {
                    const usd = parseFloat(coin.price_usd);
                    if (!isFinite(usd)) return;
                    prices[coin.symbol] = {
                        usd: usd,
                        change24h: parseFloat(coin.percent_change_24h) || 0
                    };
                });
                if (Object.keys(prices).length === 0) throw new Error('empty price list');
                writePriceCache(prices);
                return prices;
            } catch (err) {
                console.warn('[app-base] price fetch failed:', err.message);
                return null;
            } finally {
                pricePromise = null;
            }
        })();

        return pricePromise;
    }

    /**
     * Supabase Storage: turn a stored path into a temporary URL that actually
     * resolves. `kyc_documents` is private, so the raw path saved at upload
     * time is not a link — the admin page used to render a dead <a href>.
     */
    async function signedUrl(bucket, path, expiresIn) {
        if (!global.supabaseClient || !path) return null;
        if (/^https?:\/\//i.test(path)) return path;
        const { data, error } = await global.supabaseClient
            .storage
            .from(bucket)
            .createSignedUrl(path, expiresIn || 3600);
        if (error) {
            console.error('[app-base] createSignedUrl failed:', error.message);
            return null;
        }
        return data && data.signedUrl ? data.signedUrl : null;
    }

    global.App = {
        esc: esc,
        money: money,
        num: num,
        copyText: copyText,
        requireSession: requireSession,
        getPostLoginTarget: getPostLoginTarget,
        getPrices: getPrices,
        signedUrl: signedUrl
    };
})(window);
