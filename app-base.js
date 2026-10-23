/* app-base.js – shared helpers for every EXNYA page.
 *
 * Every page used to duplicate its own auth guard, price fetch and clipboard
 * code, each with slightly different bugs. This file owns them once.
 *
 * Load order: this file goes in <head>, right after the Supabase CDN script.
 * It is an IIFE that exports a single global, `window.App`.
 *
 *   <script src="https://cdn.jsdelivr.net/npm/@supabase/supabase-js@2"></script>
 *   <script src="app-base.js"></script>
 *
 * Rules this file follows, learned the hard way:
 *   - Nothing runs at load time except the export. `supabaseClient` does not
 *     exist yet when this file is parsed, so every function reads it lazily
 *     through `client()`.
 *   - Every helper is defensive: a missing client, a failed request or an
 *     unavailable sessionStorage must never throw at the top level, because a
 *     throw here leaves `window.App` undefined and every page dies with
 *     "App is not defined".
 *
 * Exports (window.App):
 *   esc(v)                          HTML-escape a value for innerHTML
 *   money(v, decimals)              "$1,234.56", never NaN
 *   num(v, fallback)                number or fallback
 *   copyText(text)                  clipboard with a non-HTTPS fallback
 *   getAuth()                       {user, session} or null
 *   requireSession(opts)            redirect to login unless signed in
 *   requireVerifiedSession(opts)    the above + 2FA code entered in this tab
 *   isOtpVerified(userId)           did this tab pass the code step?
 *   getAccountFlags(userId)         {is_2fa_enabled} or null
 *   getPostLoginTarget()            where the login page sends people
 *   getPrices(force)                {SYMBOL: {usd, change24h}} or null
 *   signedUrl(bucket, path, ttl)    temporary URL for a private object
 */
(function (global) {
    'use strict';

    var LOGIN_PAGE = './pl.html';
    var DASHBOARD_PAGE = './profile.html';
    var OTP_KEY = 'exnya_otp_verified';

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
        var n = Number(value);
        if (!isFinite(n)) return '$0.00';
        var d = decimals === undefined ? 2 : decimals;
        return '$' + n.toLocaleString('en-US', {
            minimumFractionDigits: d,
            maximumFractionDigits: d
        });
    }

    /** Format a raw number, falling back when it is not finite. */
    function num(value, fallback) {
        var n = Number(value);
        return isFinite(n) ? n : (fallback === undefined ? 0 : fallback);
    }

    /** Copy text to the clipboard, with a fallback for non-HTTPS contexts. */
    async function copyText(text) {
        if (!text) return false;
        try {
            if (global.navigator && global.navigator.clipboard && global.isSecureContext) {
                await global.navigator.clipboard.writeText(text);
                return true;
            }
        } catch (e) { /* fall through to the legacy path */ }
        try {
            var ta = document.createElement('textarea');
            ta.value = text;
            ta.setAttribute('readonly', '');
            ta.style.position = 'fixed';
            ta.style.top = '-1000px';
            document.body.appendChild(ta);
            ta.select();
            var ok = document.execCommand('copy');
            document.body.removeChild(ta);
            return ok;
        } catch (e) {
            return false;
        }
    }

    // ─── Auth ───────────────────────────────────────────────────────────

    /** The page's Supabase client, read lazily (it may not exist yet). */
    function client() {
        return global.supabaseClient || null;
    }

    /**
     * Resolve the current session. Returns { user, session } or null.
     *
     * getSession() already refreshes an expired token, and supabase-js keeps
     * refreshing in the background. Calling refreshSession() on every page
     * load bounced members to the login screen whenever the auth server
     * hiccupped, so it is never called here.
     */
    async function getAuth() {
        var c = client();
        if (!c || !c.auth) return null;
        try {
            var res = await c.auth.getSession();
            var session = res && res.data ? res.data.session : null;
            if (!session) return null;
            return { user: session.user, session: session };
        } catch (e) {
            console.warn('[app-base] getSession failed:', e && e.message);
            return null;
        }
    }

    /**
     * Has this tab passed the 2FA step? pl.html writes this after a code is
     * accepted. Without it a member with 2FA could open a page URL directly.
     */
    function isOtpVerified(userId) {
        try {
            var value = global.sessionStorage.getItem(OTP_KEY);
            if (!value) return false;
            return value === 'verified' || (!!userId && value === userId);
        } catch (e) {
            // Storage unavailable: do not lock the member out.
            console.warn('[app-base] sessionStorage unavailable; 2FA gate cannot be checked');
            return true;
        }
    }

    /** The profile fields the gate needs. Returns null when unknown. */
    async function getAccountFlags(userId) {
        var c = client();
        if (!c) return null;
        try {
            var res = await c.from('profiles').select('is_2fa_enabled').eq('id', userId).maybeSingle();
            if (res.error) {
                console.error('[app-base] could not read account flags:', res.error.message);
                return null;
            }
            return res.data;
        } catch (e) {
            console.error('[app-base] account flags request failed:', e && e.message);
            return null;
        }
    }

    /**
     * Page guard: redirects to the login page and returns null when there is
     * no session. Returns { user, session } otherwise.
     */
    async function requireSession(opts) {
        var options = opts || {};
        var auth = await getAuth();
        if (!auth) {
            global.location.href = options.redirect || LOGIN_PAGE;
            return null;
        }
        return auth;
    }

    /**
     * Full guard for a dashboard page: a session AND, when the account has 2FA
     * on, proof that a code was entered in this tab.
     *
     * If the flag cannot be read (network, permissions) the member is let
     * through rather than bounced: a failed lookup is not evidence of an
     * attack, and locking people out on a hiccup is the worse failure.
     */
    async function requireVerifiedSession(opts) {
        var auth = await requireSession(opts);
        if (!auth) return null;
        var flags = await getAccountFlags(auth.user.id);
        if (flags && flags.is_2fa_enabled && !isOtpVerified(auth.user.id)) {
            global.location.href = (opts && opts.redirect) || LOGIN_PAGE;
            return null;
        }
        return auth;
    }

    /** Where the login page sends a member who just signed in. */
    function getPostLoginTarget() {
        return DASHBOARD_PAGE;
    }

    // ─── Live prices (cached, one request per 30s across pages) ────────

    var PRICE_URL = 'https://api.coinlore.net/api/tickers/?limit=100';
    var PRICE_TTL = 30000;
    var PRICE_CACHE_KEY = 'exnya_prices';
    var pricePromise = null;

    function readPriceCache() {
        try {
            var raw = global.localStorage.getItem(PRICE_CACHE_KEY);
            if (!raw) return null;
            var parsed = JSON.parse(raw);
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

    /**
     * Resolve { SYMBOL: { usd, change24h } }.
     * Never throws: returns null when the API is unreachable, and callers must
     * cope (showing "—" rather than a confident $0.00).
     */
    async function getPrices(force) {
        if (!force) {
            var cached = readPriceCache();
            if (cached) return cached;
        }
        if (pricePromise) return pricePromise;

        pricePromise = (async function () {
            try {
                var res = await fetch(PRICE_URL, { cache: 'no-store' });
                if (!res.ok) throw new Error('HTTP ' + res.status);
                var json = await res.json();
                if (!json || !Array.isArray(json.data)) throw new Error('unexpected payload');
                var prices = {};
                json.data.forEach(function (coin) {
                    var usd = parseFloat(coin.price_usd);
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
     * Supabase Storage: turn a stored path into a temporary URL that resolves.
     * `kyc_documents` is private, so the raw path saved at upload time is not a
     * link — admin used to render a dead <a href> without this.
     */
    async function signedUrl(bucket, path, expiresIn) {
        var c = client();
        if (!c || !path) return null;
        if (/^https?:\/\//i.test(path)) return path;
        try {
            var res = await c.storage.from(bucket).createSignedUrl(path, expiresIn || 3600);
            if (res.error) {
                console.error('[app-base] createSignedUrl failed:', res.error.message);
                return null;
            }
            return res.data && res.data.signedUrl ? res.data.signedUrl : null;
        } catch (e) {
            console.error('[app-base] createSignedUrl threw:', e && e.message);
            return null;
        }
    }

    // ─── Export ─────────────────────────────────────────────────────────

    global.App = {
        esc: esc,
        money: money,
        num: num,
        copyText: copyText,
        getAuth: getAuth,
        requireSession: requireSession,
        requireVerifiedSession: requireVerifiedSession,
        isOtpVerified: isOtpVerified,
        getAccountFlags: getAccountFlags,
        getPostLoginTarget: getPostLoginTarget,
        getPrices: getPrices,
        signedUrl: signedUrl
    };
})(window);
