# EXNYA — Security notes

What protects the app, what you still need to switch on, and what is
deliberately left to the backend.

## 1. What is already in place (code)

| Area | Control |
|---|---|
| Scripts | `app-base.js` / `settings.js` load in `<head>` before any page code uses `App.*` — a page can no longer run half-initialised |
| XSS | Every value that comes back from the database or from another user goes through `App.esc()` before it reaches `innerHTML`. `textContent` used where no markup is needed |
| Clickjacking | Every page has a `Content-Security-Policy` with `frame-ancestors 'none'` plus a JS framebuster for older browsers |
| Tab-nabbing | `rel="noopener noreferrer"` forced on every `target="_blank"` link |
| Referrer leakage | `strict-origin-when-cross-origin` — tokens in URLs are never sent to third parties |
| CSP | `object-src 'none'`, no `eval`, no inline event handlers from data, connection allow-list limited to your Supabase project, Coinlore and ipapi |
| Secrets | Only the **anon** key is in the browser. The `service_role` key and the database password appear nowhere in the repo |
| 2FA | Authenticator app (TOTP) via Supabase Auth MFA. The secret never leaves Supabase's `auth.mfa_factors`; `profiles.totp_secret` is unused |
| 2FA bypass | `security.html` and `admin.html` require a **verified** session, so a password alone cannot reach them |
| Session | `getSession()` only — no `refreshSession()` race that logs people out |
| Enumeration | Supabase returns the same `Invalid login credentials` for unknown users and wrong passwords |

## 2. What you must switch on (dashboard)

These are settings, not code. None of them are on by default in a fresh project.

### Authentication → Providers → Email
- [ ] **Confirm email = ON** for production. Right now a stranger can register
      with someone else's address and use it. (Signup currently works without
      confirmation because auto-confirm is on.)
- [ ] **Enable leaked password protection** (HaveIBeenPwned check)
- [ ] **Minimum password length = 8**, require letters and digits
- [ ] **Maximum signup rate** / CAPTCHA (Turnstile) — stops scripted account creation

### Authentication → URL Configuration
- [ ] **Site URL** = your real domain
- [ ] **Redirect allow-list** = your real domain only (no wildcards)

### Authentication → Sessions
- [ ] **JWT expiry** 3600s, **refresh token rotation ON**,
      **reuse interval** 10s, **time-box user sessions** if you want forced re-login

### Project Settings → API
- [ ] **Exposed schemas**: `public` only (never `auth`, `storage`, `extensions`)
- [ ] If you ever put a `service_role` key in a browser bundle, rotate it immediately

### Storage
- [ ] `kyc_documents` stays **private** (it already is)
- [ ] Add a **file size limit** and MIME allow-list (`image/jpeg,image/png,image/webp`)
- [ ] The bucket policies in `supabase-auth-fix-2.sql` restrict each user to their own folder

### Database
- [ ] Run `supabase-auth-fix-1.sql`, then `-2.sql`, then `supabase-security-hardening.sql`
- [ ] Turn on **Point-in-time recovery** (paid plans) before handling real money

## 3. What the SQL files enforce (server side)

Client code cannot be trusted, so the rules live in the database:

- `profiles` — a user may edit their own name, theme, currency, language,
  notification prefs, 2FA flag and KYC **document path**. They may **not**
  change `is_admin`, `role`, `balance_usd`, `escrow_held_usd`,
  `completed_trades_count`, `merchant`, or set `kyc_status = 'verified'`.
- `user_assets` — users can read their own rows and insert a **zero-balance**
  row. Quantity is written only by the wallet Edge Function / admin.
- `p2p_trades` — column-level grants: the browser may only write `status`,
  `matched_user_id`, `updated_at`. `escrow_status`, `tx_hash`,
  `escrow_address`, `escrow_locked_amount`, `amount`, `price` are service-role
  only. A taker cannot re-point an ad or rewrite its terms.
- `withdrawal_requests` — can only be inserted as `pending`, with no hash and
  no processed timestamp. Users cannot self-complete a payout.
- `otp_codes` — revoked for `anon` and `authenticated` entirely.
- `audit_log` — admin actions on other users' profiles are written
  automatically by a trigger.

## 4. Known gaps — things to fix next

1. **`kyc_document_url` is user-controlled.** A user could point it at another
   user's object path in the bucket. The storage policy still blocks reading
   it, but the admin queue should sign URLs only for paths under the row's own
   `id`. Consider moving the upload into an Edge Function.
2. **`profiles` exposes email to any signed-in user via the p2p join**
   (`select('id, first_name, ...')` is fine, but a future careless `select('*')`
   would leak addresses). Consider a `public_profiles` view.
3. **No server-side trade state machine.** The client moves a trade through
   `matched → paid → completed`. A malicious client can send any transition.
   Move the transitions into an Edge Function with the service role.
4. **Swap has no server-side price oracle.** It runs on Coinlore prices fetched
   in the browser. A modified client can quote any rate. Move quoting and
   balance changes into an Edge Function.
5. **No 2FA recovery codes.** If a user loses their phone they are locked out
   and an admin has to unenroll the factor manually (Supabase → Auth → Users →
   remove factor).
6. **`exnyaexchanger@gmail`** in `profiles` is not a valid email address —
   worth cleaning up so password reset never targets it.

## 5. Deploying

Because this is a static site, the CSP meta tag is the only header you control.
If you move to Netlify / Vercel / Cloudflare Pages, add the same CSP **plus**
`Strict-Transport-Security`, `X-Content-Type-Options: nosniff` and
`Permissions-Policy` as real HTTP headers — they are stronger than the meta tag.
