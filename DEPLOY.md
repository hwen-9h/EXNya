# EXNYA — deployment and setup

Ordered checklist. The app is a static site plus a Supabase project; nothing
here needs a build step.

---

## 1. Put the site online

Any static host works (GitHub Pages, Netlify, Vercel, Cloudflare Pages).

- Publish the repository root — `index.html` is the landing page, `pl.html` is
  sign-in.
- **Serve over HTTPS.** Supabase Auth cannot store a session on `file://` or on
  plain `http://` for anything other than localhost.
- If you use GitHub Pages: Settings → Pages → Source = `main` / root.
  The site lands at `https://<user>.github.io/EXnYa/`.

After the domain is known, replace the `APP_URL` value in step 4 with it.

---

## 2. Apply the database migrations

Supabase Dashboard → **SQL Editor** → new query → paste → **Run**.

| Order | File | What it does |
|---|---|---|
| 1 | `supabase/migrations/001_rls_profiles_and_policies.sql` | Admin helper, RLS policies, grants |
| 2 | `supabase/migrations/002_trigger_and_storage.sql` | Profile auto-create trigger, KYC storage policies |
| 3 | `supabase/migrations/003_column_guards_and_audit.sql` | Stops self-approving KYC and self-crediting balances; audit trigger |
| 4 | `supabase/migrations/004_swap_and_p2p_functions.sql` | `swap_execute()` and `p2p_transition()` — the only places money moves |
| 5 | `supabase/migrations/005_reset_rate_limits.sql` | Rate-limit tables for the reset function |

Run them **in order**: 003 revokes things 001 granted, 004 replaces the policies
003 created.

Migrations are written to be re-runnable; if one reports
`policy ... already exists`, it is safe to delete that `create policy` line and
run the rest.

---

## 3. Authentication settings

Dashboard → **Authentication**.

### Providers → Email
- **Confirm email: ON** (this is what `confirm.html` handles)
- **Leaked password protection: ON**
- Minimum password length 8, require letters and digits

### URL Configuration
- **Site URL**: `https://your-site.example`
- **Redirect URLs**, add all three:
  ```
  https://your-site.example
  https://your-site.example/pl.html
  https://your-site.example/confirm.html
  ```

### Sessions
- Refresh token rotation **ON**, reuse interval 10s

### Email templates
If you switch on email confirmation, the *Confirm signup* template's link must
point at `confirm.html`. Supabase's default works — it appends the tokens — as
long as the redirect above is allowed.

---

## 4. Password reset emails (`send-reset`)

Without this, "Forgot your password?" cannot deliver. It is independent of
Supabase's SMTP settings.

1. Create a free [Resend](https://resend.com) account → **API Keys → Create**
2. Dashboard → **Project Settings → Edge Functions → Secrets**:

   | Name | Value |
   |---|---|
   | `RESEND_API_KEY` | `re_…` |
   | `RESEND_FROM` | `EXNYA <no-reply@yourdomain.com>` (or `onboarding@resend.dev` while testing) |
   | `APP_URL` | `https://your-site.example` — no trailing slash |

3. Dashboard → **Edge Functions → Deploy a new function → Via editor**:
   - name `send-reset`
   - paste `supabase/functions/send-reset/index.ts`
   - **Verify JWT: off** (the caller has no session; the function never trusts them)
4. Full notes and troubleshooting: `supabase/functions/send-reset/README.md`

---

## 5. Two-factor authentication

Authenticator app (TOTP) via Supabase Auth MFA — no email, no SMTP involved.
No setup needed beyond migrations 001–002.

Members enable it at **Security → Set up authenticator app**. Enrolment shows a
QR code and a manual key; disabling requires a live code.

> Accounts created under the old email-2FA build carry `is_2fa_enabled = true`
> with no enrolled factor. They sign in without a second step until they enrol.
> To clear the stale flag:
> ```sql
> update public.profiles set is_2fa_enabled = false where id = '<user-id>';
> ```

---

## 6. Housekeeping

- Delete the unused Edge Functions `send-otp` and `verify-otp` (TOTP replaced them).
- The `escrow` function returns `503 BOOT_ERROR` and is no longer called — delete
  it or redeploy it if you want on-chain escrow later.
- Storage bucket `kyc_documents` must stay **private**; add a 5 MB limit and an
  image-only MIME allow-list.
- Point-in-time recovery before handling real money.

---

## 7. Verify the deployment

| Check | Expected |
|---|---|
| `https://your-site.example/pl.html` | Sign-in page, console silent |
| Sign in with a real account | Lands on `profile.html`, stays there |
| Reload `profile.html` | Still signed in |
| Sign up a new address | "Check your inbox" prompt; link opens `confirm.html` |
| Forgot password | Email arrives; link opens the "choose a new password" form |
| Settings → save | Toast confirms |
| Swap | Succeeds with a live quote; refuses a stale one |
| Security → set up authenticator | QR + key, then a code activates it |

---

## Local development

```sh
# any static server works
python -m http.server 8000
# then open http://localhost:8000/pl.html
```

`file://` will not work: the browser blocks session storage, so sign-in silently
fails.
