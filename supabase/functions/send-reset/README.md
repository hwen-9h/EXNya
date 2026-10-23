# Password reset email (Resend)

`send-reset` is a small Edge Function that emails the password-reset link
through [Resend](https://resend.com) instead of relying on Supabase's SMTP
settings. Free tier is 100 emails/day — plenty for resets.

## Deploy

### 1. Get a Resend API key
1. Sign up at <https://resend.com> (free)
2. **API Keys → Create API Key**, permission "Sending access"
3. Copy the `re_…` key

### 2. Add the domain you will send from
- **Domains → Add Domain**, enter your domain, add the DNS records Resend shows
- Or, to test immediately, use `onboarding@resend.dev` — it only delivers to the
  address that owns the Resend account

### 3. Set the function secrets
Dashboard → **Project Settings → Edge Functions → Secrets**, add:

| Name | Value |
|---|---|
| `RESEND_API_KEY` | `re_…` |
| `RESEND_FROM` | `EXNYA <no-reply@yourdomain.com>` (must be a verified domain) |
| `APP_URL` | `https://your-site.example` (no trailing slash) |

`SUPABASE_URL` and `SUPABASE_SERVICE_ROLE_KEY` are injected automatically.

### 4. Turn off Supabase's own mailer for recovery
Auth → **Email Templates** → *Reset Password*: the function now sends its own
email, so this template is only a fallback when the function is missing.

Auth → **URL Configuration → Redirect URLs**: add `https://your-site.example/pl.html`.
The function builds the link with `APP_URL/pl.html`, and Supabase rejects a
redirect that is not on this list.

### 5. Deploy the function
```sh
supabase functions deploy send-reset --no-verify-jwt
```
`--no-verify-jwt` is intentional: the caller is a stranger who has forgotten
their password, so they have no session. The function never trusts the caller —
it only accepts an email address and always answers the same way.

Or paste the file into Dashboard → **Edge Functions → Deploy a new function →
Via editor**, name it `send-reset`, and turn **Verify JWT** off.

### 6. Create the rate-limit tables
Run `supabase-reset-rate-limit.sql` in the SQL Editor.

## Verify

```sh
curl -X POST "https://YOUR-PROJECT.supabase.co/functions/v1/send-reset" \
  -H "apikey: YOUR_ANON_KEY" \
  -H "Content-Type: application/json" \
  -d '{"email":"you@example.com"}'
```

Expected: `{"ok":true,"message":"If that address has an account, a reset link is on its way."}`
— the same body for an address that does not exist.

## What it protects against

| Attack | Defence |
|---|---|
| Finding out who has an account | Identical response for unknown and known addresses |
| Spamming one inbox | 3 requests per address per 15 minutes |
| Spamming from one source | 10 requests per IP per 15 minutes |
| Forging reset links | Links are minted server-side with `generateLink()`, which needs the service role key |
| Token leaking into logs | The user object returned by `generateLink` (which contains the token) is never logged |
| A leaked anon key | The anon key alone cannot mint a link; only this function can |

## If it fails

| Symptom | Cause |
|---|---|
| `Email service is not configured` (500) | `RESEND_API_KEY` secret missing |
| `Could not send the email right now` (502) | Resend refused — check the function logs; usually an unverified `RESEND_FROM` domain |
| Email arrives but the link 404s | `APP_URL` wrong, or `/pl.html` missing from Supabase's Redirect URLs |
| `Too many attempts` (429) | Rate limit hit — wait out `retry_after` seconds |
| Nothing in the inbox, no error | Resend free tier only delivers to your own address until a domain is verified |
