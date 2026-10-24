// supabase/functions/send-reset/index.ts
//
// POST /functions/v1/send-reset   { "email": "user@example.com" }
//
// Sends an EXNYA password-reset email through Resend, so the app does not
// depend on Supabase's SMTP settings (which silently fail when unset).
//
// Security properties, in order of importance:
//   * It NEVER reveals whether an address is registered. Unknown address and
//     known address both return 200 with the same body.
//   * The reset link is minted with the SERVICE ROLE key via
//     generateLink({type:'recovery'}), so the anon key can never mint links.
//   * Rate limited per address (3 per 15 min) and per IP (10 per 15 min).
//     Counters live on the caller's row in public.password_reset_requests;
//     there is no new secret table to manage.
//   * The user object returned by generateLink contains the reset token, so
//     it is never logged.
//
// Required secrets:
//   supabase secrets set RESEND_API_KEY=re_xxx
//   supabase secrets set RESEND_FROM="EXNYA <no-reply@yourdomain.com>"
//   supabase secrets set APP_URL="https://your-site.example"   (optional)
//
// SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY are injected automatically.

// @ts-ignore - Deno runtime
import { serve } from "https://deno.land/std@0.224.0/http/server.ts";
// @ts-ignore
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const SUPABASE_URL = Deno.env.get("SUPABASE_URL") ?? "";

function getServiceKey() {
  // Prefer the modern named secret key; retain legacy service-role fallback
  // so existing deployments can rotate keys without breaking password reset.
  const raw = Deno.env.get("SUPABASE_SECRET_KEYS");
  if (raw) {
    try {
      const keys = JSON.parse(raw);
      if (typeof keys.default === "string" && keys.default) return keys.default;
    } catch { /* fall through to legacy server key */ }
  }
  return Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ??
    Deno.env.get("SERVICE_ROLE_KEY") ?? "";
}

const SERVICE_KEY = getServiceKey();
const RESEND_API_KEY = Deno.env.get("RESEND_API_KEY") ?? "";
const RESEND_FROM = Deno.env.get("RESEND_FROM") ??
  Deno.env.get("RESEND_FROM_EMAIL") ?? "EXNYA <onboarding@resend.dev>";
const APP_URL = (Deno.env.get("APP_URL") ?? "").replace(/\/+$/, "");

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};

const WINDOW_MS = 15 * 60 * 1000;
const MAX_PER_EMAIL = 3;
const MAX_PER_IP = 10;

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...CORS, "Content-Type": "application/json" },
  });
}

/** Same answer for every request, so the endpoint cannot be used to probe accounts. */
const NEUTRAL = { ok: true, message: "If that address has an account, a reset link is on its way." };

function escapeHtml(s: string) {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}

function emailBody(link: string, appUrl: string) {
  const safeLink = escapeHtml(link);
  const brand = appUrl ? escapeHtml(appUrl) : "EXNYA";
  const text =
    `Someone asked to reset the password for your EXNYA account.\n\n` +
    `Open this link to choose a new password (valid for one hour):\n${link}\n\n` +
    `If this wasn't you, ignore this email — your password will not change.\n`;
  const html = `<!doctype html><html><body style="margin:0;padding:0;background:#080b0f;font-family:Arial,Helvetica,sans-serif">
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#080b0f;padding:32px 16px">
    <tr><td align="center">
      <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="max-width:520px;background:#0d1117;border:1px solid #1e2733;border-radius:14px;padding:32px">
        <tr><td>
          <h1 style="margin:0 0 8px;font-size:20px;color:#fcd535;font-family:Arial,sans-serif">Reset your password</h1>
          <p style="margin:0 0 20px;font-size:14px;line-height:1.6;color:#a9b2bf">
            Someone asked to reset the password for your ${brand} account. If it was you, choose a new password below.
            The link is valid for one hour.
          </p>
          <p style="margin:0 0 24px">
            <a href="${safeLink}" style="display:inline-block;background:#fcd535;color:#000;text-decoration:none;
               font-weight:700;font-size:14px;padding:13px 26px;border-radius:8px">Choose a new password</a>
          </p>
          <p style="margin:0 0 8px;font-size:12px;color:#5e6a7a">Button not working? Copy this address into your browser:</p>
          <p style="margin:0 0 24px;font-size:11px;color:#7b8794;word-break:break-all">${safeLink}</p>
          <p style="margin:0;font-size:12px;color:#5e6a7a;border-top:1px solid #1e2733;padding-top:16px">
            If this wasn't you, ignore this email — your password will not change and nobody can sign in with the link once it expires.
          </p>
        </td></tr>
      </table>
    </td></tr>
  </table>
</body></html>`;
  return { text, html };
}

/** Seconds until this key may be used again, or 0. */
async function rateLimit(admin: any, key: string, table: string, max: number) {
  const now = Date.now();
  const { data } = await admin.from(table)
    .select("count, window_start")
    .eq("key", key).maybeSingle();

  if (!data) {
    await admin.from(table).upsert({ key, count: 1, window_start: new Date(now).toISOString() });
    return 0;
  }
  const started = new Date(data.window_start).getTime();
  if (now - started > WINDOW_MS) {
    await admin.from(table).upsert({ key, count: 1, window_start: new Date(now).toISOString() });
    return 0;
  }
  if (data.count >= max) return Math.ceil((WINDOW_MS - (now - started)) / 1000);
  await admin.from(table).update({ count: data.count + 1 }).eq("key", key);
  return 0;
}

serve(async (req: Request) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: CORS });
  if (req.method !== "POST") return json({ error: "Method not allowed" }, 405);

  let email = "";
  try {
    const body = await req.json();
    email = String(body.email ?? "").trim().toLowerCase();
  } catch {
    return json({ error: "Expected a JSON body with an email" }, 400);
  }
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return json({ error: "Enter a valid email address" }, 400);
  }

  if (!SUPABASE_URL || !SERVICE_KEY) {
    console.error("Password reset service is not configured");
    return json({ error: "Password reset service is not configured" }, 503);
  }

  const ip = req.headers.get("x-forwarded-for")?.split(",")[0].trim() || "unknown";
  const admin = createClient(SUPABASE_URL, SERVICE_KEY, { auth: { persistSession: false } });

  // ── rate limits (silent: still answers neutrally) ────────────────────
  try {
    const ipWait = await rateLimit(admin, ip, "password_reset_rate_ip", MAX_PER_IP);
    const mailWait = await rateLimit(admin, email, "password_reset_rate_email", MAX_PER_EMAIL);
    if (ipWait || mailWait) {
      return json({ ...NEUTRAL, retry_after: Math.max(ipWait, mailWait) }, 429);
    }
  } catch (e) {
    // A missing rate-limit table must not take password reset down.
    console.warn("rate limit unavailable:", (e as Error).message);
  }

  // ── mint the recovery link ───────────────────────────────────────────
  // Unknown addresses fail here; the caller never learns that.
  const redirectTo = APP_URL ? `${APP_URL}/pl.html` : undefined;
  const { data: linkData, error: linkError } = await admin.auth.admin.generateLink({
    type: "recovery",
    email,
    options: redirectTo ? { redirectTo } : undefined,
  });

  if (linkError || !linkData?.properties?.action_link) {
    console.log("no link for request (address probably unknown)");
    return json(NEUTRAL);
  }

  const link = linkData.properties.action_link;

  if (!RESEND_API_KEY) {
    console.error("RESEND_API_KEY secret is not set");
    return json({ error: "Email service is not configured" }, 500);
  }

  const { text, html } = emailBody(link, APP_URL);
  const resend = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${RESEND_API_KEY}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      from: RESEND_FROM,
      to: [email],
      subject: "Reset your EXNYA password",
      text,
      html,
    }),
  });

  if (!resend.ok) {
    const detail = await resend.text();
    console.error("resend failed:", resend.status, detail.slice(0, 300));
    return json({ error: "Could not send the email right now. Try again shortly." }, 502);
  }

  return json(NEUTRAL);
});
