-- EXNYA auth fix, part 1 of 2 — run this FIRST in Supabase SQL Editor.
-- (Part 2: supabase-auth-fix-2.sql)
--
-- Fixes the "permission denied / 42501" errors the app throws, without
-- opening the tables to the world: users only touch their own rows, admins
-- (is_admin = true) keep full access.
--
-- IMPORTANT: run with the statements as they are. If the editor complains
-- about "unexpected end of function definition", make sure you pasted the
-- WHOLE file (it ends with the storage policies at the bottom).

-- ── 0. Helper: is the caller an admin? ─────────────────────────────────
create or replace function public.is_admin()
returns boolean
language sql
security definer
set search_path = public
stable
as $fn$
  select coalesce(
    (select p.is_admin from public.profiles p where p.id = auth.uid()),
    false
  );
$fn$;

-- ── 1. Make sure RLS is on everywhere ───────────────────────────────────
alter table public.profiles            enable row level security;
alter table public.user_assets         enable row level security;
alter table public.p2p_trades          enable row level security;
alter table public.withdrawal_requests enable row level security;
alter table public.ledger_entries      enable row level security;
alter table public.escrow_transactions enable row level security;
alter table public.audit_log           enable row level security;
alter table public.otp_codes           enable row level security;
alter table public.user_wallets        enable row level security;

-- ── 2. Drop old / half-working policies ────────────────────────────────
drop policy if exists "Users can view own profile"      on public.profiles;
drop policy if exists "Users can update own profile"    on public.profiles;
drop policy if exists "Users can insert own profile"    on public.profiles;
drop policy if exists "Enable read for own profile"     on public.profiles;
drop policy if exists "Enable update for own profile"   on public.profiles;
drop policy if exists "Enable insert for own profile"   on public.profiles;
drop policy if exists "profiles_select_own"             on public.profiles;
drop policy if exists "profiles_update_own"             on public.profiles;
drop policy if exists "profiles_insert_own"             on public.profiles;
drop policy if exists "profiles_admin_all"              on public.profiles;
drop policy if exists "Admins full access profiles"     on public.profiles;

drop policy if exists "Users manage own assets"         on public.user_assets;
drop policy if exists "Enable all for own assets"       on public.user_assets;
drop policy if exists "user_assets_own_all"             on public.user_assets;
drop policy if exists "user_assets_admin_all"           on public.user_assets;
drop policy if exists "Admins full access assets"       on public.user_assets;

drop policy if exists "Users manage own trades"         on public.p2p_trades;
drop policy if exists "Open ads readable"               on public.p2p_trades;
drop policy if exists "p2p_trades_select_visible"       on public.p2p_trades;
drop policy if exists "p2p_trades_insert_own"           on public.p2p_trades;
drop policy if exists "p2p_trades_update_party"         on public.p2p_trades;
drop policy if exists "p2p_trades_admin_all"            on public.p2p_trades;

drop policy if exists "Users manage own withdrawals"    on public.withdrawal_requests;
drop policy if exists "withdrawals_own_all"             on public.withdrawal_requests;
drop policy if exists "withdrawals_admin_all"           on public.withdrawal_requests;

drop policy if exists "ledger_own_select"               on public.ledger_entries;
drop policy if exists "ledger_admin_all"                on public.ledger_entries;
drop policy if exists "escrow_party_select"             on public.escrow_transactions;
drop policy if exists "escrow_admin_all"                on public.escrow_transactions;
drop policy if exists "audit_admin_select"              on public.audit_log;
drop policy if exists "otp_codes_admin_all"             on public.otp_codes;
drop policy if exists "wallets_own_select"              on public.user_wallets;
drop policy if exists "wallets_admin_all"               on public.user_wallets;

-- ── 3. PROFILES ─────────────────────────────────────────────────────────
create policy "profiles_select_own"
  on public.profiles for select to authenticated
  using (auth.uid() = id);

create policy "profiles_insert_own"
  on public.profiles for insert to authenticated
  with check (auth.uid() = id);

-- A user may never change their own is_admin / balances / trade stats.
-- (Admins write those through profiles_admin_all below.)
create policy "profiles_update_own"
  on public.profiles for update to authenticated
  using (auth.uid() = id)
  with check (
    auth.uid() = id
    and is_admin is not distinct from
        ((select p.is_admin from public.profiles p where p.id = auth.uid()))
    and balance_usd is not distinct from
        ((select p.balance_usd from public.profiles p where p.id = auth.uid()))
    and escrow_held_usd is not distinct from
        ((select p.escrow_held_usd from public.profiles p where p.id = auth.uid()))
    and completed_trades_count is not distinct from
        ((select p.completed_trades_count from public.profiles p where p.id = auth.uid()))
    and merchant is not distinct from
        ((select p.merchant from public.profiles p where p.id = auth.uid()))
  );

create policy "profiles_admin_all"
  on public.profiles for all to authenticated
  using (public.is_admin())
  with check (public.is_admin());

-- ── 4. USER_ASSETS ──────────────────────────────────────────────────────
create policy "user_assets_own_all"
  on public.user_assets for all to authenticated
  using (auth.uid() = user_id)
  with check (auth.uid() = user_id);

create policy "user_assets_admin_all"
  on public.user_assets for all to authenticated
  using (public.is_admin())
  with check (public.is_admin());

-- ── 5. P2P_TRADES ───────────────────────────────────────────────────────
create policy "p2p_trades_select_visible"
  on public.p2p_trades for select to authenticated
  using (
    status = 'open'
    or auth.uid() = user_id
    or auth.uid() = matched_user_id
  );

create policy "p2p_trades_insert_own"
  on public.p2p_trades for insert to authenticated
  with check (auth.uid() = user_id);

create policy "p2p_trades_update_party"
  on public.p2p_trades for update to authenticated
  using (auth.uid() = user_id or auth.uid() = matched_user_id)
  with check (auth.uid() = user_id or auth.uid() = matched_user_id);

create policy "p2p_trades_admin_all"
  on public.p2p_trades for all to authenticated
  using (public.is_admin())
  with check (public.is_admin());

-- ── 6. WITHDRAWAL_REQUESTS ──────────────────────────────────────────────
create policy "withdrawals_own_all"
  on public.withdrawal_requests for all to authenticated
  using (auth.uid() = user_id)
  with check (auth.uid() = user_id);

create policy "withdrawals_admin_all"
  on public.withdrawal_requests for all to authenticated
  using (public.is_admin())
  with check (public.is_admin());

-- ── 7. LEDGER / ESCROW / WALLETS — read own, write via Edge Functions ───
create policy "ledger_own_select"
  on public.ledger_entries for select to authenticated
  using (auth.uid() = user_id);

create policy "ledger_admin_all"
  on public.ledger_entries for all to authenticated
  using (public.is_admin())
  with check (public.is_admin());

create policy "escrow_party_select"
  on public.escrow_transactions for select to authenticated
  using (auth.uid() = user_id);

create policy "escrow_admin_all"
  on public.escrow_transactions for all to authenticated
  using (public.is_admin())
  with check (public.is_admin());

create policy "wallets_own_select"
  on public.user_wallets for select to authenticated
  using (auth.uid() = user_id);

create policy "wallets_admin_all"
  on public.user_wallets for all to authenticated
  using (public.is_admin())
  with check (public.is_admin());

-- ── 8. AUDIT_LOG / OTP_CODES — never writable from the browser ──────────
create policy "audit_admin_select"
  on public.audit_log for select to authenticated
  using (public.is_admin() or auth.uid() = actor_id);

create policy "otp_codes_admin_all"
  on public.otp_codes for all to authenticated
  using (false)
  with check (false);

-- ── 9. Grants (policies alone are not enough) ───────────────────────────
grant usage on schema public to authenticated;
grant select, insert, update on public.profiles to authenticated;
grant all on public.user_assets to authenticated;
grant all on public.p2p_trades to authenticated;
grant all on public.withdrawal_requests to authenticated;
grant select on public.ledger_entries to authenticated;
grant select on public.escrow_transactions to authenticated;
grant select on public.user_wallets to authenticated;
grant select on public.audit_log to authenticated;
