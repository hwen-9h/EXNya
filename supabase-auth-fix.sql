-- EXNYA auth fix — run once in Supabase Dashboard → SQL Editor.
-- Fixes every "permission denied / 42501" error the app currently throws
-- WITHOUT opening the tables to the world: users can only touch their own
-- rows, admins (is_admin = true) keep full access, and login/signup keep
-- working through the existing profile auto-create trigger.
--
-- Order is important: the admin check function must exist before policies use it.

-- ── 0. Helper: is the caller an admin? ─────────────────────────────────
create or replace function public.is_admin()
returns boolean
language sql
security definer
set search_path = public
stable
as $$
  select coalesce(
    (select p.is_admin from public.profiles p where p.id = auth.uid()),
    false
  );
$$;

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

-- ── 2. Drop the old half-working policies (names may vary; drop by table) ─
-- profiles
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
-- user_assets
drop policy if exists "Users manage own assets"         on public.user_assets;
drop policy if exists "Enable all for own assets"       on public.user_assets;
drop policy if exists "user_assets_own_all"             on public.user_assets;
drop policy if exists "user_assets_admin_all"           on public.user_assets;
drop policy if exists "Admins full access assets"       on public.user_assets;
-- p2p_trades
drop policy if exists "Users manage own trades"         on public.p2p_trades;
drop policy if exists "Open ads readable"               on public.p2p_trades;
drop policy if exists "p2p_trades_select_visible"       on public.p2p_trades;
drop policy if exists "p2p_trades_insert_own"           on public.p2p_trades;
drop policy if exists "p2p_trades_update_party"         on public.p2p_trades;
drop policy if exists "p2p_trades_admin_all"            on public.p2p_trades;
-- withdrawal_requests
drop policy if exists "Users manage own withdrawals"   on public.withdrawal_requests;
drop policy if exists "withdrawals_own_all"             on public.withdrawal_requests;
drop policy if exists "withdrawals_admin_all"           on public.withdrawal_requests;
-- ledger / escrow / audit / otp / wallets
drop policy if exists "ledger_own_select"               on public.ledger_entries;
drop policy if exists "ledger_admin_all"                on public.ledger_entries;
drop policy if exists "escrow_party_select"             on public.escrow_transactions;
drop policy if exists "escrow_admin_all"                on public.escrow_transactions;
drop policy if exists "audit_admin_select"              on public.audit_log;
drop policy if exists "otp_deny_client"                 on public.otp_codes;
drop policy if exists "otp_codes_admin_all"             on public.otp_codes;
drop policy if exists "wallets_own_select"              on public.user_wallets;
drop policy if exists "wallets_admin_all"               on public.user_wallets;

-- ── 3. PROFILES ─────────────────────────────────────────────────────────
-- Login page reads is_2fa_enabled; every page reads the caller's own row;
-- signup updates first/last name on the row the trigger created; settings /
-- security / KYC update only the caller's own safe columns.
create policy "profiles_select_own"
  on public.profiles for select to authenticated
  using (auth.uid() = id);

create policy "profiles_insert_own"
  on public.profiles for insert to authenticated
  with check (auth.uid() = id);

-- UPDATE is column-guarded: a user may never flip their own is_admin,
-- balance_usd, escrow_held_usd, completed_trades_count or merchant.
-- (Admin console writes those through the admin policy below.)
create policy "profiles_update_own"
  on public.profiles for update to authenticated
  using (auth.uid() = id)
  with check (
    auth.uid() = id
    and is_admin               is not distinct from
        ((select p.is_admin from public.profiles p where p.id = auth.uid()))
    and balance_usd            is not distinct from
        ((select p.balance_usd from public.profiles p where p.id = auth.uid()))
    and escrow_held_usd        is not distinct from
        ((select p.escrow_held_usd from public.profiles p where p.id = auth.uid()))
    and completed_trades_count is not distinct from
        ((select p.completed_trades_count from public.profiles p where p.id = auth.uid()))
    and merchant               is not distinct from
        ((select p.merchant from public.profiles p where p.id = auth.uid()))
  );

create policy "profiles_admin_all"
  on public.profiles for all to authenticated
  using (public.is_admin())
  with check (public.is_admin());

-- ── 4. USER_ASSETS (portfolio / swap / wallet pages) ────────────────────
create policy "user_assets_own_all"
  on public.user_assets for all to authenticated
  using (auth.uid() = user_id)
  with check (auth.uid() = user_id);

create policy "user_assets_admin_all"
  on public.user_assets for all to authenticated
  using (public.is_admin())
  with check (public.is_admin());

-- ── 5. P2P_TRADES ───────────────────────────────────────────────────────
-- Anyone signed in can SEE open ads + trades they are a party to (needed for
-- the order book). Only the maker creates; maker or matched taker updates;
-- NOBODY deletes from the client (cancel = status update).
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
  using (
    auth.uid() = user_id
    or auth.uid() = matched_user_id
  )
  with check (
    auth.uid() = user_id
    or auth.uid() = matched_user_id
  );

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
-- These are money-movement tables: the service_role Edge Functions
-- (wallet-operations, escrow) write them; clients only read their own rows.
create policy "ledger_own_select"
  on public.ledger_entries for select to authenticated
  using (auth.uid() = user_id);

create policy "ledger_admin_all"
  on public.ledger_entries for all to authenticated
  using (public.is_admin())
  with check (public.is_admin());

create policy "escrow_party_select"
  on public.escrow_transactions for select to authenticated
  using (
    auth.uid() = user_id
    or auth.uid() = counterparty_id
  );

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

-- ── 8. AUDIT_LOG / OTP_CODES — never from the browser ───────────────────
-- No client policy = denied for anon/authenticated; only service_role
-- (Edge Functions) can read/write. This is what makes verify-otp secure:
-- codes can't be listed or brute-read by users.
create policy "audit_admin_select"
  on public.audit_log for select to authenticated
  using (public.is_admin());

create policy "otp_codes_admin_all"
  on public.otp_codes for all to authenticated
  using (false)
  with check (false);

-- ── 9. Grants (policies alone are not enough) ───────────────────────────
grant usage on schema public to authenticated;
grant select, insert, update on public.profiles            to authenticated;
grant all on public.user_assets, public.p2p_trades,
           public.withdrawal_requests                     to authenticated;
grant select on public.ledger_entries, public.escrow_transactions,
                public.user_wallets, public.audit_log      to authenticated;

-- ── 10. Profile auto-create trigger (keeps signup working) ──────────────
-- If a previous trigger was dropped, this restores it: every new
-- auth.users row gets a matching public.profiles row.
create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  insert into public.profiles (id, email, first_name, last_name)
  values (
    new.id,
    new.email,
    coalesce(new.raw_user_meta_data ->> 'first_name', ''),
    coalesce(new.raw_user_meta_data ->> 'last_name', '')
  on conflict (id) do update set
    email      = excluded.email,
    first_name = case when public.profiles.first_name = ''
                      then excluded.first_name else public.profiles.first_name end,
    last_name  = case when public.profiles.last_name = ''
                      then excluded.last_name else public.profiles.last_name end;
  return new;
end;
$$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
  after insert on auth.users
  for each row execute function public.handle_new_user();

-- ── 11. KYC storage: users upload to their own folder, admins read all ──
-- Bucket kyc_documents must stay PRIVATE.
drop policy if exists "kyc_insert_own"   on storage.objects;
drop policy if exists "kyc_select_admin" on storage.objects;

create policy "kyc_insert_own"
  on storage.objects for insert to authenticated
  with check (
    bucket_id = 'kyc_documents'
    and (storage.foldername(name))[1] = auth.uid()::text
  );

create policy "kyc_select_admin"
  on storage.objects for select to authenticated
  using (
    bucket_id = 'kyc_documents'
    and (
      (storage.foldername(name))[1] = auth.uid()::text
      or public.is_admin()
    )
  );
