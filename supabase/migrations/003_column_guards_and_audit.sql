-- EXNYA security hardening, part 3 — run AFTER parts 1 and 2 in Supabase SQL Editor.
--
-- Closes the gaps that client code cannot close on its own:
--   1. a user could sign up and mark their own KYC "verified"
--   2. a user could credit their own portfolio (swap/p2p mint money)
--   3. a P2P counterparty could set escrow_status / tx_hash / status
--      on the other party's ad (fake escrow)
--   4. a withdraw_request could be inserted already "completed"
--
-- Design: the browser may only touch the columns a human is allowed to type.
-- Anything that represents money or trust (balance, escrow, completion counts,
-- KYC approval) is written by the service role (Edge Functions) or by an admin.

-- ── A. Helper: is the caller an admin? (created by part 1, redefined safe) ──
create or replace function public.is_admin()
returns boolean
language sql
security definer
set search_path = public
stable
as $fn3$
  select coalesce(
    (select p.is_admin from public.profiles p where p.id = auth.uid()),
    false
  );
$fn3$;

-- ── B. PROFILES: add kyc_status to the guarded columns ──────────────────
-- A user may edit their own name, theme, currency, language, font size,
-- notification prefs, kyc_document_url (the file they uploaded) and the 2FA
-- flag. They may NOT approve their own KYC, or change money/role columns.
drop policy if exists "profiles_update_own" on public.profiles;

create policy "profiles_update_own"
  on public.profiles for update to authenticated
  using (auth.uid() = id)
  with check (
    auth.uid() = id
    -- money and trust columns must keep their current value
    and is_admin is not distinct from
        ((select p.is_admin from public.profiles p where p.id = auth.uid()))
    and role is not distinct from
        ((select p.role from public.profiles p where p.id = auth.uid()))
    and balance_usd is not distinct from
        ((select p.balance_usd from public.profiles p where p.id = auth.uid()))
    and escrow_held_usd is not distinct from
        ((select p.escrow_held_usd from public.profiles p where p.id = auth.uid()))
    and completed_trades_count is not distinct from
        ((select p.completed_trades_count from public.profiles p where p.id = auth.uid()))
    and merchant is not distinct from
        ((select p.merchant from public.profiles p where p.id = auth.uid()))
    -- KYC: only an admin may move the status. A user may set it to 'pending'
    -- (submitting a document) but never back to 'verified'.
    and (
      kyc_status is not distinct from
        ((select p.kyc_status from public.profiles p where p.id = auth.uid()))
      or kyc_status = 'pending'
    )
  );

-- ── C. USER_ASSETS: quantity is money ──────────────────────────────────
-- Users may add a row for an asset they do not hold yet (quantity 0) and read
-- their own rows, but only the service role / admin may change a quantity.
drop policy if exists "user_assets_own_all"  on public.user_assets;
drop policy if exists "user_assets_own_read" on public.user_assets;

create policy "user_assets_own_read"
  on public.user_assets for select to authenticated
  using (auth.uid() = user_id);

create policy "user_assets_own_insert_empty"
  on public.user_assets for insert to authenticated
  with check (auth.uid() = user_id and quantity = 0);

-- (no UPDATE / DELETE policy for users: they cannot mint or burn assets)

-- ── D. P2P_TRADES: escrow fields belong to the escrow service ──────────
-- Column-level grants are the cleanest tool here: the browser may only write
-- the fields a trader types. status is included because the UI moves a trade
-- open -> matched -> paid -> completed, but escrow_* / tx_hash / amounts are
-- service-role only.
revoke update on public.p2p_trades from authenticated;
grant  update (status, matched_user_id, updated_at) on public.p2p_trades to authenticated;

-- The taker must not be able to re-point the ad at a different maker, and the
-- maker must not be able to overwrite an accepted ad's terms.
drop policy if exists "p2p_trades_update_party" on public.p2p_trades;

create policy "p2p_trades_update_party"
  on public.p2p_trades for update to authenticated
  using (auth.uid() = user_id or auth.uid() = matched_user_id)
  with check (
    -- the maker keeps ownership of their own ad
    (auth.uid() = user_id and user_id = (select t.user_id from public.p2p_trades t where t.id = id))
    or
    -- the taker may only claim an open ad, or update one they are matched on
    (auth.uid() = matched_user_id)
  );

-- ── E. WITHDRAWAL_REQUESTS: nobody may self-complete a withdrawal ──────
drop policy if exists "withdrawals_own_all" on public.withdrawal_requests;

create policy "withdrawals_own_select"
  on public.withdrawal_requests for select to authenticated
  using (auth.uid() = user_id);

create policy "withdrawals_own_insert_pending"
  on public.withdrawal_requests for insert to authenticated
  with check (
    auth.uid() = user_id
    and coalesce(status, 'pending') in ('pending', 'requested')
    and transaction_hash is null
    and processed_at is null
  );

-- (no UPDATE: the wallet Edge Function marks it processed; the user cancels
--  by asking support, or extend this later with a pending-only UPDATE policy)

-- ── F. OTP_CODES: remove entirely from the public schema paths ─────────
-- TOTP replaced email codes, so this table should not be reachable at all.
revoke all on public.otp_codes from anon;
revoke all on public.otp_codes from authenticated;

-- ── G. Audit trail: record admin actions on other people's data ────────
create or replace function public.log_profile_change()
returns trigger
language plpgsql
security definer
set search_path = public
as $fn4$
begin
  -- only log changes an admin made to somebody else's row
  if auth.uid() is not null and auth.uid() <> new.id then
    insert into public.audit_log (actor_id, action, target_type, target_id, metadata)
    values (
      auth.uid(),
      'profiles.update',
      'profiles',
      new.id::text,
      jsonb_build_object(
        'kyc_status', new.kyc_status,
        'is_admin', new.is_admin,
        'balance_usd', new.balance_usd
      )
    );
  end if;
  return new;
end;
$fn4$;

drop trigger if exists profiles_audit_admin_change on public.profiles;

create trigger profiles_audit_admin_change
  after update on public.profiles
  for each row execute function public.log_profile_change();

-- ── H. Sanity: every table the app reads has RLS on ────────────────────
do $chk$
declare t text;
begin
  for t in
    select c.relname
    from pg_class c
    join pg_namespace n on n.oid = c.relnamespace
    where n.nspname = 'public' and c.relkind = 'r'
      and not c.relrowsecurity
  loop
    raise notice 'RLS is OFF on public.%', t;
  end loop;
end
$chk$;
