-- EXNYA migration 006 — run this in Supabase SQL Editor.
--
-- Problem found by testing the live project:
--   the signed-in browser gets
--     POST /rest/v1/rpc/swap_execute -> 403
--     {"code":"42501","message":"permission denied for function swap_execute"}
--   so swap.html's server call can never succeed, even with a correct quote.
--   `p2p_transition` is fine (400 "Trade not found" = reachable, correctly
--   refusing), so only swap_execute lost its grant.
--
-- Root cause: 004 revoked EXECUTE from PUBLIC but the GRANT to `authenticated`
-- did not survive (a later run of 003/004, or the function being recreated,
-- drops grants). Re-granting is idempotent and safe.

-- Make sure the function exists in the shape the page calls it.
-- (If 004 already created it, this is a no-op.)
do $chk$
begin
  if not exists (
    select 1 from pg_proc p
    join pg_namespace n on n.oid = p.pronamespace
    where n.nspname = 'public'
      and p.proname = 'swap_execute'
      and pg_get_function_identity_arguments(p.oid) =
          'text, numeric, text, numeric, jsonb'
  ) then
    raise notice 'swap_execute(text,numeric,text,numeric,jsonb) is missing — run 004 first';
  end if;
end
$chk$;

-- Re-grant for both roles that can call it.
revoke all on function public.swap_execute(text, numeric, text, numeric, jsonb) from public;
grant execute on function public.swap_execute(text, numeric, text, numeric, jsonb) to authenticated;
grant execute on function public.swap_execute(text, numeric, text, numeric, jsonb) to anon;

-- Same treatment for the P2P state machine, so a re-run of the grants above
-- cannot strand it in the same way.
do $p2p$
begin
  if exists (
    select 1 from pg_proc p
    join pg_namespace n on n.oid = p.pronamespace
    where n.nspname = 'public' and p.proname = 'p2p_transition'
  ) then
    execute 'revoke all on function public.p2p_transition(uuid, text) from public';
    execute 'grant execute on function public.p2p_transition(uuid, text) to authenticated';
  end if;
end
$p2p$;

-- ── Verify (expect: both lines say can_execute = true) ──────────────────
select
  p.proname                        as function_name,
  has_function_privilege('authenticated', p.oid, 'EXECUTE') as can_execute
from pg_proc p
join pg_namespace n on n.oid = p.pronamespace
where n.nspname = 'public'
  and p.proname in ('swap_execute', 'p2p_transition')
order by p.proname;
