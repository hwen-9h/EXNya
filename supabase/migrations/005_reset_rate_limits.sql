-- Rate-limit counters for the send-reset Edge Function (security part 5).
-- Run once in SQL Editor. Small, no secrets, service-role access only.

create table if not exists public.password_reset_rate_ip (
  key          text primary key,
  count        integer not null default 1,
  window_start timestamptz not null default now()
);

create table if not exists public.password_reset_rate_email (
  key          text primary key,
  count        integer not null default 1,
  window_start timestamptz not null default now()
);

-- Nobody but the service role may see or touch these.
alter table public.password_reset_rate_ip    enable row level security;
alter table public.password_reset_rate_email enable row level security;

revoke all on public.password_reset_rate_ip    from anon, authenticated;
revoke all on public.password_reset_rate_email from anon, authenticated;

-- Housekeeping: drop windows older than a day so the tables stay tiny.
create or replace function public.reset_rate_cleanup()
returns void
language sql
security definer
set search_path = public
as $rc$
  delete from public.password_reset_rate_ip    where window_start < now() - interval '1 day';
  delete from public.password_reset_rate_email where window_start < now() - interval '1 day';
$rc$;

revoke all on function public.reset_rate_cleanup() from anon, authenticated;
