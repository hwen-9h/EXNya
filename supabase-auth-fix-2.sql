-- EXNYA auth fix, part 2 of 2 — run this AFTER part 1 succeeded.
-- Only two things live here: the signup profile trigger and the KYC storage
-- policies. Both are small on their own, which is why they are in a
-- separate file (the editor gets confused pasting everything at once).

-- ── 10. Profile auto-create trigger (keeps signup working) ──────────────
-- Every new auth.users row gets a matching public.profiles row. If a
-- previous trigger was dropped, this restores it.
create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer
set search_path = public
as $fn2$
begin
  insert into public.profiles (id, email, first_name, last_name)
  values (
    new.id,
    new.email,
    coalesce(new.raw_user_meta_data ->> 'first_name', ''),
    coalesce(new.raw_user_meta_data ->> 'last_name', '')
  )
  on conflict (id) do update set
    email = excluded.email,
    first_name = case when public.profiles.first_name = ''
                      then excluded.first_name else public.profiles.first_name end,
    last_name  = case when public.profiles.last_name = ''
                      then excluded.last_name else public.profiles.last_name end;
  return new;
end;
$fn2$;

drop trigger if exists on_auth_user_created on auth.users;

create trigger on_auth_user_created
  after insert on auth.users
  for each row execute function public.handle_new_user();

-- ── 11. KYC storage policies (bucket stays private) ─────────────────────
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
