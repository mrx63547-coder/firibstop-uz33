-- FiribStop UZ optional cloud history schema.
-- Run in the Supabase SQL Editor of your own project.
-- Never use a service_role/secret key in the browser; use only a public anon/publishable key.

create table if not exists public.scan_history (
  user_id uuid not null references auth.users (id) on delete cascade,
  local_id text not null check (length(local_id) between 1 and 80),
  record jsonb not null check (pg_column_size(record) <= 65536),
  updated_at timestamptz not null default now(),
  primary key (user_id, local_id)
);

alter table public.scan_history enable row level security;
alter table public.scan_history force row level security;

revoke all on table public.scan_history from anon, public;
grant select, insert, update, delete on table public.scan_history to authenticated;

drop policy if exists "Users can read their own scan history" on public.scan_history;
create policy "Users can read their own scan history"
  on public.scan_history for select to authenticated
  using ((select auth.uid()) = user_id);

drop policy if exists "Users can insert their own scan history" on public.scan_history;
create policy "Users can insert their own scan history"
  on public.scan_history for insert to authenticated
  with check ((select auth.uid()) = user_id);

drop policy if exists "Users can update their own scan history" on public.scan_history;
create policy "Users can update their own scan history"
  on public.scan_history for update to authenticated
  using ((select auth.uid()) = user_id)
  with check ((select auth.uid()) = user_id);

drop policy if exists "Users can delete their own scan history" on public.scan_history;
create policy "Users can delete their own scan history"
  on public.scan_history for delete to authenticated
  using ((select auth.uid()) = user_id);
