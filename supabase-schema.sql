-- ============================================================
--  SchemeAI — Supabase Database Schema (COMPLETE)
--  Run this entire file in:
--  Supabase Dashboard → SQL Editor → New Query → Paste → Run
-- ============================================================

-- 1. PROFILES
create table if not exists public.profiles (
  id            uuid references auth.users(id) on delete cascade primary key,
  full_name     text,
  phone         text,
  state         text,
  category      text default 'General',
  income        numeric,
  plan          text default 'free',
  plan_since    timestamptz,
  created_at    timestamptz default now(),
  updated_at    timestamptz default now()
);

create or replace function public.handle_new_user()
returns trigger language plpgsql security definer set search_path = public as $$
begin
  insert into public.profiles (id, full_name)
  values (new.id, new.raw_user_meta_data ->> 'full_name');
  return new;
end;
$$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
  after insert on auth.users
  for each row execute procedure public.handle_new_user();

-- 2. SAVED SCHEMES
create table if not exists public.saved_schemes (
  id            uuid primary key default gen_random_uuid(),
  user_id       uuid references auth.users(id) on delete cascade not null,
  scheme_name   text not null,
  match_score   int,
  saved_at      timestamptz default now()
);
create index if not exists saved_schemes_user_idx on public.saved_schemes(user_id);

-- 3. APPLICATIONS
create table if not exists public.applications (
  id            uuid primary key default gen_random_uuid(),
  user_id       uuid references auth.users(id) on delete cascade not null,
  scheme_id     text,
  scheme_name   text,
  status        text default 'draft',
  notes         text,
  updated_at    timestamptz default now(),
  created_at    timestamptz default now()
);
create index if not exists applications_user_idx on public.applications(user_id);

-- 4. REFERRALS
create table if not exists public.referrals (
  id            uuid primary key default gen_random_uuid(),
  referrer_id   uuid references auth.users(id) on delete cascade not null,
  referred_id   uuid references auth.users(id),
  status        text default 'pending',
  created_at    timestamptz default now()
);
create index if not exists referrals_referrer_idx on public.referrals(referrer_id);

-- 5. DOCUMENT SUMMARIES (NEW — needed for AI PDF analyzer)
create table if not exists public.document_summaries (
  id            uuid primary key default gen_random_uuid(),
  user_id       uuid references auth.users(id) on delete cascade,
  file_name     text,
  file_type     text,
  type          text,
  result        text,
  created_at    timestamptz default now()
);
create index if not exists doc_summaries_user_idx on public.document_summaries(user_id);

-- ============================================================
--  ROW LEVEL SECURITY
-- ============================================================
alter table public.profiles enable row level security;
create policy "User can view own profile"   on public.profiles for select using (auth.uid() = id);
create policy "User can update own profile" on public.profiles for update using (auth.uid() = id);

alter table public.saved_schemes enable row level security;
create policy "User can manage own saved schemes"
  on public.saved_schemes for all using (auth.uid() = user_id);

alter table public.applications enable row level security;
create policy "User can manage own applications"
  on public.applications for all using (auth.uid() = user_id);

alter table public.referrals enable row level security;
create policy "User can view own referrals"
  on public.referrals for select using (auth.uid() = referrer_id);

alter table public.document_summaries enable row level security;
create policy "User owns summaries"
  on public.document_summaries for all using (auth.uid() = user_id);

-- ============================================================
--  SET ADMIN — run separately after signup
--  Replace with your actual email
-- ============================================================
-- update auth.users
--   set raw_user_meta_data = raw_user_meta_data || '{"role":"admin"}'::jsonb
--   where email = 'your@email.com';
