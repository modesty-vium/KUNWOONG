-- ============================================================
--  건웅기계 홈페이지 - 회원/로그인 데이터베이스 스키마
--  Supabase 대시보드 → SQL Editor 에 붙여넣고 [Run] 실행
-- ============================================================

-- 1) 회원정보 테이블 (auth.users 와 1:1 연결)
create table if not exists public.profiles (
  id          uuid references auth.users on delete cascade primary key,
  email       text,
  name        text,
  company     text,
  phone       text,
  role        text default 'customer',   -- customer / admin
  created_at  timestamptz default now(),
  updated_at  timestamptz default now()
);

-- 2) 로그인 이력 테이블
create table if not exists public.login_history (
  id            bigint generated always as identity primary key,
  user_id       uuid references auth.users on delete cascade,
  email         text,
  logged_in_at  timestamptz default now(),
  user_agent    text,
  ip_address    text
);

create index if not exists idx_login_history_user on public.login_history (user_id);
create index if not exists idx_login_history_time on public.login_history (logged_in_at desc);

-- ============================================================
-- 3) RLS (행 수준 보안) - 본인 데이터만 접근 가능
-- ============================================================
alter table public.profiles      enable row level security;
alter table public.login_history enable row level security;

-- profiles 정책
drop policy if exists "본인 프로필 조회" on public.profiles;
create policy "본인 프로필 조회" on public.profiles
  for select using (auth.uid() = id);

drop policy if exists "본인 프로필 수정" on public.profiles;
create policy "본인 프로필 수정" on public.profiles
  for update using (auth.uid() = id);

-- login_history 정책
drop policy if exists "본인 로그인이력 조회" on public.login_history;
create policy "본인 로그인이력 조회" on public.login_history
  for select using (auth.uid() = user_id);

drop policy if exists "본인 로그인이력 추가" on public.login_history;
create policy "본인 로그인이력 추가" on public.login_history
  for insert with check (auth.uid() = user_id);

-- ============================================================
-- 4) 회원가입 시 profiles 자동 생성 트리거
-- ============================================================
create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer set search_path = public
as $$
begin
  insert into public.profiles (id, email, name, company, phone)
  values (
    new.id,
    new.email,
    new.raw_user_meta_data->>'name',
    new.raw_user_meta_data->>'company',
    new.raw_user_meta_data->>'phone'
  );
  return new;
end;
$$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
  after insert on auth.users
  for each row execute function public.handle_new_user();
