-- Secure RDMS: Supabase/Postgres schema. Apply with `supabase db push`.
create extension if not exists pgcrypto;

create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  full_name text not null default '',
  email text not null default '',
  username text unique,
  role text not null default 'researcher' check (role in ('admin','researcher','viewer')),
  is_active boolean not null default true,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create or replace function public.handle_new_user()
returns trigger language plpgsql security definer set search_path = '' as $$
begin
  insert into public.profiles(id, full_name, email, username, role)
  values (new.id, coalesce(new.raw_user_meta_data->>'full_name',''), coalesce(new.email,''), nullif(new.raw_user_meta_data->>'username',''), 'researcher')
  on conflict (id) do nothing;
  return new;
end; $$;
drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created after insert on auth.users for each row execute procedure public.handle_new_user();

create or replace function public.current_role()
returns text language sql stable security definer set search_path = '' as $$
  select role from public.profiles where id = (select auth.uid()) and is_active = true limit 1;
$$;
create or replace function public.is_admin()
returns boolean language sql stable security definer set search_path = '' as $$ select coalesce(public.current_role() = 'admin', false); $$;

create table if not exists public.research_files (
  id uuid primary key default gen_random_uuid(),
  title text not null,
  project_code text not null,
  description text not null default '',
  original_filename text not null,
  mime_type text not null default 'application/octet-stream',
  file_size bigint not null default 0,
  storage_path text not null unique,
  encryption_version text not null default 'AES-256-GCM-v1',
  uploaded_by uuid not null references public.profiles(id),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create index if not exists research_files_uploaded_by_idx on public.research_files(uploaded_by);
create index if not exists research_files_created_at_idx on public.research_files(created_at desc);

create table if not exists public.file_assignments (
  id uuid primary key default gen_random_uuid(),
  file_id uuid not null references public.research_files(id) on delete cascade,
  user_id uuid not null references public.profiles(id) on delete cascade,
  assigned_by uuid not null references public.profiles(id),
  created_at timestamptz not null default now(),
  unique(file_id,user_id)
);

create table if not exists public.audit_logs (
  id bigint generated always as identity primary key,
  user_id uuid references public.profiles(id) on delete set null,
  username text not null default 'system',
  action text not null,
  resource text not null default 'system',
  details text not null default '',
  ip_address text,
  user_agent text,
  status text not null default 'success' check(status in ('success','failed','warning')),
  created_at timestamptz not null default now()
);
create index if not exists audit_logs_created_at_idx on public.audit_logs(created_at desc);
create index if not exists audit_logs_action_idx on public.audit_logs(action);

create table if not exists public.security_alerts (
  id uuid primary key default gen_random_uuid(),
  user_id uuid references public.profiles(id) on delete set null,
  alert_type text not null,
  message text not null,
  severity text not null default 'medium' check(severity in ('low','medium','high','critical')),
  resolved boolean not null default false,
  resolved_by uuid references public.profiles(id),
  resolved_at timestamptz,
  created_at timestamptz not null default now()
);
create index if not exists security_alerts_created_at_idx on public.security_alerts(created_at desc);

create table if not exists public.login_attempts (
  id bigint generated always as identity primary key,
  username text not null,
  event_type text not null check(event_type in ('login_failed','mfa_failed')),
  ip_address text,
  created_at timestamptz not null default now()
);
create index if not exists login_attempts_username_time_idx on public.login_attempts(username,created_at desc);

alter table public.profiles enable row level security;
alter table public.research_files enable row level security;
alter table public.file_assignments enable row level security;
alter table public.audit_logs enable row level security;
alter table public.security_alerts enable row level security;
alter table public.login_attempts enable row level security;

-- Users can read their own profile. Admins can read all profiles. Only trusted Edge Functions
-- (service role) may provision users or change roles/status.
create policy "profiles read self or admin" on public.profiles for select to authenticated using (id = (select auth.uid()) or public.is_admin());
create policy "files read permitted metadata" on public.research_files for select to authenticated using (
  public.is_admin() or uploaded_by = (select auth.uid()) or exists (
    select 1 from public.file_assignments a where a.file_id = research_files.id and a.user_id = (select auth.uid())
  )
);
create policy "assignments read self or admin" on public.file_assignments for select to authenticated using (user_id = (select auth.uid()) or public.is_admin());
create policy "audit logs admin read" on public.audit_logs for select to authenticated using (public.is_admin());
create policy "alerts admin read" on public.security_alerts for select to authenticated using (public.is_admin());
create policy "alerts admin resolve" on public.security_alerts for update to authenticated using (public.is_admin()) with check (public.is_admin());
-- No client policies for INSERT/UPDATE/DELETE on research files, audit logs, attempts or assignments.
-- All sensitive writes are performed by validated Edge Functions using the service role.

insert into storage.buckets(id,name,public,file_size_limit,allowed_mime_types)
values ('research-vault','research-vault',false,5242880,
  array['application/pdf','text/plain','text/csv','application/vnd.openxmlformats-officedocument.wordprocessingml.document','application/msword','application/vnd.openxmlformats-officedocument.spreadsheetml.sheet','application/vnd.ms-excel','application/vnd.openxmlformats-officedocument.presentationml.presentation','application/vnd.ms-powerpoint','image/png','image/jpeg','application/zip','application/octet-stream'])
on conflict (id) do update set public=false, file_size_limit=5242880, allowed_mime_types=excluded.allowed_mime_types;

-- The storage bucket intentionally has no authenticated object policies. Only Edge Functions
-- using the service role can read/write encrypted objects after performing ownership checks.
