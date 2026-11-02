-- Enforce MFA (AAL2) for protected data, logs, alerts and administration.
drop policy if exists "profiles read self or admin" on public.profiles;
create policy "profiles read self or admin" on public.profiles for select to authenticated using (id = (select auth.uid()) or (auth.jwt()->>'aal' = 'aal2' and public.is_admin()));
-- Profile self-read remains available at AAL1 so a new user can enrol an authenticator.
drop policy if exists "files read permitted metadata" on public.research_files;
create policy "files read permitted metadata" on public.research_files for select to authenticated using (
  (auth.jwt()->>'aal' = 'aal2') and (public.is_admin() or uploaded_by = (select auth.uid()) or exists (
    select 1 from public.file_assignments a where a.file_id = research_files.id and a.user_id = (select auth.uid())
  ))
);
drop policy if exists "assignments read self or admin" on public.file_assignments;
create policy "assignments read self or admin" on public.file_assignments for select to authenticated using (
  auth.jwt()->>'aal' = 'aal2' and (user_id = (select auth.uid()) or public.is_admin())
);
drop policy if exists "audit logs admin read" on public.audit_logs;
create policy "audit logs admin read" on public.audit_logs for select to authenticated using (auth.jwt()->>'aal' = 'aal2' and public.is_admin());
drop policy if exists "alerts admin read" on public.security_alerts;
create policy "alerts admin read" on public.security_alerts for select to authenticated using (auth.jwt()->>'aal' = 'aal2' and public.is_admin());
drop policy if exists "alerts admin resolve" on public.security_alerts;
create policy "alerts admin resolve" on public.security_alerts for update to authenticated using (auth.jwt()->>'aal' = 'aal2' and public.is_admin()) with check (auth.jwt()->>'aal' = 'aal2' and public.is_admin());
-- Avoid exposing login attempt records to browser clients.
revoke all on public.login_attempts from anon, authenticated;
-- The application never accepts role changes from self-service signup. New accounts are researchers.

-- Record failed login/MFA attempts and create an alert after five failures in ten minutes.
-- The RPC is callable only by the Edge Function service role, not browser clients.
create or replace function public.record_auth_failure(p_username text, p_event_type text, p_ip text)
returns void language plpgsql security definer set search_path = '' as $$
declare
  v_count integer;
begin
  if p_event_type not in ('login_failed','mfa_failed') or length(trim(p_username)) < 3 then
    raise exception 'Invalid authentication failure event';
  end if;
  if (select count(*) from public.login_attempts where ip_address = p_ip and created_at > now() - interval '10 minutes') >= 60 then
    return;
  end if;
  insert into public.login_attempts(username,event_type,ip_address) values (left(lower(trim(p_username)),320),p_event_type,left(p_ip,64));
  select count(*) into v_count from public.login_attempts
    where username = left(lower(trim(p_username)),320) and event_type = p_event_type and created_at > now() - interval '10 minutes';
  if v_count >= 5 and not exists (
    select 1 from public.security_alerts where alert_type = case when p_event_type='login_failed' then 'REPEATED_LOGIN_FAILURES' else 'REPEATED_MFA_FAILURES' end
      and message like '%' || left(lower(trim(p_username)),320) || '%' and created_at > now() - interval '10 minutes'
  ) then
    insert into public.security_alerts(alert_type,message,severity)
    values (case when p_event_type='login_failed' then 'REPEATED_LOGIN_FAILURES' else 'REPEATED_MFA_FAILURES' end,
      'At least five ' || replace(p_event_type,'_',' ') || ' events were recorded for ' || left(lower(trim(p_username)),320) || ' within ten minutes.',
      case when p_event_type='login_failed' then 'high' else 'medium' end);
  end if;
end; $$;
revoke all on function public.record_auth_failure(text,text,text) from public, anon, authenticated;
grant execute on function public.record_auth_failure(text,text,text) to service_role;
