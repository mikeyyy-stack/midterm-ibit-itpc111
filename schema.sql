create extension if not exists pgcrypto;

create table public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  full_name text not null default 'New User',
  student_id text unique,
  email text,
  role text not null default 'scholar'
    check (role in ('scholar', 'staff')),
  created_at timestamptz not null default now()
);

-- Keep the Auth email available for staff assignment lookup in the client.
-- The ALTER supports projects where profiles was created before this column.
alter table public.profiles add column if not exists email text;
update public.profiles p
set email = lower(u.email)
from auth.users u
where u.id = p.id and p.email is distinct from lower(u.email);
create unique index if not exists profiles_email_lower_idx
  on public.profiles (lower(email)) where email is not null;

create table public.programs (
  id text primary key,
  name text not null unique,
  max_gwa numeric(3,2) not null check (max_gwa between 1 and 5),
  min_units integer not null check (min_units >= 0),
  max_failed integer not null default 0 check (max_failed >= 0),
  max_incomplete integer not null default 0 check (max_incomplete >= 0),
  max_dropped integer not null check (max_dropped >= 0),
  deadline timestamptz not null
);

insert into public.programs
(id, name, max_gwa, min_units, max_failed, max_incomplete, max_dropped, deadline)
values
('MERIT', 'Merit Scholar', 1.75, 18, 0, 0, 0, '2026-10-30 17:00:00+08'),
('COMMUNITY', 'Community Scholar', 2.25, 15, 0, 0, 1, '2026-10-30 17:00:00+08')
on conflict (id) do update set
  name = excluded.name,
  max_gwa = excluded.max_gwa,
  min_units = excluded.min_units,
  max_failed = excluded.max_failed,
  max_incomplete = excluded.max_incomplete,
  max_dropped = excluded.max_dropped,
  deadline = excluded.deadline;

create table public.assignments (
  id uuid primary key default gen_random_uuid(),
  scholar_id uuid not null references public.profiles(id),
  program_id text not null references public.programs(id),
  assigned_at timestamptz not null default now(),
  unique (scholar_id)
);

create table public.submissions (
  id uuid primary key default gen_random_uuid(),
  scholar_id uuid not null references public.profiles(id),
  program_id text not null references public.programs(id),
  academic_year text not null,
  semester text not null,
  gwa numeric(3,2) not null check (gwa between 1 and 5),
  enrolled_units integer not null check (enrolled_units >= 0),
  failed_count integer not null check (failed_count >= 0),
  incomplete_count integer not null check (incomplete_count >= 0),
  dropped_count integer not null check (dropped_count >= 0),
  evidence_ref text not null check (length(trim(evidence_ref)) > 0),
  submitted_at timestamptz not null default now(),
  verification_status text not null default 'Pending'
    check (verification_status in ('Pending','Verified','Returned')),
  verification_reason text,
  compliance_status text not null default 'Not Evaluated'
    check (compliance_status in ('Not Evaluated','Compliant','With Deficiency')),
  compliance_reasons text[] not null default '{}',
  renewal_decision text not null default 'Pending'
    check (renewal_decision in ('Pending','Approved','Held')),
  decision_note text,
  unique (scholar_id, academic_year, semester)
);

create table public.audit_logs (
  id bigint generated always as identity primary key,
  submission_id uuid not null references public.submissions(id) on delete cascade,
  actor_id uuid not null references public.profiles(id),
  action text not null,
  details jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);

-- Automatically create a scholar profile for new Auth users.
create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  insert into public.profiles (id, full_name, email, role)
  values (
    new.id,
    coalesce(new.raw_user_meta_data ->> 'full_name', 'New User'),
    lower(new.email),
    'scholar'
  )
  on conflict (id) do update
    set email = excluded.email;
  return new;
end;
$$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
after insert or update on auth.users
for each row execute function public.handle_new_user();

-- Security helper: the role comes from the database profile,
-- not from a browser-supplied role value.
create or replace function public.is_staff()
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1 from public.profiles p
    where p.id = (select auth.uid()) and p.role = 'staff'
  );
$$;

alter table public.profiles enable row level security;
alter table public.programs enable row level security;
alter table public.assignments enable row level security;
alter table public.submissions enable row level security;
alter table public.audit_logs enable row level security;

grant select on public.programs to authenticated;
grant select, insert, update on public.profiles to authenticated;
grant select, insert, update on public.assignments to authenticated;
grant select, insert, update on public.submissions to authenticated;
grant select, insert on public.audit_logs to authenticated;
grant execute on function public.is_staff() to authenticated;

-- Profiles: scholars can read their own profile.
create policy "profile_read_own_or_staff"
on public.profiles for select to authenticated
using (id = (select auth.uid()) or (select public.is_staff()));

create policy "staff_manage_profiles"
on public.profiles for update to authenticated
using ((select public.is_staff()))
with check (role in ('scholar','staff'));

-- Programs are readable by authenticated users; staff manage policies.
create policy "authenticated_read_programs"
on public.programs for select to authenticated using (true);

create policy "staff_update_programs"
on public.programs for update to authenticated
using ((select public.is_staff()))
with check ((select public.is_staff()));

-- Assignments are private to the assigned scholar and staff.
create policy "assignment_read_own_or_staff"
on public.assignments for select to authenticated
using (scholar_id = (select auth.uid()) or (select public.is_staff()));

create policy "staff_insert_assignments"
on public.assignments for insert to authenticated
with check ((select public.is_staff()));

create policy "staff_update_assignments"
on public.assignments for update to authenticated
using ((select public.is_staff()))
with check ((select public.is_staff()));

-- Staff can read all submissions; scholars only their own.
create policy "submission_read_own_or_staff"
on public.submissions for select to authenticated
using (scholar_id = (select auth.uid()) or (select public.is_staff()));

create policy "scholar_insert_assigned_submission"
on public.submissions for insert to authenticated
with check (
  scholar_id = (select auth.uid())
  and verification_status = 'Pending'
  and compliance_status = 'Not Evaluated'
  and renewal_decision = 'Pending'
  and exists (
    select 1 from public.assignments a
    where a.scholar_id = (select auth.uid())
      and a.program_id = submissions.program_id
  )
);

-- Scholars may only correct a returned submission.
create policy "scholar_correct_returned"
on public.submissions for update to authenticated
using (
  scholar_id = (select auth.uid())
  and verification_status = 'Returned'
)
with check (
  scholar_id = (select auth.uid())
  and verification_status = 'Pending'
  and compliance_status = 'Not Evaluated'
  and renewal_decision = 'Pending'
  and exists (
    select 1 from public.assignments a
    where a.scholar_id = (select auth.uid())
      and a.program_id = submissions.program_id
  )
);

-- Staff perform verification, evaluation and renewal updates.
create policy "staff_manage_submissions"
on public.submissions for update to authenticated
using ((select public.is_staff()))
with check ((select public.is_staff()));

create policy "audit_read_own_or_staff"
on public.audit_logs for select to authenticated
using (
  actor_id = (select auth.uid())
  or (select public.is_staff())
  or exists (
    select 1 from public.submissions s
    where s.id = audit_logs.submission_id
      and s.scholar_id = (select auth.uid())
  )
);

create policy "staff_insert_audit"
on public.audit_logs for insert to authenticated
with check (
  actor_id = (select auth.uid())
  and (select public.is_staff())
);

-- No public/anonymous table access.
revoke all on public.profiles, public.programs, public.assignments,
  public.submissions, public.audit_logs from anon;

-- Identity columns used by the audit table.
grant usage, select on sequence public.audit_logs_id_seq to authenticated;