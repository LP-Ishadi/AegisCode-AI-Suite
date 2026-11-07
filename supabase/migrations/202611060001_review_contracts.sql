-- Apply after 202611010001_review_reliability.sql, then rebuild scan-worker.
-- Finding origin and review scope are separate from security severity.
begin;

alter table public.scans
  add column review_mode text not null default 'scanner_only'
    check (review_mode in ('unknown','scanner_only','manual','automated','legacy_ai'));
-- Historical scans may contain manual AI output, and their mode was not
-- recorded. Preserve that uncertainty instead of inventing provenance.
update public.scans set review_mode = 'unknown';

alter table public.findings
  add column origin text not null default 'scanner'
    check (origin in ('unknown','scanner','ai')),
  add column review_mode text not null default 'scanner_only'
    check (review_mode in ('unknown','scanner_only','manual','automated','legacy_ai')),
  add column evidence_status text not null default 'scanner_reported'
    check (evidence_status in ('scanner_reported','unverified','location_checked')),
  add constraint finding_origin_consistency check (
    (origin = 'unknown' and review_mode = 'unknown'
      and evidence_status = 'unverified')
    or
    (origin = 'scanner' and review_mode = 'scanner_only'
      and evidence_status = 'scanner_reported')
    or
    (origin = 'ai' and review_mode in ('manual','automated','legacy_ai')
      and evidence_status in ('unverified','location_checked'))
  );
update public.findings set origin = 'unknown', review_mode = 'unknown',
  evidence_status = 'unverified';
alter table public.findings add constraint findings_id_organization_unique
  unique (id, organization_id);

-- These records hold locations and selection metadata, never raw source.
create table public.finding_evidence (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations(id) on delete cascade,
  finding_id uuid not null,
  commit_sha text not null check (commit_sha ~ '^[0-9a-f]{40}$'),
  file_path text not null check (length(file_path) between 1 and 1024),
  line integer not null check (line > 0),
  role text not null check (length(role) between 1 and 40),
  source text not null check (length(source) between 1 and 40),
  created_at timestamptz not null default now(),
  foreign key (finding_id, organization_id)
    references public.findings(id, organization_id) on delete cascade,
  unique (finding_id, commit_sha, file_path, line, role, source)
);
create index finding_evidence_org_idx on public.finding_evidence(organization_id);

-- A citation must point to the exact commit that produced its finding.
create function public.check_finding_evidence_commit()
returns trigger language plpgsql security invoker set search_path = '' as $$
declare
  pinned_commit text;
begin
  select s.commit_sha into pinned_commit
    from public.findings f join public.scans s on s.id = f.scan_id
    where f.id = new.finding_id and f.organization_id = new.organization_id;
  if pinned_commit is null or new.commit_sha <> pinned_commit then
    raise exception 'Evidence commit does not match finding scan';
  end if;
  return new;
end;
$$;
create trigger check_finding_evidence_commit
  before insert or update of finding_id, organization_id, commit_sha
  on public.finding_evidence for each row
  execute function public.check_finding_evidence_commit();

create table public.review_coverage (
  scan_id uuid not null,
  organization_id uuid not null references public.organizations(id) on delete cascade,
  review_mode text not null
    check (review_mode in ('scanner_only','manual','automated','legacy_ai')),
  commit_sha text not null check (commit_sha ~ '^[0-9a-f]{40}$'),
  status text not null check (status in ('pending','complete','partial','failed')),
  summary jsonb not null default '{}'::jsonb
    check (jsonb_typeof(summary) = 'object' and octet_length(summary::text) <= 65536),
  updated_at timestamptz not null default now(),
  primary key (scan_id, review_mode),
  foreign key (scan_id, organization_id)
    references public.scans(id, organization_id) on delete cascade
);
create index review_coverage_org_idx on public.review_coverage(organization_id);

alter table public.finding_evidence enable row level security;
alter table public.review_coverage enable row level security;
revoke all on public.finding_evidence, public.review_coverage
  from public, anon, authenticated;
grant select on public.finding_evidence, public.review_coverage to authenticated;
grant all on public.finding_evidence, public.review_coverage to service_role;
create policy finding_evidence_read on public.finding_evidence for select to authenticated
  using (organization_id in (
    select organization_id from public.organization_members
    where user_id = (select auth.uid())
  ));
create policy review_coverage_read on public.review_coverage for select to authenticated
  using (organization_id in (
    select organization_id from public.organization_members
    where user_id = (select auth.uid())
  ));

-- A service-only, idempotent coverage write. The scan supplies tenant and
-- commit identity; the caller cannot move a ledger to another PR or tenant.
create function public.put_review_coverage(
  p_scan_id uuid, p_mode text, p_status text, p_summary jsonb default '{}'
) returns boolean language plpgsql security invoker set search_path = '' as $$
declare
  target public.scans%rowtype;
begin
  select * into target from public.scans where id = p_scan_id;
  if not found then return false; end if;
  if p_mode not in ('scanner_only','manual','automated','legacy_ai')
     or p_status not in ('pending','complete','partial','failed')
     or jsonb_typeof(p_summary) <> 'object'
     or octet_length(p_summary::text) > 65536 then
    raise exception 'Invalid coverage record';
  end if;
  insert into public.review_coverage(
    scan_id, organization_id, review_mode, commit_sha, status, summary
  ) values (
    p_scan_id, target.organization_id, p_mode, target.commit_sha, p_status, p_summary
  ) on conflict (scan_id, review_mode) do update set
    status = excluded.status, summary = excluded.summary, updated_at = now();
  return true;
end;
$$;
revoke all on function public.put_review_coverage(uuid,text,text,jsonb)
  from public, anon, authenticated;
grant execute on function public.put_review_coverage(uuid,text,text,jsonb)
  to service_role;

-- Replaying the same citation is harmless. Tenant and commit are derived
-- from the finding's scan rather than accepted from a caller.
create function public.put_finding_evidence(
  p_finding_id uuid, p_file_path text, p_line integer,
  p_role text, p_source text
) returns boolean language plpgsql security invoker set search_path = '' as $$
declare
  target record;
begin
  select f.organization_id, s.commit_sha into target
    from public.findings f join public.scans s on s.id = f.scan_id
    where f.id = p_finding_id;
  if not found then return false; end if;
  insert into public.finding_evidence(
    organization_id, finding_id, commit_sha, file_path, line, role, source
  ) values (
    target.organization_id, p_finding_id, target.commit_sha,
    p_file_path, p_line, p_role, p_source
  ) on conflict (finding_id, commit_sha, file_path, line, role, source)
    do nothing;
  return true;
end;
$$;
revoke all on function public.put_finding_evidence(uuid,text,integer,text,text)
  from public, anon, authenticated;
grant execute on function public.put_finding_evidence(uuid,text,integer,text,text)
  to service_role;

-- V2 keeps the existing lease compare-and-swap and persists trusted origin
-- fields. V1 remains for an in-flight old worker during a rolling rebuild.
create function public.finish_scan_job_v2(
  p_job_id uuid, p_lease_token uuid, p_findings jsonb default '[]',
  p_engine_version text default null, p_error_code text default null,
  p_retryable boolean default false, p_review_mode text default 'scanner_only'
) returns boolean language plpgsql security invoker set search_path = '' as $$
declare
  job public.scan_jobs%rowtype;
  pr public.pull_requests%rowtype;
  is_current boolean;
  retry boolean;
begin
  select * into job from public.scan_jobs where id = p_job_id for update;
  if not found or job.status <> 'running' or job.lease_token is distinct from p_lease_token
    or job.lease_expires_at <= now() then return false; end if;
  select p.* into pr from public.pull_requests p join public.scans s on s.pull_request_id = p.id
    where s.id = job.scan_id for update of p;
  is_current := pr.latest_scan_id = job.scan_id;
  if p_error_code is not null then
    if p_error_code not in ('adapter_unavailable','timeout','upstream_unavailable',
      'invalid_input','engine_error','repository_not_connected','ai_not_authorized',
      'github_configuration','github_access_denied','source_incomplete',
      'ai_configuration','invalid_ai_output') then
      raise exception 'Invalid error code';
    end if;
    retry := p_retryable and job.attempts < 3;
    update public.scan_jobs set status = case when retry then 'queued' else 'failed' end,
      available_at = now() + make_interval(secs => 5 * (2 ^ job.attempts)::integer),
      last_error = p_error_code, lease_token = null, lease_expires_at = null where id = job.id;
    update public.scans set status = case when retry then 'queued' else 'failed' end,
      error_code = p_error_code, completed_at = case when retry then null else now() end
      where id = job.scan_id;
    if is_current then
      update public.pull_requests set status = case when retry then 'queued' else 'failed' end,
        updated_at = now() where id = pr.id;
    end if;
    return true;
  end if;
  if p_review_mode not in ('scanner_only','automated','legacy_ai')
     or p_engine_version is null or length(p_engine_version) not between 1 and 100
     or jsonb_typeof(p_findings) <> 'array' or jsonb_array_length(p_findings) > 1000 then
    raise exception 'Invalid scan result';
  end if;
  if exists (
    select 1 from jsonb_to_recordset(p_findings) as f(origin text, review_mode text,
      evidence_status text)
    where coalesce(f.origin, 'scanner') not in ('scanner','ai')
       or (coalesce(f.origin, 'scanner') = 'scanner' and
         (coalesce(f.review_mode, 'scanner_only') <> 'scanner_only'
          or coalesce(f.evidence_status, 'scanner_reported') <> 'scanner_reported'))
       or (coalesce(f.origin, 'scanner') = 'ai' and
         (p_review_mode = 'scanner_only'
          or coalesce(f.review_mode, p_review_mode) <> p_review_mode
          or coalesce(f.evidence_status, 'unverified') not in
            ('unverified','location_checked')))
  ) then
    raise exception 'Invalid finding provenance';
  end if;
  insert into public.findings(
    organization_id, scan_id, rule_id, file_path, line, severity, message,
    origin, review_mode, evidence_status, resolved
  )
    select job.organization_id, job.scan_id, f.rule_id, f.file_path, f.line,
      f.severity, f.message, coalesce(f.origin, 'scanner'),
      coalesce(f.review_mode, case when f.origin = 'ai'
        then p_review_mode else 'scanner_only' end),
      coalesce(f.evidence_status, case when f.origin = 'ai'
        then 'unverified' else 'scanner_reported' end),
      not coalesce(is_current, false)
    from jsonb_to_recordset(p_findings) as f(
      rule_id text, file_path text, line integer, severity text, message text,
      origin text, review_mode text, evidence_status text
    );
  update public.scan_jobs set status = 'completed', last_error = null,
    lease_token = null, lease_expires_at = null where id = job.id;
  update public.scans set status = 'completed', engine_version = p_engine_version,
    review_mode = p_review_mode, error_code = null, completed_at = now()
    where id = job.scan_id;
  if is_current then
    update public.pull_requests set status = case when jsonb_array_length(p_findings) = 0
      then 'passed' else 'action_required' end,
      risk_tags = array(select distinct f->>'rule_id' from jsonb_array_elements(p_findings) f),
      updated_at = now() where id = pr.id;
  end if;
  return true;
end;
$$;
revoke all on function public.finish_scan_job_v2(uuid,uuid,jsonb,text,text,boolean,text)
  from public, anon, authenticated;
grant execute on function public.finish_scan_job_v2(uuid,uuid,jsonb,text,text,boolean,text)
  to service_role;

-- Manual findings are AI proposals, never scanner findings. Preserve the
-- safeguard from the previous migration: a failed scan stays failed.
create or replace function public.advance_manual_review(
  p_review_id uuid, p_step integer, p_action text, p_response jsonb,
  p_tool_summary jsonb, p_next_prompt jsonb, p_findings jsonb default '[]'
) returns boolean language plpgsql security invoker set search_path = '' as $$
declare
  review public.manual_reviews%rowtype;
  worker_status text;
  job_status text;
begin
  if p_action not in ('tool','final') or jsonb_typeof(p_findings) <> 'array'
     or jsonb_array_length(p_findings) > 100 then
    raise exception 'Invalid manual review transition';
  end if;
  update public.manual_reviews set step = step + 1,
    status = case when p_action = 'final' then 'completed' else 'active' end,
    prompt = p_next_prompt, updated_at = now()
    where id = p_review_id and status = 'active' and step = p_step and step < 20;
  if not found then return false; end if;
  select * into review from public.manual_reviews where id = p_review_id;
  insert into public.manual_review_steps(review_id, step, action, response, tool_summary)
    values (p_review_id, p_step, p_action, p_response, p_tool_summary);
  if p_action = 'final' then
    select s.status into worker_status from public.scans s
      where s.id = review.scan_id for update;
    select j.status into job_status from public.scan_jobs j
      where j.scan_id = review.scan_id for update;
    if worker_status not in ('completed','failed') or job_status not in ('completed','failed') then
      raise exception 'Worker scan has not finished';
    end if;
    insert into public.findings(
      organization_id, scan_id, rule_id, file_path, line, severity, message,
      origin, review_mode, evidence_status, resolved
    )
      select review.organization_id, review.scan_id, f.rule_id, f.file_path, f.line,
        f.severity, f.message, 'ai', 'manual', 'location_checked',
        p.latest_scan_id is distinct from review.scan_id
      from jsonb_to_recordset(p_findings) as f(rule_id text, file_path text,
        line integer, severity text, message text)
      join public.scans s on s.id = review.scan_id
      join public.pull_requests p on p.id = s.pull_request_id
      where not exists (
        select 1 from public.findings existing
        where existing.scan_id = review.scan_id and existing.rule_id = f.rule_id
          and existing.file_path = f.file_path and existing.line = f.line
          and existing.origin = 'ai' and existing.review_mode = 'manual'
      );
    if worker_status = 'completed' and job_status = 'completed' then
      update public.scans set
        engine_version = left(coalesce(engine_version || '+manual-v1', 'manual-v1'), 100)
        where id = review.scan_id;
      update public.pull_requests p set
        status = case when exists(select 1 from public.findings f
          where f.scan_id = review.scan_id and not f.resolved)
          then 'action_required' else 'passed' end,
        risk_tags = array(select distinct f.rule_id from public.findings f
          where f.scan_id = review.scan_id and not f.resolved), updated_at = now()
        where p.latest_scan_id = review.scan_id;
    else
      update public.pull_requests p set status = 'failed',
        risk_tags = array(select distinct f.rule_id from public.findings f
          where f.scan_id = review.scan_id and not f.resolved), updated_at = now()
        where p.latest_scan_id = review.scan_id;
    end if;
  end if;
  return true;
end;
$$;
revoke all on function public.advance_manual_review(uuid,integer,text,jsonb,jsonb,jsonb,jsonb)
  from public, anon, authenticated;
grant execute on function public.advance_manual_review(uuid,integer,text,jsonb,jsonb,jsonb,jsonb)
  to service_role;

commit;
