-- Apply after 202611060001_review_contracts.sql, before rebuilding backend/worker.
-- Coverage and AI citations are committed with the review transition.
begin;

create table public.review_coverage_files (
  scan_id uuid not null,
  organization_id uuid not null,
  review_mode text not null
    check (review_mode in ('scanner_only','manual','automated','legacy_ai')),
  file_path text not null check (length(file_path) between 1 and 1024),
  outcome text not null check (outcome in
    ('snapshot_acquired','diff_only','supplied_context','read_file','omitted')),
  reason text check (reason is null or length(reason) between 1 and 100),
  updated_at timestamptz not null default now(),
  primary key (scan_id, review_mode, file_path),
  foreign key (scan_id, organization_id)
    references public.scans(id, organization_id) on delete cascade,
  foreign key (scan_id, review_mode)
    references public.review_coverage(scan_id, review_mode) on delete cascade
);
create index review_coverage_files_org_idx
  on public.review_coverage_files(organization_id);
alter table public.review_coverage_files enable row level security;
revoke all on public.review_coverage_files from public, anon, authenticated;
grant select on public.review_coverage_files to authenticated;
grant all on public.review_coverage_files to service_role;
create policy review_coverage_files_read on public.review_coverage_files
  for select to authenticated using (organization_id in (
    select organization_id from public.organization_members
    where user_id = (select auth.uid())
  ));

create function public.save_review_coverage_v2(p_scan_id uuid, p_entry jsonb)
returns boolean language plpgsql security invoker set search_path = '' as $$
declare
  target public.scans%rowtype;
  item jsonb;
  mode text;
begin
  select * into target from public.scans where id = p_scan_id;
  if not found then return false; end if;
  if jsonb_typeof(p_entry) is distinct from 'object'
    or p_entry->>'commit_sha' is distinct from target.commit_sha
    or jsonb_typeof(p_entry->'files') <> 'array'
    or jsonb_array_length(p_entry->'files') > 2000 then
    raise exception 'Invalid coverage payload';
  end if;
  mode := p_entry->>'mode';
  if not public.put_review_coverage(p_scan_id, mode, p_entry->>'status',
    p_entry->'summary') then raise exception 'Coverage scan missing'; end if;
  delete from public.review_coverage_files
    where scan_id = p_scan_id and review_mode = mode;
  for item in select value from jsonb_array_elements(p_entry->'files') loop
    if jsonb_typeof(item) <> 'object' then
      raise exception 'Invalid coverage file';
    end if;
    insert into public.review_coverage_files(
      scan_id, organization_id, review_mode, file_path, outcome, reason
    ) values (
      p_scan_id, target.organization_id, mode, item->>'path',
      item->>'outcome', item->>'reason'
    );
  end loop;
  return true;
end;
$$;
revoke all on function public.save_review_coverage_v2(uuid,jsonb)
  from public, anon, authenticated;
grant execute on function public.save_review_coverage_v2(uuid,jsonb)
  to service_role;

create function public.save_ai_evidence_v2(
  p_scan_id uuid, p_findings jsonb, p_mode text
) returns boolean language plpgsql security invoker set search_path = '' as $$
declare
  target public.scans%rowtype;
  item jsonb;
  citation jsonb;
  matched_id uuid;
begin
  select * into target from public.scans where id = p_scan_id;
  if not found then return false; end if;
  if jsonb_typeof(p_findings) <> 'array' or jsonb_array_length(p_findings) > 1000 then
    raise exception 'Invalid finding evidence payload';
  end if;
  for item in select value from jsonb_array_elements(p_findings) loop
    if coalesce(item->>'origin','scanner') <> 'ai' then continue; end if;
    if item->>'review_mode' is distinct from p_mode then
      raise exception 'AI finding review mode mismatch';
    end if;
    if jsonb_typeof(item->'evidence') <> 'array'
      or jsonb_array_length(item->'evidence') > 8
      or (p_mode <> 'legacy_ai' and jsonb_array_length(item->'evidence') = 0) then
      raise exception 'AI finding has invalid evidence';
    end if;
    select f.id into matched_id from public.findings f
      where f.scan_id = p_scan_id and f.origin = 'ai' and f.review_mode = p_mode
        and f.rule_id = item->>'rule_id' and f.file_path = item->>'file_path'
        and f.line = (item->>'line')::integer
      order by f.created_at desc limit 1;
    if matched_id is null then raise exception 'AI finding was not saved'; end if;
    for citation in select value from jsonb_array_elements(item->'evidence') loop
      if citation->>'commit_sha' is distinct from target.commit_sha
        or citation->>'source' is null
        or citation->>'source' not in ('diff','auto_context','read_file') then
        raise exception 'Invalid AI evidence reference';
      end if;
      perform public.put_finding_evidence(
        matched_id, citation->>'file_path', (citation->>'line')::integer,
        citation->>'role', citation->>'source'
      );
    end loop;
  end loop;
  return true;
end;
$$;
revoke all on function public.save_ai_evidence_v2(uuid,jsonb,text)
  from public, anon, authenticated;
grant execute on function public.save_ai_evidence_v2(uuid,jsonb,text)
  to service_role;

create function public.finish_scan_job_v3(
  p_job_id uuid, p_lease_token uuid, p_findings jsonb default '[]',
  p_engine_version text default null, p_error_code text default null,
  p_retryable boolean default false, p_review_mode text default 'scanner_only',
  p_coverage jsonb default null
) returns boolean language plpgsql security invoker set search_path = '' as $$
declare
  sid uuid;
  target public.scans%rowtype;
  item jsonb;
  primary_status text;
  job_status text;
  accepted boolean;
begin
  select scan_id into sid from public.scan_jobs where id = p_job_id;
  if sid is null then return false; end if;
  select * into target from public.scans where id = sid;
  if jsonb_typeof(p_coverage) <> 'array'
    or jsonb_array_length(p_coverage) not between 1 and 2 then
    raise exception 'Coverage is required for scan completion';
  end if;
  if exists(select 1 from jsonb_array_elements(p_coverage) entry
    where entry->>'commit_sha' is distinct from target.commit_sha) then
    raise exception 'Coverage commit mismatch';
  end if;
  if (select count(distinct entry->>'mode')
      from jsonb_array_elements(p_coverage) entry) < jsonb_array_length(p_coverage)
    or exists(select 1 from jsonb_array_elements(p_coverage) entry
      where entry->>'mode' is null
        or entry->>'mode' not in ('scanner_only','automated','legacy_ai')) then
    raise exception 'Invalid coverage modes';
  end if;
  if p_error_code is null then
    select entry->>'status' into primary_status
      from jsonb_array_elements(p_coverage) entry
      where entry->>'mode' = p_review_mode;
    if primary_status is null or primary_status not in ('complete','partial')
      or (primary_status = 'partial' and jsonb_array_length(p_findings) = 0)
      or (p_review_mode = 'scanner_only' and primary_status <> 'complete')
      or (p_review_mode = 'automated' and not exists (
        select 1 from jsonb_array_elements(p_coverage) entry
        where entry->>'mode' = 'scanner_only' and entry->>'status' = 'complete'
      )) then
      raise exception 'Incomplete review cannot complete a clean scan';
    end if;
  end if;
  accepted := public.finish_scan_job_v2(
    p_job_id, p_lease_token, p_findings, p_engine_version, p_error_code,
    p_retryable, p_review_mode
  );
  if not accepted then return false; end if;
  select status into job_status from public.scan_jobs where id = p_job_id;
  for item in select value from jsonb_array_elements(p_coverage) loop
    if p_error_code is not null then
      item := jsonb_set(item, '{status}', to_jsonb(
        case when job_status = 'queued' then 'pending' else 'failed' end::text
      ));
    end if;
    perform public.save_review_coverage_v2(sid, item);
  end loop;
  if p_error_code is null then
    perform public.save_ai_evidence_v2(sid, p_findings, p_review_mode);
  end if;
  return true;
end;
$$;
revoke all on function public.finish_scan_job_v3(uuid,uuid,jsonb,text,text,boolean,text,jsonb)
  from public, anon, authenticated;
grant execute on function public.finish_scan_job_v3(uuid,uuid,jsonb,text,text,boolean,text,jsonb)
  to service_role;

create function public.advance_manual_review_v2(
  p_review_id uuid, p_step integer, p_action text, p_response jsonb,
  p_tool_summary jsonb, p_next_prompt jsonb, p_findings jsonb default '[]',
  p_coverage jsonb default null
) returns boolean language plpgsql security invoker set search_path = '' as $$
declare
  sid uuid;
  accepted boolean;
begin
  select scan_id into sid from public.manual_reviews where id = p_review_id;
  if sid is null then return false; end if;
  if jsonb_typeof(p_coverage) is distinct from 'object'
    or p_coverage->>'mode' is distinct from 'manual'
    or (p_action = 'tool' and p_coverage->>'status' is distinct from 'pending')
    or (p_action = 'final' and (
      p_coverage->>'status' is null
      or p_coverage->>'status' not in ('complete','partial')
      or (p_coverage->>'status' = 'partial' and jsonb_array_length(p_findings) = 0)
    )) then
    raise exception 'Invalid manual coverage';
  end if;
  accepted := public.advance_manual_review(
    p_review_id, p_step, p_action, p_response, p_tool_summary,
    p_next_prompt, p_findings
  );
  if not accepted then return false; end if;
  perform public.save_review_coverage_v2(sid, p_coverage);
  if p_action = 'final' then
    perform public.save_ai_evidence_v2(sid, p_findings, 'manual');
  end if;
  return true;
end;
$$;
revoke all on function public.advance_manual_review_v2(uuid,integer,text,jsonb,jsonb,jsonb,jsonb,jsonb)
  from public, anon, authenticated;
grant execute on function public.advance_manual_review_v2(uuid,integer,text,jsonb,jsonb,jsonb,jsonb,jsonb)
  to service_role;

commit;
