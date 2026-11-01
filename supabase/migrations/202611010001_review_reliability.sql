-- Apply after 202610230001_manual_reviews.sql. Manual AI review is additive evidence;
-- it must never erase a failed or incomplete worker scan.
begin;
create function public.require_completed_scan_for_pass()
returns trigger language plpgsql security invoker set search_path = '' as $$
begin
  if new.status = 'passed' and not exists (
    select 1 from public.scans s join public.scan_jobs j on j.scan_id = s.id
    where s.id = new.latest_scan_id and s.status = 'completed'
      and s.error_code is null and j.status = 'completed'
  ) then
    raise exception 'A PR cannot pass without a completed worker scan';
  end if;
  return new;
end;
$$;
create trigger require_completed_scan_for_pass
  before insert or update of status, latest_scan_id on public.pull_requests
  for each row execute function public.require_completed_scan_for_pass();

-- The old function used `manual-v1` with no scanner engine when it upgraded a
-- failed worker scan. Restore those identifiable historical failures. The
-- original failure reason was erased by the old function and cannot be recovered.
update public.scan_jobs j set status = 'failed',
  last_error = 'manual_review_overrode_failure'
  from public.scans s where j.scan_id = s.id and s.engine_version = 'manual-v1';
update public.scans set status = 'failed',
  error_code = 'manual_review_overrode_failure', engine_version = null
  where engine_version = 'manual-v1';
update public.pull_requests p set status = 'failed', updated_at = now()
  from public.scans s where p.latest_scan_id = s.id
    and s.error_code = 'manual_review_overrode_failure';

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
    insert into public.findings(organization_id, scan_id, rule_id, file_path, line,
      severity, message, resolved)
      select review.organization_id, review.scan_id, f.rule_id, f.file_path, f.line,
        f.severity, f.message, p.latest_scan_id is distinct from review.scan_id
      from jsonb_to_recordset(p_findings) as f(rule_id text, file_path text,
        line integer, severity text, message text)
      join public.scans s on s.id = review.scan_id
      join public.pull_requests p on p.id = s.pull_request_id
      where not exists (
        select 1 from public.findings existing
        where existing.scan_id = review.scan_id and existing.rule_id = f.rule_id
          and existing.file_path = f.file_path and existing.line = f.line
      );
    -- Only a successfully completed worker scan can produce a passed PR.
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
