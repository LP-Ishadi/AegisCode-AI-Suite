-- Apply after 202610200001_live_scan_adapters.sql.
begin;
create table public.manual_reviews (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations(id) on delete cascade,
  scan_id uuid not null unique,
  status text not null default 'active' check (status in ('active','completed')),
  step integer not null default 0 check (step between 0 and 20),
  prompt jsonb not null,
  created_by uuid not null references auth.users(id),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  foreign key (scan_id, organization_id) references public.scans(id, organization_id) on delete cascade
);
create table public.manual_review_steps (
  review_id uuid not null references public.manual_reviews(id) on delete cascade,
  step integer not null,
  action text not null check (action in ('tool','final')),
  response jsonb not null,
  tool_summary jsonb,
  created_at timestamptz not null default now(),
  primary key (review_id, step)
);
alter table public.manual_reviews enable row level security;
alter table public.manual_review_steps enable row level security;
revoke all on public.manual_reviews, public.manual_review_steps from public, anon, authenticated;
grant select on public.manual_reviews, public.manual_review_steps to authenticated;
grant all on public.manual_reviews, public.manual_review_steps to service_role;
create policy manual_review_read on public.manual_reviews for select to authenticated
  using (organization_id in (
    select organization_id from public.organization_members
    where user_id = (select auth.uid()) and role in ('owner','admin')
  ));
create policy manual_review_step_read on public.manual_review_steps for select to authenticated
  using (review_id in (select id from public.manual_reviews));

-- Compare-and-swap avoids two browser submissions advancing the same review.
create function public.advance_manual_review(
  p_review_id uuid, p_step integer, p_action text, p_response jsonb,
  p_tool_summary jsonb, p_next_prompt jsonb, p_findings jsonb default '[]'
) returns boolean language plpgsql security invoker set search_path = '' as $$
declare
  review public.manual_reviews%rowtype;
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
    update public.scans set status = 'completed', error_code = null,
      engine_version = left(coalesce(engine_version || '+manual-v1', 'manual-v1'), 100),
      completed_at = now()
      where id = review.scan_id;
    update public.scan_jobs set status = 'completed', last_error = null
      where scan_id = review.scan_id and status = 'failed';
    update public.pull_requests p set
      status = case when exists(select 1 from public.findings f
        where f.scan_id = review.scan_id and not f.resolved)
        then 'action_required' else 'passed' end,
      risk_tags = array(select distinct f.rule_id from public.findings f
        where f.scan_id = review.scan_id and not f.resolved), updated_at = now()
      where p.latest_scan_id = review.scan_id;
  end if;
  return true;
end;
$$;
revoke all on function public.advance_manual_review(uuid,integer,text,jsonb,jsonb,jsonb,jsonb)
  from public, anon, authenticated;
grant execute on function public.advance_manual_review(uuid,integer,text,jsonb,jsonb,jsonb,jsonb)
  to service_role;
commit;
