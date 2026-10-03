-- Apply AFTER 202609300001_foundation.sql. All queue mutations are service-role only.
begin;
alter table public.repositories add column github_installation_id bigint
  check (github_installation_id > 0);
alter table public.pull_requests
  add column source_updated_at timestamptz not null default '-infinity',
  add column source_merged boolean not null default false,
  add column latest_scan_id uuid references public.scans(id) on delete set null;
alter table public.scans add column error_code text;
alter table public.webhook_deliveries
  add column scan_id uuid references public.scans(id) on delete set null;

create table public.scan_jobs (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations(id) on delete cascade,
  scan_id uuid not null unique,
  dedup_key text not null unique,
  payload jsonb not null,
  status text not null default 'queued' check (status in ('queued','running','completed','failed')),
  attempts integer not null default 0 check (attempts between 0 and 3),
  available_at timestamptz not null default now(),
  lease_token uuid,
  lease_expires_at timestamptz,
  last_error text,
  created_at timestamptz not null default now(),
  foreign key (scan_id, organization_id) references public.scans(id, organization_id) on delete cascade
);
create index scan_jobs_ready_idx on public.scan_jobs(available_at, created_at)
  where status = 'queued';
create index scan_jobs_expired_idx on public.scan_jobs(lease_expires_at)
  where status = 'running';
alter table public.scan_jobs enable row level security;
revoke all on public.scan_jobs from public, anon, authenticated;
grant all on public.scan_jobs to service_role;

create function public.enqueue_scan(p_delivery_id uuid, p_payload jsonb)
returns jsonb language plpgsql security invoker set search_path = '' as $$
declare
  repo public.repositories%rowtype;
  pr public.pull_requests%rowtype;
  sid uuid;
  jid uuid;
  dkey text;
  fresh boolean;
  inserted integer;
begin
  -- Never infer tenant ownership from a webhook-supplied org/user name.
  select * into repo from public.repositories
    where github_id = (p_payload->>'github_repository_id')::bigint
      and github_installation_id = (p_payload->>'installation_id')::bigint
      and lower(full_name) = lower(p_payload->>'repository_full_name')
    for update;
  if not found then
    raise exception 'Repository installation is not connected' using errcode = '42501';
  end if;
  insert into public.webhook_deliveries(delivery_id, event)
    values (p_delivery_id, 'pull_request') on conflict do nothing;
  get diagnostics inserted = row_count;
  if inserted = 0 then
    select scan_id into sid from public.webhook_deliveries where delivery_id = p_delivery_id;
    return jsonb_build_object('status','duplicate','scan_id',sid);
  end if;

  insert into public.pull_requests(organization_id, repository_id, number, title, author, head_sha)
    values (repo.organization_id, repo.id, (p_payload->>'pull_request_number')::integer,
      p_payload->>'title', p_payload->>'author', p_payload->>'head_sha')
    on conflict (repository_id, number) do nothing;
  select * into pr from public.pull_requests where repository_id = repo.id
    and number = (p_payload->>'pull_request_number')::integer for update;
  dkey := pr.id::text || ':' || (p_payload->>'base_sha') || ':' || (p_payload->>'commit_sha')
    || ':' || (p_payload->>'merged')
    || ':' || extract(epoch from (p_payload->>'event_updated_at')::timestamptz)::text;
  select scan_id, id into sid, jid from public.scan_jobs where dedup_key = dkey;
  if found then
    update public.webhook_deliveries set scan_id = sid where delivery_id = p_delivery_id;
    return jsonb_build_object('status','duplicate','scan_id',sid,'job_id',jid);
  end if;

  insert into public.scans(organization_id, pull_request_id, commit_sha)
    values (repo.organization_id, pr.id, p_payload->>'commit_sha') returning id into sid;
  insert into public.scan_jobs(organization_id, scan_id, dedup_key, payload)
    values (repo.organization_id, sid, dkey, p_payload) returning id into jid;
  update public.webhook_deliveries set scan_id = sid where delivery_id = p_delivery_id;
  fresh := (p_payload->>'event_updated_at')::timestamptz >= pr.source_updated_at
    and (not pr.source_merged or (p_payload->>'merged')::boolean);
  if fresh then
    update public.pull_requests set title = p_payload->>'title', author = p_payload->>'author',
      head_sha = p_payload->>'head_sha', source_updated_at = (p_payload->>'event_updated_at')::timestamptz,
      source_merged = (p_payload->>'merged')::boolean, latest_scan_id = sid,
      status = 'queued', risk_tags = '{}', updated_at = now() where id = pr.id;
    -- Prior findings no longer describe the current revision. They remain as history.
    update public.findings set resolved = true where scan_id in
      (select id from public.scans where pull_request_id = pr.id);
  end if;
  return jsonb_build_object('status','queued','scan_id',sid,'job_id',jid);
end;
$$;

create function public.claim_scan_job()
returns jsonb language plpgsql security invoker set search_path = '' as $$
declare
  job public.scan_jobs%rowtype;
  token uuid;
begin
  loop
    select * into job from public.scan_jobs
      where (status = 'queued' and available_at <= now())
         or (status = 'running' and lease_expires_at <= now())
      order by created_at for update skip locked limit 1;
    if not found then return null; end if;
    if job.attempts >= 3 then
      update public.scan_jobs set status = 'failed', last_error = 'lease_exhausted',
        lease_token = null, lease_expires_at = null where id = job.id;
      update public.scans set status = 'failed', error_code = 'lease_exhausted',
        completed_at = now() where id = job.scan_id;
      update public.pull_requests set status = 'failed', updated_at = now()
        where latest_scan_id = job.scan_id;
      continue;
    end if;
    token := gen_random_uuid();
    update public.scan_jobs set status = 'running', attempts = attempts + 1,
      lease_token = token, lease_expires_at = now() + interval '5 minutes'
      where id = job.id;
    update public.scans set status = 'running', error_code = null, completed_at = null
      where id = job.scan_id;
    update public.pull_requests set status = 'scanning', updated_at = now()
      where latest_scan_id = job.scan_id;
    return jsonb_build_object('id',job.id,'scan_id',job.scan_id,
      'lease_token',token,'payload',job.payload);
  end loop;
end;
$$;

create function public.finish_scan_job(
  p_job_id uuid, p_lease_token uuid, p_findings jsonb default '[]',
  p_engine_version text default null, p_error_code text default null, p_retryable boolean default false
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
    if p_error_code not in ('adapter_unavailable','timeout','upstream_unavailable','invalid_input','engine_error') then
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
  if p_engine_version is null or length(p_engine_version) not between 1 and 100
    or jsonb_typeof(p_findings) <> 'array' or jsonb_array_length(p_findings) > 1000 then
    raise exception 'Invalid scan result';
  end if;
  insert into public.findings(organization_id, scan_id, rule_id, file_path, line, severity, message, resolved)
    select job.organization_id, job.scan_id, f.rule_id, f.file_path, f.line, f.severity, f.message,
      not coalesce(is_current, false)
    from jsonb_to_recordset(p_findings) as f(rule_id text, file_path text, line integer, severity text, message text);
  update public.scan_jobs set status = 'completed', last_error = null,
    lease_token = null, lease_expires_at = null where id = job.id;
  update public.scans set status = 'completed', engine_version = p_engine_version,
    error_code = null, completed_at = now() where id = job.scan_id;
  if is_current then
    update public.pull_requests set status = case when jsonb_array_length(p_findings) = 0
      then 'passed' else 'action_required' end,
      risk_tags = array(select distinct f->>'rule_id' from jsonb_array_elements(p_findings) f),
      updated_at = now() where id = pr.id;
  end if;
  return true;
end;
$$;

revoke all on function public.enqueue_scan(uuid,jsonb) from public, anon, authenticated;
revoke all on function public.claim_scan_job() from public, anon, authenticated;
revoke all on function public.finish_scan_job(uuid,uuid,jsonb,text,text,boolean) from public, anon, authenticated;
grant execute on function public.enqueue_scan(uuid,jsonb) to service_role;
grant execute on function public.claim_scan_job() to service_role;
grant execute on function public.finish_scan_job(uuid,uuid,jsonb,text,text,boolean) to service_role;
commit;
