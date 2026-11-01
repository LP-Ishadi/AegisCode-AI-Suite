-- Apply after durable_scan_dispatch. No existing repository opts into AI automatically.
begin;
alter table public.repositories add column ai_scan_enabled boolean not null default false;

-- Immutable IDs authorize dispatch; repository renames do not change ownership.
create or replace function public.enqueue_scan(p_delivery_id uuid, p_payload jsonb)
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
    for update;
  if not found then
    raise exception 'Repository installation is not connected' using errcode = 'PT403';
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

create or replace function public.finish_scan_job(
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
    if p_error_code not in ('adapter_unavailable','timeout','upstream_unavailable','invalid_input','engine_error',
      'repository_not_connected','ai_not_authorized','github_configuration',
      'github_access_denied','source_incomplete','ai_configuration','invalid_ai_output') then
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


-- Explicit administrative recovery after correcting credentials/configuration.
create function public.retry_failed_scan(p_scan_id uuid)
returns boolean language plpgsql security invoker set search_path = '' as $$
declare
  job public.scan_jobs%rowtype;
  pr public.pull_requests%rowtype;
begin
  select * into job from public.scan_jobs where scan_id = p_scan_id for update;
  if not found or job.status <> 'failed' then return false; end if;
  select p.* into pr from public.pull_requests p join public.scans s on s.pull_request_id = p.id
    where s.id = p_scan_id for update of p;
  if pr.latest_scan_id is distinct from p_scan_id then return false; end if;
  update public.scan_jobs set status = 'queued', attempts = 0, available_at = now(),
    last_error = null, lease_token = null, lease_expires_at = null where id = job.id;
  update public.scans set status = 'queued', error_code = null, completed_at = null
    where id = p_scan_id;
  update public.pull_requests set status = 'queued', risk_tags = '{}', updated_at = now()
    where id = pr.id;
  return true;
end;
$$;
revoke all on function public.retry_failed_scan(uuid) from public, anon, authenticated;
grant execute on function public.retry_failed_scan(uuid) to service_role;
-- Administrative mapping with atomic ownership protection (including concurrent creates).
create function public.connect_github_repository(
  p_organization_id uuid, p_github_id bigint, p_full_name text,
  p_installation_id bigint, p_enable_ai boolean default false
) returns jsonb language plpgsql security invoker set search_path = '' as $$
declare
  repo public.repositories%rowtype;
begin
  if p_github_id <= 0 or p_installation_id <= 0 or p_full_name is null
    or p_full_name !~ '^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$' then
    raise exception 'Invalid repository mapping';
  end if;
  insert into public.repositories(organization_id, github_id, full_name,
    github_installation_id, ai_scan_enabled)
    values (p_organization_id, p_github_id, p_full_name, p_installation_id, p_enable_ai)
    on conflict (github_id) do nothing;
  select * into repo from public.repositories where github_id = p_github_id for update;
  if repo.organization_id is distinct from p_organization_id then
    raise exception 'Repository already belongs to another organization';
  end if;
  update public.repositories set full_name = p_full_name,
    github_installation_id = p_installation_id, ai_scan_enabled = p_enable_ai
    where id = repo.id;
  return jsonb_build_object('id',repo.id,'ai_scan_enabled',p_enable_ai);
end;
$$;
revoke all on function public.connect_github_repository(uuid,bigint,text,bigint,boolean)
  from public, anon, authenticated;
grant execute on function public.connect_github_repository(uuid,bigint,text,bigint,boolean)
  to service_role;
commit;
