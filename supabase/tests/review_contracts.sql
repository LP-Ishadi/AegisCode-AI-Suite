-- Disposable Supabase-compatible test database only, after all migrations.
-- Never run this against production records or a live queue.
begin;
set local role service_role;
do $$
declare
  org_id uuid := gen_random_uuid();
  repo_id uuid := gen_random_uuid();
  pr_id uuid := gen_random_uuid();
  v_scan_id uuid := gen_random_uuid();
  v_job_id uuid := gen_random_uuid();
  v_lease_id uuid := gen_random_uuid();
  v_finding_id uuid;
  sha text := repeat('a',40);
begin
  insert into public.organizations(id,name) values (org_id,'review-contract-test');
  insert into public.repositories(id,organization_id,github_id,full_name)
    values (repo_id,org_id,900000002,'test/contracts');
  insert into public.pull_requests(id,organization_id,repository_id,number,title,
    author,head_sha,status)
    values (pr_id,org_id,repo_id,1,'Contract test','test',sha,'scanning');
  insert into public.scans(id,organization_id,pull_request_id,commit_sha,status)
    values (v_scan_id,org_id,pr_id,sha,'running');
  update public.pull_requests set latest_scan_id = v_scan_id where id = pr_id;
  insert into public.scan_jobs(id,organization_id,scan_id,dedup_key,payload,
    status,attempts,lease_token,lease_expires_at)
    values (v_job_id,org_id,v_scan_id,'review-contract-test','{}','running',1,
      v_lease_id,now() + interval '5 minutes');

  begin
    perform public.finish_scan_job_v2(v_job_id,v_lease_id,
      '[{"rule_id":"test.rule","file_path":"app.py","line":1,
         "severity":"medium","message":"Check this","origin":"ai"}]',
      'contract-test',null,false,'scanner_only');
    raise exception 'Scanner-only run accepted AI finding';
  exception when raise_exception then
    if sqlerrm <> 'Invalid finding provenance' then raise; end if;
  end;

  if not public.finish_scan_job_v2(v_job_id,v_lease_id,
    '[{"rule_id":"test.rule","file_path":"app.py","line":1,
       "severity":"medium","message":"Check this","origin":"ai",
       "review_mode":"automated","evidence_status":"location_checked"}]',
    'contract-test',null,false,'automated') then
    raise exception 'V2 finish failed';
  end if;
  if public.finish_scan_job_v2(v_job_id,v_lease_id,'[]','contract-test',null,false,
    'automated') then raise exception 'V2 accepted duplicate completion'; end if;
  select f.id into v_finding_id from public.findings f where f.scan_id = v_scan_id
    and origin = 'ai' limit 1;
  if v_finding_id is null then raise exception 'AI origin not saved'; end if;
  if not public.put_finding_evidence(v_finding_id,'app.py',1,'changed_code','diff')
    or not public.put_finding_evidence(v_finding_id,'app.py',1,'changed_code','diff')
    then raise exception 'Evidence replay failed'; end if;
  if (select count(*) from public.finding_evidence e where e.finding_id = v_finding_id) <> 1
    then raise exception 'Evidence write was not idempotent'; end if;
  begin
    update public.finding_evidence set commit_sha = repeat('b',40)
      where finding_evidence.finding_id = v_finding_id;
    raise exception 'Wrong evidence commit accepted';
  exception when raise_exception then
    if sqlerrm <> 'Evidence commit does not match finding scan' then raise; end if;
  end;
  perform public.put_review_coverage(v_scan_id,'automated','partial',
    '{"reason":"bounded context"}');
  perform public.put_review_coverage(v_scan_id,'automated','partial',
    '{"reason":"bounded context"}');
  if (select count(*) from public.review_coverage c where c.scan_id = v_scan_id)
    <> 1 then raise exception 'Coverage write was not idempotent'; end if;
  if has_function_privilege('authenticated',
      'public.finish_scan_job_v2(uuid,uuid,jsonb,text,text,boolean,text)','execute')
    or has_function_privilege('authenticated',
      'public.put_finding_evidence(uuid,text,integer,text,text)','execute')
    or has_table_privilege('authenticated','public.review_coverage','insert')
    then raise exception 'Review mutation exposed to browser roles'; end if;
  raise notice 'PASS: provenance, commit pin, idempotent writes, grants';
end;
$$;
rollback;
