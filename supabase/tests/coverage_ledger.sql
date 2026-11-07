-- Disposable Supabase-compatible test database only, after all migrations.
begin;
insert into auth.users(id) values ('10000000-0000-0000-0000-000000000003');
set local role service_role;
do $$
declare
  org_id uuid := gen_random_uuid();
  repo_id uuid := gen_random_uuid();
  pr_id uuid := gen_random_uuid();
  v_scan_id uuid := gen_random_uuid();
  job_id uuid := gen_random_uuid();
  lease_id uuid := gen_random_uuid();
  user_id uuid := '10000000-0000-0000-0000-000000000003';
  review_id uuid := gen_random_uuid();
  sha text := repeat('a',40);
  good jsonb;
begin
  insert into public.organizations(id,name) values (org_id,'coverage-ledger-test');
  insert into public.repositories(id,organization_id,github_id,full_name)
    values (repo_id,org_id,900000003,'test/coverage');
  insert into public.pull_requests(id,organization_id,repository_id,number,title,
    author,head_sha,status)
    values (pr_id,org_id,repo_id,1,'Coverage test','test',sha,'scanning');
  insert into public.scans(id,organization_id,pull_request_id,commit_sha,status)
    values (v_scan_id,org_id,pr_id,sha,'running');
  update public.pull_requests set latest_scan_id = v_scan_id where id = pr_id;
  insert into public.scan_jobs(id,organization_id,scan_id,dedup_key,payload,
    status,attempts,lease_token,lease_expires_at)
    values (job_id,org_id,v_scan_id,'coverage-ledger-test','{}','running',1,
      lease_id,now() + interval '5 minutes');
  good := jsonb_build_array(jsonb_build_object(
    'mode','scanner_only','status','complete','commit_sha',sha,
    'summary',jsonb_build_object('scope','bounded_selected_files',
      'scanner_stages',jsonb_build_object('semgrep','completed')),
    'files',jsonb_build_array(jsonb_build_object(
      'path','app.py','outcome','snapshot_acquired'))));

  begin
    perform public.finish_scan_job_v3(job_id,lease_id,'[]','test',null,false,
      'scanner_only',jsonb_build_array(jsonb_build_object(
      'mode','scanner_only','status','partial','commit_sha',sha,
      'summary','{}'::jsonb,'files','[]'::jsonb)));
    raise exception 'Partial empty scan accepted';
  exception when raise_exception then
    if sqlerrm <> 'Incomplete review cannot complete a clean scan' then raise; end if;
  end;
  if (select status from public.scans where id = v_scan_id) <> 'running' then
    raise exception 'Rejected completion changed scan'; end if;
  begin
    perform public.finish_scan_job_v3(job_id,lease_id,'[]','test',null,false,
      'scanner_only',jsonb_set(good,'{0,commit_sha}',to_jsonb(repeat('b',40))));
    raise exception 'Wrong commit accepted';
  exception when raise_exception then
    if sqlerrm <> 'Coverage commit mismatch' then raise; end if;
  end;
  if not public.finish_scan_job_v3(job_id,lease_id,'[]','test',null,false,
    'scanner_only',good) then raise exception 'Completion rejected'; end if;
  if (select status from public.pull_requests where id = pr_id) <> 'passed'
    or (select count(*) from public.review_coverage_files where scan_id = v_scan_id) <> 1
    then raise exception 'Atomic coverage completion failed'; end if;

  pr_id := gen_random_uuid();
  v_scan_id := gen_random_uuid();
  job_id := gen_random_uuid();
  lease_id := gen_random_uuid();
  insert into public.pull_requests(id,organization_id,repository_id,number,title,
    author,head_sha,status)
    values (pr_id,org_id,repo_id,2,'Failed coverage test','test',sha,'scanning');
  insert into public.scans(id,organization_id,pull_request_id,commit_sha,status)
    values (v_scan_id,org_id,pr_id,sha,'running');
  update public.pull_requests set latest_scan_id = v_scan_id where id = pr_id;
  insert into public.scan_jobs(id,organization_id,scan_id,dedup_key,payload,
    status,attempts,lease_token,lease_expires_at)
    values (job_id,org_id,v_scan_id,'coverage-ledger-failed','{}','running',1,
      lease_id,now() + interval '5 minutes');
  if not public.finish_scan_job_v3(job_id,lease_id,'[]',null,'source_incomplete',false,
    'scanner_only',good) then raise exception 'Failure completion rejected'; end if;
  if (select status from public.scans where id = v_scan_id) <> 'failed'
    or (select status from public.pull_requests where id = pr_id) <> 'failed'
    or (select status from public.review_coverage where scan_id = v_scan_id) <> 'failed'
    then raise exception 'Failed scan appeared clean'; end if;
  insert into public.manual_reviews(id,organization_id,scan_id,prompt,created_by)
    values (review_id,org_id,v_scan_id,'{}'::jsonb,user_id);
  if not public.advance_manual_review_v2(review_id,0,'final',
      '{"kind":"final","findings":[]}'::jsonb,'{}'::jsonb,
      '{"status":"completed"}'::jsonb,'[]'::jsonb,
      jsonb_build_object('mode','manual','status','complete',
      'commit_sha',sha,'summary','{}'::jsonb,'files','[]'::jsonb)) then
    raise exception 'Manual final rejected'; end if;
  if (select status from public.scans where id = v_scan_id) <> 'failed'
    or (select status from public.pull_requests where id = pr_id) <> 'failed'
    or (select status from public.review_coverage where scan_id = v_scan_id
      and review_mode = 'manual') <> 'complete'
    then raise exception 'Manual review made failed scan appear clean'; end if;

  pr_id := gen_random_uuid();
  v_scan_id := gen_random_uuid();
  job_id := gen_random_uuid();
  lease_id := gen_random_uuid();
  insert into public.pull_requests(id,organization_id,repository_id,number,title,
    author,head_sha,status)
    values (pr_id,org_id,repo_id,3,'AI evidence test','test',sha,'scanning');
  insert into public.scans(id,organization_id,pull_request_id,commit_sha,status)
    values (v_scan_id,org_id,pr_id,sha,'running');
  update public.pull_requests set latest_scan_id = v_scan_id where id = pr_id;
  insert into public.scan_jobs(id,organization_id,scan_id,dedup_key,payload,
    status,attempts,lease_token,lease_expires_at)
    values (job_id,org_id,v_scan_id,'coverage-ledger-ai','{}','running',1,
      lease_id,now() + interval '5 minutes');
  if not public.finish_scan_job_v3(job_id,lease_id,jsonb_build_array(
      jsonb_build_object('rule_id','test.ai','file_path','app.py','line',1,
      'severity','medium','message','Check the behavior','origin','ai',
      'review_mode','automated','evidence_status','location_checked',
      'evidence',jsonb_build_array(jsonb_build_object('commit_sha',sha,
      'file_path','app.py','line',1,'role','changed_code','source','diff')))),
    'test',null,false,'automated',good || jsonb_build_array(jsonb_build_object(
      'mode','automated','status','complete','commit_sha',sha,
      'summary','{}'::jsonb,'files',jsonb_build_array(jsonb_build_object(
      'path','app.py','outcome','diff_only'))))) then
    raise exception 'AI completion rejected'; end if;
  if (select count(*) from public.finding_evidence e join public.findings f
      on f.id = e.finding_id where f.scan_id = v_scan_id) <> 1
    then raise exception 'AI citation was not persisted'; end if;
  if has_function_privilege('authenticated',
    'public.finish_scan_job_v3(uuid,uuid,jsonb,text,text,boolean,text,jsonb)','execute')
    or has_table_privilege('authenticated','public.review_coverage_files','insert')
    then raise exception 'Coverage mutation exposed to browser roles'; end if;
  raise notice 'PASS: incomplete rejected; commit pinned; coverage persisted with scan';
end;
$$;
rollback;
