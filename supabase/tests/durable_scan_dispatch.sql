-- Run with psql ON_ERROR_STOP after both migrations in a disposable test database.
-- Everything is rolled back; no production credentials or external calls required.
begin;
set local role service_role;
do $$
declare
  oid uuid := gen_random_uuid(); rid uuid; did uuid := gen_random_uuid();
  payload jsonb; first_result jsonb; newer_result jsonb; job jsonb; newer_job jsonb;
  stale_token uuid; val text; total integer;
begin
  insert into public.organizations(id,name) values(oid,'dispatch-tests');
  insert into public.repositories(organization_id,github_id,github_installation_id,full_name)
    values(oid,9223372036854700000,101,'dispatch-test/example') returning id into rid;
  payload := jsonb_build_object('github_repository_id',9223372036854700000,
    'installation_id',101,'repository_full_name','dispatch-test/example',
    'pull_request_number',1,'title','Test PR','author','test',
    'head_sha',repeat('a',40),'base_sha',repeat('b',40),'commit_sha',repeat('a',40),
    'merged',false,'event_updated_at','2026-10-03T01:00:00Z');

  -- The trusted mapping is mandatory; unauthorized events leave no receipt.
  begin
    perform public.enqueue_scan(did,payload || '{"installation_id":999}'::jsonb);
    raise exception 'Unauthorized installation accepted';
  exception when insufficient_privilege then null;
  end;
  if exists(select 1 from public.webhook_deliveries where delivery_id=did) then
    raise exception 'Unauthorized event left a receipt';
  end if;
  first_result := public.enqueue_scan(did,payload);
  if first_result->>'status' <> 'queued' then raise exception 'Not queued'; end if;
  if public.enqueue_scan(did,payload)->>'status' <> 'duplicate' then
    raise exception 'Delivery replay not deduplicated';
  end if;
  if public.enqueue_scan(gen_random_uuid(),payload)->>'status' <> 'duplicate' then
    raise exception 'Same revision not deduplicated';
  end if;
  select count(*) into total from public.scan_jobs where organization_id=oid;
  if total <> 1 then raise exception 'Duplicate jobs exist'; end if;

  job := public.claim_scan_job();
  if job->>'id' <> first_result->>'job_id' then raise exception 'Wrong job claimed'; end if;
  if public.claim_scan_job() is not null then raise exception 'Live lease claimed twice'; end if;
  if public.finish_scan_job((job->>'id')::uuid,gen_random_uuid(),'[]','test-engine') then
    raise exception 'Stale token accepted';
  end if;

  -- A newer event must remain current even when the older worker finishes later.
  payload := payload || jsonb_build_object('head_sha',repeat('c',40),'commit_sha',repeat('c',40),
    'event_updated_at','2026-10-03T02:00:00Z');
  newer_result := public.enqueue_scan(gen_random_uuid(),payload);
  if not public.finish_scan_job((job->>'id')::uuid,(job->>'lease_token')::uuid,
    '[{"rule_id":"old","file_path":"a.py","line":1,"severity":"high","message":"old finding"}]',
    'test-engine') then raise exception 'Old job not finished'; end if;
  select status into val from public.pull_requests where repository_id=rid;
  if val <> 'queued' then raise exception 'Old result overwrote new PR status'; end if;
  if exists(select 1 from public.findings where scan_id=(job->>'scan_id')::uuid and not resolved) then
    raise exception 'Historical finding incorrectly active';
  end if;

  newer_job := public.claim_scan_job();
  stale_token := (newer_job->>'lease_token')::uuid;
  update public.scan_jobs set lease_expires_at=now()-interval '1 second'
    where id=(newer_job->>'id')::uuid;
  newer_job := public.claim_scan_job();
  if newer_job->>'lease_token'=stale_token::text then raise exception 'Lease not rotated'; end if;
  if public.finish_scan_job((newer_job->>'id')::uuid,stale_token,'[]','test-engine') then
    raise exception 'Expired lease completion accepted';
  end if;
  perform public.finish_scan_job((newer_job->>'id')::uuid,(newer_job->>'lease_token')::uuid,
    '[{"rule_id":"current","file_path":"api.py","line":12,"severity":"high","message":"finding"}]',
    'test-engine');
  select status into val from public.pull_requests where repository_id=rid;
  if val <> 'action_required' then raise exception 'Current result not applied'; end if;
  if public.finish_scan_job((newer_job->>'id')::uuid,(newer_job->>'lease_token')::uuid,'[]','test-engine') then
    raise exception 'Completed job finalized twice';
  end if;

  -- Out-of-order, previously unseen revision cannot become the latest scan.
  payload := payload || jsonb_build_object('head_sha',repeat('d',40),'commit_sha',repeat('d',40),
    'event_updated_at','2026-10-03T00:00:00Z');
  perform public.enqueue_scan(gen_random_uuid(),payload);
  select latest_scan_id::text into val from public.pull_requests where repository_id=rid;
  if val <> newer_result->>'scan_id' then raise exception 'Old event replaced latest scan'; end if;
  job := public.claim_scan_job();
  perform public.finish_scan_job((job->>'id')::uuid,(job->>'lease_token')::uuid,
    '[]',null,'upstream_unavailable',true);
  select status into val from public.scan_jobs where id=(job->>'id')::uuid;
  if val <> 'queued' then raise exception 'Transient failure not retried'; end if;
  update public.scan_jobs set attempts=3,available_at=now() where id=(job->>'id')::uuid;
  if public.claim_scan_job() is not null then raise exception 'Exhausted job reclaimed'; end if;
  select status into val from public.scan_jobs where id=(job->>'id')::uuid;
  if val <> 'failed' then raise exception 'Exhausted job not failed'; end if;

  -- A force-push back to an earlier commit is a new event, not an old duplicate.
  payload := payload || jsonb_build_object('head_sha',repeat('a',40),'commit_sha',repeat('a',40),
    'event_updated_at','2026-10-03T03:00:00Z');
  if public.enqueue_scan(gen_random_uuid(),payload)->>'status' <> 'queued' then
    raise exception 'Return to previous commit was not queued';
  end if;
  job := public.claim_scan_job();
  perform public.finish_scan_job((job->>'id')::uuid,(job->>'lease_token')::uuid,'[]','test-engine');
  select status into val from public.pull_requests where repository_id=rid;
  if val <> 'passed' then raise exception 'Successful clean result not applied'; end if;

  -- A later failure in the RPC must roll back its receipt and PR mutations.
  did := gen_random_uuid();
  begin
    perform public.enqueue_scan(did,payload || '{"pull_request_number":2,"commit_sha":"bad-sha"}'::jsonb);
    raise exception 'Invalid scan commit accepted';
  exception when check_violation then null;
  end;
  if exists(select 1 from public.webhook_deliveries where delivery_id=did)
    or exists(select 1 from public.pull_requests where repository_id=rid and number=2) then
    raise exception 'Failed enqueue left partial state';
  end if;

  if has_function_privilege('authenticated','public.enqueue_scan(uuid,jsonb)','execute')
    or has_function_privilege('anon','public.claim_scan_job()','execute') then
    raise exception 'Queue RPC exposed to untrusted role';
  end if;
  if has_table_privilege('authenticated','public.scan_jobs','select') then
    raise exception 'Queue table exposed';
  end if;
  raise notice 'PASS: atomic enqueue, mapping, dedup, leases, results, stale events, retries, grants';
end;
$$;
rollback;
