-- Disposable test database only, after all migrations; never run against a live queue.
begin;
set local role service_role;
do $$
declare
  oid uuid := gen_random_uuid(); other_oid uuid := gen_random_uuid();
  mapping jsonb; payload jsonb; queued jsonb; job jsonb; code text; sid uuid;
begin
  insert into public.organizations(id,name) values (oid,'adapter-test'),(other_oid,'other');
  mapping := public.connect_github_repository(oid,900000001,'test/example',101,true);
  if not exists(select 1 from public.repositories where id=(mapping->>'id')::uuid
    and ai_scan_enabled and organization_id=oid) then raise exception 'Mapping missing'; end if;
  begin
    perform public.connect_github_repository(other_oid,900000001,'test/example',101,true);
    raise exception 'Tenant transfer was accepted';
  exception when raise_exception then
    if sqlerrm <> 'Repository already belongs to another organization' then raise; end if;
  end;
  payload := jsonb_build_object('github_repository_id',900000001,'installation_id',101,
    'repository_full_name','test/renamed','pull_request_number',1,'title','Test','author','test',
    'head_sha',repeat('a',40),'base_sha',repeat('b',40),'commit_sha',repeat('a',40),
    'merged',false,'event_updated_at','2026-10-20T00:00:00Z');
  -- A rename does not invalidate immutable installation/repository authorization.
  queued := public.enqueue_scan(gen_random_uuid(),payload);
  sid := (queued->>'scan_id')::uuid;
  foreach code in array array['repository_not_connected','ai_not_authorized',
    'github_configuration','github_access_denied','source_incomplete','ai_configuration',
    'invalid_ai_output'] loop
    job := public.claim_scan_job();
    if not public.finish_scan_job((job->>'id')::uuid,(job->>'lease_token')::uuid,
      '[]',null,code,false) then raise exception 'Failure not saved'; end if;
    if not exists(select 1 from public.scans where id=sid and status='failed' and error_code=code)
      then raise exception 'Failure status not saved'; end if;
    if not public.retry_failed_scan(sid) then raise exception 'Retry failed'; end if;
    if not exists(select 1 from public.scan_jobs where scan_id=sid and status='queued' and attempts=0)
      then raise exception 'Retry not reset'; end if;
  end loop;
  job := public.claim_scan_job();
  if public.retry_failed_scan(sid) then raise exception 'Running scan retried'; end if;
  perform public.finish_scan_job((job->>'id')::uuid,(job->>'lease_token')::uuid,
    '[]',null,'ai_configuration',false);
  perform public.enqueue_scan(gen_random_uuid(),payload || '{"event_updated_at":"2026-10-20T01:00:00Z"}');
  if public.retry_failed_scan(sid) then raise exception 'Stale scan retried'; end if;
  if has_function_privilege('authenticated','public.retry_failed_scan(uuid)','execute')
    or has_function_privilege('anon',
      'public.connect_github_repository(uuid,bigint,text,bigint,boolean)','execute') then
    raise exception 'Administrative RPC exposed';
  end if;
  raise notice 'PASS: mapping ownership, rename, adapter errors, retry lifecycle, grants';
end;
$$;
rollback;
