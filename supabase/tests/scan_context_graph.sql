-- Run only in a disposable Supabase-compatible database after all migrations.
begin;
set local role service_role;
do $$
declare
  org_id uuid := gen_random_uuid();
  repo_id uuid := gen_random_uuid();
  pr_id uuid := gen_random_uuid();
  sid uuid := gen_random_uuid();
  jid uuid := gen_random_uuid();
  sha text := repeat('a', 40);
  graph jsonb := jsonb_build_object(
    'commit', repeat('a', 40),
    'candidates', jsonb_build_array(jsonb_build_object(
      'path', 'app/auth.py', 'relation', 'imports_change')),
    'indexed_files', 2, 'skipped_files', 0, 'candidate_count', 1,
    'truncated', false);
begin
  insert into public.organizations(id,name) values (org_id,'context-graph-test');
  insert into public.repositories(id,organization_id,github_id,full_name)
    values (repo_id,org_id,900000004,'test/graph');
  insert into public.pull_requests(id,organization_id,repository_id,number,
    title,author,head_sha,status)
    values (pr_id,org_id,repo_id,1,'Graph test','test',sha,'scanning');
  insert into public.scans(id,organization_id,pull_request_id,commit_sha,status)
    values (sid,org_id,pr_id,sha,'completed');
  insert into public.scan_jobs(id,organization_id,scan_id,dedup_key,payload,
    status,attempts)
    values (jid,org_id,sid,'context-graph-test','{}','completed',1);
  if public.put_scan_context_graph(jid,
      jsonb_set(graph,'{commit}',to_jsonb(repeat('b',40)))) then
    raise exception 'Wrong-commit graph accepted';
  end if;
  if not public.put_scan_context_graph(jid,graph) then
    raise exception 'Valid graph rejected';
  end if;
  if (select commit_sha from public.scan_context_graph where scan_id = sid) <> sha
    then raise exception 'Graph not pinned to scan commit'; end if;
  if has_function_privilege('authenticated',
      'public.put_scan_context_graph(uuid,jsonb)','execute')
    or has_table_privilege('authenticated','public.scan_context_graph','insert')
    then raise exception 'Browser role can mutate graph'; end if;
  raise notice 'PASS: graph is commit pinned and service-only';
end;
$$;
rollback;
