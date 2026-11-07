-- Disposable Supabase-compatible test database only, after all migrations.
begin;
insert into auth.users(id) values ('10000000-0000-0000-0000-000000000004');
set local role service_role;
do $$
declare
  org_id uuid := gen_random_uuid();
  other_org_id uuid := gen_random_uuid();
  repo_id uuid := gen_random_uuid();
  other_repo_id uuid := gen_random_uuid();
  old_pr uuid := gen_random_uuid();
  new_pr uuid := gen_random_uuid();
  failed_pr uuid := gen_random_uuid();
  other_pr uuid := gen_random_uuid();
  old_scan uuid := gen_random_uuid();
  new_scan uuid := gen_random_uuid();
  failed_scan uuid := gen_random_uuid();
  other_scan uuid := gen_random_uuid();
  user_id uuid := '10000000-0000-0000-0000-000000000004';
  sha text := repeat('a', 40);
begin
  insert into public.organizations(id,name) values
    (org_id,'image-total-test'), (other_org_id,'image-total-other');
  insert into public.organization_members(organization_id,user_id,role)
    values (org_id,user_id,'owner');
  insert into public.repositories(id,organization_id,github_id,full_name) values
    (repo_id,org_id,900000004,'test/image-total'),
    (other_repo_id,other_org_id,900000005,'test/image-other');
  insert into public.pull_requests(id,organization_id,repository_id,number,title,author,head_sha,status)
    values
    (old_pr,org_id,repo_id,1,'Old','test',sha,'action_required'),
    (new_pr,org_id,repo_id,2,'New','test',sha,'action_required'),
    (failed_pr,org_id,repo_id,3,'Failed','test',sha,'failed'),
    (other_pr,other_org_id,other_repo_id,1,'Other','test',sha,'action_required');
  insert into public.scans(id,organization_id,pull_request_id,commit_sha,status,created_at,completed_at)
    values
    (old_scan,org_id,old_pr,sha,'completed',now() - interval '3 hours',now() - interval '2 hours'),
    (new_scan,org_id,new_pr,sha,'completed',now() - interval '2 hours',now() - interval '1 hour'),
    (failed_scan,org_id,failed_pr,sha,'failed',now() - interval '1 hour',now()),
    (other_scan,other_org_id,other_pr,sha,'completed',now() - interval '2 hours',now());
  update public.pull_requests set latest_scan_id = old_scan where id = old_pr;
  update public.pull_requests set latest_scan_id = new_scan where id = new_pr;
  update public.pull_requests set latest_scan_id = failed_scan where id = failed_pr;
  update public.pull_requests set latest_scan_id = other_scan where id = other_pr;
  insert into public.findings(organization_id,scan_id,rule_id,file_path,line,severity,message)
    values
    (org_id,old_scan,'trivy.image.CVE-1.pkg','Dockerfile',1,'high','old scan'),
    (org_id,new_scan,'trivy.image.CVE-1.pkg','Dockerfile',1,'high','new scan'),
    (other_org_id,other_scan,'trivy.image.CVE-2.pkg','Dockerfile',1,'high','other tenant');
  update public.findings set resolved = true where scan_id = new_scan;
  if (select count(*) from public.current_image_findings) <> 2 then
    raise exception 'Latest completed scan selection failed';
  end if;
end;
$$;

set local role authenticated;
set local request.jwt.claim.sub = '10000000-0000-0000-0000-000000000004';
do $$
begin
  if (select count(*) from public.current_image_findings) <> 1
    or (select message from public.current_image_findings limit 1) <> 'new scan'
    then raise exception 'Image view repeated history or leaked a tenant';
  end if;
  raise notice 'PASS: latest completed image findings and tenant isolation';
end;
$$;
rollback;
