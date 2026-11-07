-- Apply after 202611070001_current_image_findings.sql.
-- Path-only graph hints for reviews of an immutable PR snapshot.
begin;

create table public.scan_context_graph (
  scan_id uuid primary key,
  organization_id uuid not null,
  commit_sha text not null check (commit_sha ~ '^[0-9a-f]{40}$'),
  graph jsonb not null check (
    jsonb_typeof(graph) = 'object' and octet_length(graph::text) <= 32768
  ),
  created_at timestamptz not null default now(),
  foreign key (scan_id, organization_id)
    references public.scans(id, organization_id) on delete cascade
);
create index scan_context_graph_org_idx on public.scan_context_graph(organization_id);
alter table public.scan_context_graph enable row level security;
revoke all on public.scan_context_graph from public, anon, authenticated;
grant select on public.scan_context_graph to authenticated;
grant all on public.scan_context_graph to service_role;
create policy scan_context_graph_read on public.scan_context_graph
  for select to authenticated using (organization_id in (
    select organization_id from public.organization_members
    where user_id = (select auth.uid())
  ));

create function public.put_scan_context_graph(
  p_job_id uuid, p_graph jsonb
) returns boolean language plpgsql security invoker set search_path = '' as $$
declare
  target record;
begin
  select s.id, s.organization_id, s.commit_sha, s.status, j.status as job_status
    into target
    from public.scan_jobs j join public.scans s on s.id = j.scan_id
    where j.id = p_job_id;
  if not found or target.status <> 'completed' or target.job_status <> 'completed'
     or jsonb_typeof(p_graph) <> 'object'
     or p_graph->>'commit' is distinct from target.commit_sha
     or jsonb_typeof(p_graph->'candidates') <> 'array'
     or jsonb_array_length(p_graph->'candidates') > 32
     or octet_length(p_graph::text) > 32768
     or coalesce((p_graph->>'indexed_files')::integer, -1) not between 0 and 2000
     or coalesce((p_graph->>'skipped_files')::integer, -1) not between 0 and 2000
     or coalesce((p_graph->>'candidate_count')::integer, -1) < 0
     or jsonb_typeof(p_graph->'truncated') is distinct from 'boolean' then
    return false;
  end if;
  if exists (
    select 1 from jsonb_array_elements(p_graph->'candidates') item
    where jsonb_typeof(item) <> 'object'
       or item->>'relation' not in ('imports_change','imported_by_change')
       or item->>'path' is null or length(item->>'path') not between 1 and 1024
       or item->>'path' like '/%' or item->>'path' like '%..%'
       or position(E'\\\\' in item->>'path') > 0
       or position('?' in item->>'path') > 0
       or position('#' in item->>'path') > 0
       or position('%' in item->>'path') > 0
  ) then
    return false;
  end if;
  insert into public.scan_context_graph(scan_id, organization_id, commit_sha, graph)
    values(target.id, target.organization_id, target.commit_sha, p_graph)
    on conflict (scan_id) do nothing;
  return true;
end;
$$;
revoke all on function public.put_scan_context_graph(uuid,jsonb)
  from public, anon, authenticated;
grant execute on function public.put_scan_context_graph(uuid,jsonb) to service_role;

commit;
