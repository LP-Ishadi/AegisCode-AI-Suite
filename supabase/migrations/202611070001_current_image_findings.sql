-- Apply after 202611060002_coverage_ledger.sql.
-- The dashboard reports the latest completed PR scan per repository. Keeping
-- every scan's findings as history must not multiply the workspace image total.
-- A later failed rescan leaves the previous completed result visible, even if
-- its rows were marked resolved when the new PR revision was queued.
begin;

create view public.current_image_findings
with (security_invoker = true) as
with latest_completed as (
  select distinct on (p.repository_id)
    p.repository_id, s.id as scan_id
  from public.pull_requests p
  join public.scans s on s.pull_request_id = p.id
    and s.organization_id = p.organization_id
  where s.status = 'completed'
  order by p.repository_id, s.created_at desc,
    s.completed_at desc nulls last, s.id desc
)
select f.id, f.scan_id, f.rule_id, f.file_path, f.line, f.severity,
  f.message, f.resolved, f.created_at
from latest_completed lc
join public.findings f on f.scan_id = lc.scan_id
where f.rule_id like 'trivy.image.%';

revoke all on public.current_image_findings from public, anon;
grant select on public.current_image_findings to authenticated;

commit;
