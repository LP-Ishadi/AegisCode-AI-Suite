-- Apply after 202611080001_scan_context_graph.sql before deploying the backend.
-- Evidence roles are short explanations, not secrets or raw source text.
begin;

alter table public.finding_evidence
  drop constraint if exists finding_evidence_role_check;

alter table public.finding_evidence
  add constraint finding_evidence_role_check
  check (length(role) between 1 and 120);

commit;
