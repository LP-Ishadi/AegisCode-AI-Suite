-- Apply once through Supabase migrations or the hosted SQL editor.
begin;
create schema if not exists extensions;
create extension if not exists vector with schema extensions;

create table public.organizations (
  id uuid primary key default gen_random_uuid(),
  name text not null check (length(name) between 1 and 120),
  created_at timestamptz not null default now()
);
create table public.organization_members (
  organization_id uuid not null references public.organizations(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  role text not null default 'member' check (role in ('owner','admin','member')),
  primary key (organization_id, user_id)
);
create index organization_members_user_idx on public.organization_members(user_id);

create table public.repositories (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations(id) on delete cascade,
  github_id bigint not null unique check (github_id > 0),
  full_name text not null check (full_name ~ '^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$'),
  default_branch text not null default 'main',
  created_at timestamptz not null default now(),
  unique (id, organization_id)
);
create index repositories_org_idx on public.repositories(organization_id);

create table public.pull_requests (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations(id) on delete cascade,
  repository_id uuid not null,
  number integer not null check (number > 0),
  title text not null check (length(title) between 1 and 1000),
  author text not null,
  head_sha text not null check (head_sha ~ '^[0-9a-f]{40}$'),
  status text not null default 'queued'
    check (status in ('queued','scanning','passed','action_required','failed')),
  risk_tags text[] not null default '{}',
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  foreign key (repository_id, organization_id)
    references public.repositories(id, organization_id) on delete cascade,
  unique (repository_id, number),
  unique (id, organization_id)
);
create index pull_requests_org_updated_idx on public.pull_requests(organization_id, updated_at desc);

create table public.scans (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations(id) on delete cascade,
  pull_request_id uuid not null,
  commit_sha text not null check (commit_sha ~ '^[0-9a-f]{40}$'),
  status text not null default 'queued'
    check (status in ('queued','running','completed','failed')),
  engine_version text,
  created_at timestamptz not null default now(),
  completed_at timestamptz,
  foreign key (pull_request_id, organization_id)
    references public.pull_requests(id, organization_id) on delete cascade,
  unique (id, organization_id)
);
create index scans_org_idx on public.scans(organization_id);
create index scans_pr_idx on public.scans(pull_request_id);

create table public.findings (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations(id) on delete cascade,
  scan_id uuid not null,
  rule_id text not null,
  file_path text not null,
  line integer not null check (line > 0),
  severity text not null check (severity in ('critical','high','medium','low','info')),
  message text not null,
  resolved boolean not null default false,
  created_at timestamptz not null default now(),
  foreign key (scan_id, organization_id)
    references public.scans(id, organization_id) on delete cascade
);
create index findings_org_idx on public.findings(organization_id);
create index findings_scan_idx on public.findings(scan_id);

-- Future outbox receipts: do not store raw GitHub payloads/source code here.
create table public.webhook_deliveries (
  delivery_id uuid primary key,
  event text not null,
  received_at timestamptz not null default now()
);

alter table public.organizations enable row level security;
alter table public.organization_members enable row level security;
alter table public.repositories enable row level security;
alter table public.pull_requests enable row level security;
alter table public.scans enable row level security;
alter table public.findings enable row level security;
alter table public.webhook_deliveries enable row level security;

-- Explicitly revoke Supabase default grants. Onboarding/mutations are trusted-service only.
revoke all on public.organizations, public.organization_members, public.repositories,
  public.pull_requests, public.scans, public.findings, public.webhook_deliveries
  from anon, authenticated;
grant select on public.organizations, public.organization_members, public.repositories,
  public.pull_requests, public.scans, public.findings to authenticated;
grant all on public.organizations, public.organization_members, public.repositories,
  public.pull_requests, public.scans, public.findings, public.webhook_deliveries to service_role;

-- Self-only membership reads avoid a recursive membership policy.
create policy membership_read on public.organization_members for select to authenticated
  using (user_id = (select auth.uid()));
create policy organization_read on public.organizations for select to authenticated
  using (id in (select organization_id from public.organization_members where user_id = (select auth.uid())));
create policy repository_read on public.repositories for select to authenticated
  using (organization_id in (select organization_id from public.organization_members where user_id = (select auth.uid())));
create policy pull_request_read on public.pull_requests for select to authenticated
  using (organization_id in (select organization_id from public.organization_members where user_id = (select auth.uid())));
create policy scan_read on public.scans for select to authenticated
  using (organization_id in (select organization_id from public.organization_members where user_id = (select auth.uid())));
create policy finding_read on public.findings for select to authenticated
  using (organization_id in (select organization_id from public.organization_members where user_id = (select auth.uid())));
-- webhook_deliveries has no public policy or grants: service role only.
-- pgvector is available; embedding dimensions/retention await a provider decision.
commit;
