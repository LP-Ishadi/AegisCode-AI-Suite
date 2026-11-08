# AegisCode AI Suite

AegisCode reviews GitHub pull requests for security issues. A GitHub App sends
PR events to the backend; a durable worker fetches the exact commit and runs
Semgrep, Trivy, and TruffleHog in a separate scanner container. Results are
stored in Supabase and shown in a React dashboard. A separate manual review
window lets an operator copy a structured prompt into an AI chat and submit
its JSON reply. Automated AI review is optional and currently needs an API
key; the scanner workflow does not.

The project is an engineering case study. A finding is a lead for a developer
to investigate. “No findings” does not mean the code is secure. A failed or
incomplete scan must not be shown as clean.

## What works now

| Area | Current behavior |
| --- | --- |
| GitHub integration | Signed PR webhooks enqueue durable jobs; GitHub App installation access fetches a commit-pinned source snapshot. |
| Scanners | Isolated Semgrep, Trivy, and TruffleHog scan bounded source. Trivy also checks referenced Docker base images; it does not scan the final built image. |
| Results | Supabase stores scans and findings. New records identify scanner versus AI origin and review mode; historical records with uncertain provenance are marked unknown. The dashboard separates code/dependency findings from Docker image advisories. Its Docker total and detail list use each repository's last completed PR scan, so repeated PR scans do not multiply the workspace total. A failed newer scan leaves the previous result visible, which may be stale. Older scan findings remain in history. |
| Manual AI review | A separate signed-in window exchanges structured JSON with a chat model, supports bounded repository file tools, and stores its review steps. |
| Automated AI | An opt-in OpenAI context engine exists behind configuration and repository flags. It has mocked tests but has not been verified with a live API key. |
| Related code | The isolated scanner maps direct Python imports and relative JavaScript/TypeScript imports at the PR commit. The review prompt uses a bounded batch of changed files, then graph neighbors, then heuristic matches. Unsupported languages and unavailable graph hints use heuristic selection. |
| Failure handling | Scanner failures and incomplete source remain failed. Manual review cannot turn a failed scan into a passed scan. |

The [review architecture and implementation plan](docs/ai-review-architecture.md)
tracks the staged work. Stage 1 defines review origin, evidence references,
and coverage storage contracts. Stage 2 checks manual and context-based
automated AI citations against the PR commit and the files supplied to the
reviewer. Stage 3 persists per-file coverage outcomes and cited locations with
the review transition. Stage 4 implements bounded graph-guided context
selection. A checked citation confirms a location, not a vulnerability.
Coverage is stored but is not yet shown on the dashboard. Optional free or
local model providers, resumable AI jobs, dashboard changes, and a measured
benchmark remain planned. Stage 3 live coverage verification remains pending.

Apply `supabase/migrations/202611060002_coverage_ledger.sql` after
`202611060001_review_contracts.sql` and before rebuilding the current backend
and scan worker. This migration adds a per-file coverage ledger and versioned
completion functions. It does not rerun or relabel old scans. New scanner runs
record the acquired snapshot and scanner stage outcomes; AI reviews record
which bounded files were supplied, read through a tool, or omitted. A scan
cannot complete through the new worker path without a matching coverage record.
Apply `202611080001_scan_context_graph.sql` after
`202611070001_current_image_findings.sql`, then rebuild the scanner,
scan worker, and backend. New completed scans can save path-only graph hints;
old scans are not backfilled and use the existing selection fallback.

## How a PR moves through the system

```mermaid
flowchart LR
    GH[GitHub PR] --> WH[Verified webhook]
    WH --> JOB[Supabase scan job]
    JOB --> SRC[Exact PR commit]
    SRC --> SCAN[Isolated scanners]
    SRC --> GRAPH[Isolated one-hop import graph]
    GRAPH --> REVIEW
    SCAN --> DB[Supabase results]
    DB --> UI[Dashboard]
    SRC --> REVIEW[Optional manual or automated AI review]
    REVIEW --> DB
```

The scanner gets source code as data; the service does not run the PR's
application or tests. The manual reviewer can ask the backend for selected
files at the pinned commit. Scanner output and AI output should be judged by
their evidence and limitations, not by a single score.

## Repository map

| Path | Purpose |
| --- | --- |
| `backend/app/api/` | Signed webhook, authenticated repository, and manual review endpoints. |
| `backend/app/services/` | GitHub source acquisition, scanner dispatch, review prompts, validation, and scan pipeline. |
| `backend/app/workers/` | Durable Supabase scan worker. |
| `backend/app/scanner_api.py` | API inside the isolated scanner container. |
| `frontend/src/` | Dashboard, sign-in, analytics, and separate manual review page. |
| `supabase/migrations/` | Database schema, tenant access rules, job dispatch, scanner, and manual review migrations. |
| `docs/` | Setup guides, scanner scope, security architecture, and implementation plan. |
| `docker-compose.yml` | Local API, worker, scanner, frontend, webhook gateway, and ngrok tunnel. |

## Local quick start

You need Docker Desktop or Docker Engine with Compose, a Supabase project, and
a GitHub App installed on a repository you may test. Use a test repository
first. The scanner workflow needs **no AI API key**.

1. Copy `.env.example` to a root `.env` if you do not already have one.
   Fill its Supabase, GitHub App, webhook secret, and ngrok values. Keep
   `.env` private. Do not paste private keys or the full file into chat.
2. Apply the migrations in `supabase/migrations/` in filename order. Configure
   GitHub OAuth and create an organization membership as described in
   [the live scan guide](docs/live-scan-pipeline.md).
   For an existing installation, apply
   `202611060001_review_contracts.sql` and then
   `202611060002_coverage_ledger.sql` before rebuilding the backend and scan
   worker; the new worker calls `finish_scan_job_v3`. Apply
   `202611070001_current_image_findings.sql` before loading the updated
   dashboard; it scopes Docker advisory counts to the last completed scan
   per repository. Apply `202611080001_scan_context_graph.sql` before
   rebuilding the scanner and scan worker for graph-guided context. Apply
   `202611080002_evidence_role_limit.sql` before rebuilding the backend for
   manual review; it raises the evidence role limit to 120 characters.
3. From the **repository root**, start the services:

   ```sh
   docker compose up -d --build
   docker compose ps -a
   ```

4. Open `http://localhost:5173`. The API health route is
   `http://localhost:8000/health`.
5. Read `docker compose logs --tail=30 ngrok`, find the HTTPS tunnel URL,
   and put `<that-url>/api/v1/webhooks/github` in your GitHub App webhook
   settings. Configure the App's Pull request events and repository access.
6. Connect the repository with the backend CLI as shown in
   [the live scan guide](docs/live-scan-pipeline.md), then open or update a
   test PR. Watch `docker compose logs -f --tail=50 backend scan-worker`
   and refresh the dashboard.

The frontend at `localhost` and the ngrok webhook tunnel run while your
machine is on. This Compose setup is **not** an always-on public deployment.
Free hosted services have quotas and may change their terms. See
[Docker Compose setup](docs/docker-compose.md) for the full setup and rebuild
instructions and [webhook troubleshooting](docs/local-webhooks.md) for delivery
checks. SonarQube is not integrated.

## Manual review without an API key

After a scan record exists, open its **Manual review** link in the Recent pull
requests table. The review opens in a separate window and requires sign-in
because it can expose repository source. Copy the generated request into
your chosen AI chat, then paste only its required JSON response back into
the review window. The AI may request more repository files through the
bounded `list_files`, `list_special_files`, and `read_file` protocol.
Review the request before sharing private code with an external provider.

Read [Manual repository review](docs/manual-review.md) for the full workflow.
The manual review status and the scanner status are distinct: completing a
manual exchange does not repair a failed scanner run.

## Development checks

```sh
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt
python -m pytest
python -m ruff check .
```

```sh
cd frontend
npm ci
npm run build
npm test
```

Tests use mocks for cloud providers. A local passing test suite does not
prove that a live GitHub installation, Supabase migration, provider account,
or public deployment is configured correctly.
The disposable database contract test is
`supabase/tests/review_contracts.sql`; run it only against a throwaway
Supabase-compatible database after all migrations.

## Privacy and review limits

- Supabase service credentials and GitHub App private keys belong only in
  server configuration. Browser variables beginning with `VITE_` are public.
- The scanner container has no tenant secrets. The webhook tunnel points to
  the restricted webhook gateway, not the full API.
- Source selection, scanner rules, and AI context are bounded. A model can
  miss a bug or misinterpret real code even when its file citation is valid.
- Docker findings currently describe referenced base images. They do not
  establish that a vulnerable package is reachable in the running app.
- A reliable benchmark requires human-reviewed answers, including benign PRs
  and vulnerabilities the system misses. The planned benchmark will report
  scanner and AI findings separately.

See [architecture notes](docs/architecture.md), [scanner scope](docs/scanner-suite.md),
and [the review plan](docs/ai-review-architecture.md) for details.
