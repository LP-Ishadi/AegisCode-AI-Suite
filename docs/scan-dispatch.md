# Durable scan dispatch

## Apply and run

1. Apply `supabase/migrations/202610030001_durable_scan_dispatch.sql` once through
   the Supabase SQL editor, **after** the foundation migration. Do not rerun the
   foundation or drop existing tables. The new migration adds the queue, RPCs,
   installation mapping, and scan error/current-revision metadata.
2. Provision the repository through a trusted administrator. Associate it with its
   actual immutable GitHub repository ID, full name, tenant organization UUID and
   GitHub App installation ID. These IDs come from your verified installation setup,
   not browser input. Example in the trusted SQL editor:

   ```sql
   insert into public.repositories
     (organization_id, github_id, github_installation_id, full_name, default_branch)
   values
     ('YOUR_ORGANIZATION_UUID'::uuid, 123456, 789012, 'OWNER/REPOSITORY', 'main');
   ```

   For an existing repository, update its `github_installation_id` after verifying
   ownership instead of inserting it again. Renamed/transferred repositories need
   their trusted mapping updated. Unknown or mismatched installations return 403.
   Repository-only webhooks without `installation.id` cannot enqueue (422).
3. Keep `SUPABASE_URL`, `SUPABASE_SERVICE_KEY`, and `GITHUB_WEBHOOK_SECRET` configured
   in the root `.env`. The verified webhook uses service-only RPCs; it never accepts
   a tenant ID from the caller. Frontend public keys cannot enqueue/claim/finish jobs.
4. Start FastAPI and Ngrok as described in [local-webhooks.md](local-webhooks.md).
   Subscribe your GitHub App to Pull request events and install it on the mapped repo.
5. Run a separate worker process (from the repository root):

   ```sh
   cd backend
   source .venv/bin/activate
   python -m app.workers.scan_worker
   ```

   For one claim attempt, use `python -m app.workers.scan_worker --once`.
   For container deployment, use the backend image with command
   `python -m app.workers.scan_worker`; supply the same server environment secrets.
   The API and worker can restart independently. No Redis broker is needed for this
   implementation; the older Celery factory is optional scaffolding, not the active queue.

## Webhook behavior

- `opened`, `synchronize`, `reopened`, `ready_for_review`: queue the PR head commit.
- `closed` with `pull_request.merged = true`: queue the merge commit and preserve
  both head/base SHAs. GitHub does not emit a `merged` action.
- Signed pings return 200; unsupported events and unmerged closes return ignored/200.
- Accepted jobs return 202 with `job_id` and `scan_id`; duplicates return 200.
- A database outage or missing migration returns 503, never a false acknowledgment.
  GitHub failed deliveries must be redelivered manually or by a reconciliation job.

Delivery UUID and revision deduplication are inside the same transaction as PR/scan
creation. A job is unique per PR, base SHA, scanned SHA, merge flag and GitHub update timestamp. The same
event revision under a new delivery UUID is still a duplicate. A later event can scan
a previously seen commit again (for example a force-push back to that commit). Failed jobs are not silently
restarted by redelivery; transient failures retry automatically, and terminal failures
require an explicit operational retry after fixing adapters. A newer commit creates
another job. Draft opened events are queued too.

The payload includes repository and fork IDs/names, branch refs, PR number/title/author,
event timestamp, SHAs, merge/draft flags and canonical GitHub clone/patch/diff/compare
URLs. URLs supplied by the webhook are not trusted or fetched. PR patch URLs can move;
an acquisition adapter must fetch the pinned comparison rather than the latest PR diff.

## Worker lifecycle and adapter boundary

`queued → running → completed` or `failed`. Completion writes normalized findings and
updates the current PR to `passed` or `action_required` in one transaction. Exceptions
store fixed error codes, not source, credentials or raw provider messages.

Workers claim using `FOR UPDATE SKIP LOCKED`, lease jobs for five minutes, and use a
fresh token per claim. Work has a 120-second timeout. An expired lease can be reclaimed;
a late/stale worker cannot publish results. Completion/failure and findings are atomic.
Delivery is **at least once**: a crash can repeat source/provider work, so future external
side effects must be idempotent. Transient network/timeout errors retry with backoff up
to three claims; exhausted leases/jobs become failed when the poller next sees them.
Database failure while saving completion leaves the lease to expire and recover.

Only the latest scan may change the displayed PR status. Previously unseen older events
can be scanned for history without replacing the latest state. Prior findings are marked
resolved when superseded; here that flag means no longer active for the current revision,
not independently verified remediation. Failed/queued scans must never imply a clean repo.

`ScanPipeline` injects two asynchronous contracts:

- `SourceProvider.fetch(ScanMetadata) → SourceBundle`: bounded in-memory diff and file
  paths with matching immutable commit SHA. The default `GitHubSourceProvider` is a stub.
- `ScanEngine.analyze(ScanMetadata, SourceBundle) → ScanResult`: validated findings plus
  engine version. The default `AIScanEngine` is a stub ready for OpenAI/Claude integration.

**The queue and worker are implemented; code acquisition and real AI analysis are not.**
Running the default worker marks jobs `failed` with `adapter_unavailable`. It never emits
fake clean results. Leave the worker stopped if you want jobs to remain queued until an
adapter is implemented. Tests inject deterministic adapters to verify the success path.

Before replacing stubs, add GitHub installation-token minting and ownership checks,
response/time/expansion limits, immutable fork comparisons, secret redaction, tenant
AI opt-in, budgets and validated model output. No code checkout, subprocess, source
persistence, AI calls or GitHub comments happen with these stubs.

## Verification

```sh
cd backend
.venv/bin/ruff check .
.venv/bin/pytest
```

`supabase/tests/durable_scan_dispatch.sql` runs transactional queue checks after both
migrations in an otherwise empty **disposable test database**, then rolls back fixtures.
Do not run it against a live queue: it invokes the global claim function. Use `psql -v
ON_ERROR_STOP=1 -f supabase/tests/durable_scan_dispatch.sql` with your test database connection.
It covers duplicate deliveries/revisions, wrong installations, stale results, expired
leases, retry exhaustion and public access restrictions.

The synthetic webhook helper accepts `--repository-id`, `--installation-id`, and
`--repository OWNER/NAME` for a trusted **test** mapping. A synthetic PR has fake SHAs;
use actual GitHub deliveries for eventual code fetching.

References: [GitHub PR events](https://docs.github.com/en/webhooks/webhook-events-and-payloads#pull_request),
[PostgreSQL queue locking](https://www.postgresql.org/docs/current/sql-select.html).
