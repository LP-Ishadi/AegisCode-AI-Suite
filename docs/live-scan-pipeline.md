# Enable GitHub source fetching and optional AI review

The worker fetches an immutable GitHub comparison using a short-lived, repository-scoped
GitHub App installation token, checks patch completeness, redacts common secrets, and
optionally asks a selected AI provider for structured findings. Findings and scan/PR statuses are committed together
using the existing leased queue. The signed-in dashboard refreshes every 15 seconds while
visible. No repository checkout or source file is persisted locally or in Supabase.

## 1. Diagnose the webhook response

Inspect **GitHub App → Advanced → Recent deliveries → Response** and backend logs:

| Response | Meaning and action |
| --- | --- |
| 401 `Invalid webhook signature` | Set the same exact `GITHUB_WEBHOOK_SECRET` in root `.env` and the GitHub **App webhook Secret** field. Recreate the backend container after changing it. |
| 403 `Repository installation is not connected` | HMAC passed. The repository ID and installation ID are not mapped together; use step 4. |
| 503 `Durable scan queue unavailable` | Check migrations, Supabase connectivity and the server service key. Database permission failures now return 503 instead of being mislabeled as mapping failures. |
| 422 | Check payload: this endpoint expects GitHub App PR deliveries including `installation.id`, not a repository-only webhook. |
| 202 | Job committed to the durable queue. |
| 200 | Signed ping, ignored event, or duplicate delivery. |

Do not disable signature checks to fix a 403. The implementation authenticates the raw
request bytes using SHA-256 HMAC and constant-time comparison. Ngrok does not change the
secret or require a different signature scheme. Use the public tunnel URL followed by
`/api/v1/webhooks/github`. If the response is HTML rather than the API's JSON, investigate
Ngrok/access policies before changing the application.

The GitHub webhook secret, OAuth client secret, GitHub App private key, and Ngrok auth
token are separate credentials. GitHub does not expose the saved webhook secret for
comparison; if uncertain, set the same new value on both sides. Never paste secrets into
logs/issues or a `VITE_*` variable. `docker compose restart` does not reload environment
variables; use `docker compose up -d --build --force-recreate`.

From the project root, the existing helper signs a ping using your root `.env` secret
and verifies that the backend accepts it (without creating a scan):

```sh
backend/.venv/bin/python backend/scripts/send_test_webhook.py --event ping
backend/.venv/bin/python backend/scripts/send_test_webhook.py --event ping --tamper
```

Expect 200, then 401. This verifies local configuration and HMAC; GitHub's own saved
secret must still match. Add `--url https://YOUR-TUNNEL/api/v1/webhooks/github` to test
through Ngrok.

## 2. Apply migrations

For a new database, apply all files in `supabase/migrations/` in filename order.
For an existing database, apply only migrations that have not already run.
Do not rerun the foundation script or drop tables. Stage 5 provider selection
requires no new migration. Existing repositories default to AI disabled.

## 3. Configure credentials in the root `.env`

In your **GitHub App** (not the OAuth app), grant repository **Contents: Read-only**
and **Pull requests: Read-only**, subscribe to **Pull request** events, install the app
on your selected repository, and approve updated permissions for existing installations.
Generate/download a private key from the App settings. Set:

```dotenv
GITHUB_APP_ID=your_app_id
GITHUB_APP_PRIVATE_KEY_B64=one_line_base64_of_downloaded_pem
AI_SCANNING_ENABLED=false
SCAN_MAX_FILES=80
SCAN_MAX_DIFF_CHARS=100000
```

On macOS, copy a one-line encoding to the clipboard without printing the key:

```sh
base64 < /absolute/path/to/downloaded-private-key.pem | tr -d '\n' | pbcopy
```

Paste it as `GITHUB_APP_PRIVATE_KEY_B64`. Keep the PEM outside the repository.
For automated review, set `AI_SCANNING_ENABLED=true`, select one provider, and
enable AI on the repository in step 4:

| Provider | Root `.env` settings | Requirement |
| --- | --- | --- |
| Groq | `AI_PROVIDER=groq`, `GROQ_API_KEY=...`, `GROQ_MODEL=...` | A Groq API key and a model that supports JSON object responses. Check current availability and quotas with Groq. |
| Ollama | `AI_PROVIDER=ollama`, `OLLAMA_MODEL=...`, `OLLAMA_BASE_URL=http://host.docker.internal:11434/v1` | A running local Ollama server and downloaded model with JSON response support; it must be reachable from the worker container. No cloud API key. |
| OpenAI | `AI_PROVIDER=openai`, `OPENAI_API_KEY=...`, `OPENAI_MODEL=...` | An API key and model supporting the Responses API and structured outputs. |

The same bounded prompts, file tools, and finding checks apply to each provider.
Source redaction is best-effort; cloud providers receive potentially proprietary
code. OpenAI requests set `store=False`, which does not promise zero provider
retention. The automated loop currently allows at most five model steps and is
not yet a resumable AI job. The separate worker runs Semgrep, Trivy, and
TruffleHog when started through Docker Compose; see [scanner suite](scanner-suite.md).

Rebuild and recreate the containers:

```sh
docker compose up -d --build --force-recreate
```

Only backend/worker receive private keys. The frontend continues to receive public
Supabase configuration only. No edits to `frontend/.env.local` are needed for scanning.

## 4. Connect the repository to the correct organization

Find your existing organization UUID in the trusted Supabase SQL Editor:

```sql
select id, name from public.organizations;
select id, organization_id, github_id, github_installation_id, full_name, ai_scan_enabled
from public.repositories;
```

If you have no organization yet, create one and explicitly add your Supabase Auth user
as a member using trusted administrator access. Do not infer tenant membership from a
GitHub login or webhook payload. Example (replace the user UUID from Authentication):

```sql
with organization as (
  insert into public.organizations(name) values ('My workspace') returning id
)
insert into public.organization_members(organization_id, user_id, role)
select id, 'YOUR_SUPABASE_AUTH_USER_UUID'::uuid, 'owner' from organization
returning organization_id;
```

Then run this **administrative** command, replacing the placeholders:

```sh
docker compose exec backend python -m app.cli.connect_repository \
  --organization-id YOUR_ORGANIZATION_UUID \
  --repository OWNER/REPOSITORY \
  --enable-ai
```

The command verifies the installation with your GitHub App, obtains the real immutable
repository ID, and maps it to your chosen organization. It refuses to move an existing
repository between organizations. `--enable-ai` explicitly opts this repository into
automated review with the selected provider; omitting it disables AI for that mapping. Only run this command as a
trusted administrator. Dashboard users must belong to that same organization to see data.
Repository renames no longer cause webhook 403 solely due to a stale stored name; run
this command again with the current name to update the displayed repository name.

## 5. Deliver a real PR and verify completion

Redeliver the failed GitHub delivery or open/update a real PR. Synthetic webhook test
fixtures contain fake SHAs and are useful for dispatch/HMAC checks only. Follow:

```sh
docker compose logs -f --tail=50 backend scan-worker
```

Expected sequence: webhook 202; PR `queued → scanning → passed` or `action_required`;
scan `queued → running → completed`; any findings appear in the dashboard vulnerability
logs. HTTP polling logs are suppressed; completion outcomes remain visible. In Supabase:

```sql
select id, status, error_code, engine_version, completed_at
from public.scans order by created_at desc limit 20;
select scan_id, status, attempts, last_error
from public.scan_jobs order by created_at desc limit 20;
```

Already accepted deliveries are deduplicated, even after a terminal scan failure.
After fixing configuration, explicitly requeue a **latest failed** scan:

```sql
select public.retry_failed_scan('FAILED_SCAN_UUID'::uuid);
```

This administrative RPC resets attempts and visible status together. It returns false
for a running/completed scan or an older revision. Never manually reset a running lease.

## Failure codes and limits

- `adapter_unavailable`: GitHub App credentials absent.
- `repository_not_connected`: installation mapping changed or GitHub ownership mismatch.
- `ai_not_authorized`: global AI setting or per-repository opt-in disabled.
- `github_configuration` / `github_access_denied`: invalid key, permissions, inaccessible
  commit/repo, or installation removed; verify GitHub App setup.
- `ai_configuration`: missing selected-provider key/model or unsupported model/request.
- `source_incomplete`: comparison exceeds bounds, commits are paginated, or any patch is
  binary, missing, truncated or unsupported. No partial review is reported as clean.
- `invalid_ai_output`: refusal, incomplete response or findings outside supplied paths/lines.
- `upstream_unavailable` / `timeout`: retryable network/provider error, up to three attempts.

This is bounded **changed-code and related-context review**, not full-repository SAST. Comparisons with more than
100 commits, more than the configured file limit, missing/rename-only patches, or over
100,000 diff characters fail explicitly. Fork comparisons work when GitHub can resolve
the pinned head SHA through the base repository; inaccessible SHAs fail explicitly.
The worker never follows webhook clone/patch URLs, HTTP redirects, or runs repository
code. Model findings require human review. A crash may repeat a provider call because
queue delivery is at least once. Provider quotas and an operational budget are still needed.

References: [GitHub App installation tokens](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-an-installation-access-token-for-a-github-app),
[GitHub commit comparison](https://docs.github.com/en/rest/commits/commits#compare-two-commits),
[OpenAI structured outputs](https://developers.openai.com/api/docs/guides/structured-outputs).

## Local verification

Run `backend/.venv/bin/pytest backend/tests` and `backend/.venv/bin/ruff check backend`.
Run `npm test` and `npm run build` in `frontend`. Provider tests mock the external APIs;
they do not transmit source or incur AI charges. Run both `supabase/tests/*.sql` files
with `psql -v ON_ERROR_STOP=1` after all migrations in a **disposable** test database.
The SQL tests claim jobs globally; never run them against your live queue.
