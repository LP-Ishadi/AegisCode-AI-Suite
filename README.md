# AegisCode AI Suite

A Supabase-first foundation for secure, AI-assisted pull request review. FastAPI
provides API security boundaries; React, TypeScript and Tailwind provide the dark
dashboard. Scanner and AI adapters are explicit stubs, not active scanning services.

## Structure

```text
backend/
  app/
    api/           # Identity, repository reads, verified GitHub hooks
    core/          # Settings, bearer auth and HMAC
    database/      # Stateless Supabase clients
    models/        # Validated scan/finding/review contracts
    services/      # Semgrep and AI stubs
    workers/       # Optional Celery bootstrap
    main.py
  tests/
  Dockerfile
  requirements.txt
  requirements-dev.txt
  requirements-scanner.txt
frontend/
  public/
  src/
    components/    # Navigation, metric cards, PR table, sign-in
    pages/         # Overview and analytics
    lib/           # Supabase, cloud queries and demo fixtures
    App.tsx
supabase/migrations/ # Tenant schema, RLS and pgvector
docs/architecture.md
.github/workflows/ci.yml
.env.example
```

## Dashboard quick start

Requires Node 22.12+ (Node 24 also works).

```sh
cd frontend
npm ci
npm run dev
```

Open `http://localhost:5173`. Without credentials, the dashboard shows labeled demo
data. Search, status filtering and the Analytics view work immediately.

## Backend quick start

Requires Python 3.11+; the container uses Python 3.12. From the repository root:

```sh
python3 -m venv backend/.venv
source backend/.venv/bin/activate
pip install -r backend/requirements-dev.txt
cp .env.example .env
# Replace placeholders with your cloud credentials.
cd backend
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

Health: `http://localhost:8000/health`. API docs: `http://localhost:8000/docs`.
Liveness works without provider credentials; protected routes require Supabase and
a user bearer token. Settings find the root `.env` regardless of working directory.
Container deployments inject secrets as environment variables.

## Hosted Supabase setup

1. Create a Supabase project and apply
   `supabase/migrations/202609300001_foundation.sql` using its SQL editor or migration
   pipeline. This creates the tenant schema, grants, RLS and pgvector extension.
2. Create an Auth user through your project's user-management flow. Provision its
   organization membership in the trusted SQL editor:

   ```sql
   with new_org as (
     insert into public.organizations (name) values ('Your organization') returning id
   )
   insert into public.organization_members (organization_id, user_id, role)
   select id, 'REPLACE_WITH_AUTH_USER_UUID'::uuid, 'owner' from new_org;
   ```

3. Fill the root `.env` with the project URL, public/anon key and server-only service
   key. Never expose privileged keys in the frontend or source control.
4. Copy `frontend/.env.example` to `frontend/.env.local`, supply the public project
   URL and public/anon key, set `VITE_DEMO_MODE=false`, restart Vite and sign in.
5. New projects show an empty dashboard. Trusted provisioning/workers populate
   repository, PR and finding records; browser clients have read-only tenant access.

Sessions live in memory and disappear on reload. No localStorage, sessionStorage,
offline database or persistent code checkout is used. All `VITE_` variables are
public browser configuration. The service key is server-only and bypasses RLS.

## API and integration status

### GitHub sign-in

Enable GitHub under Supabase Authentication → Sign In / Providers and enter your
GitHub OAuth App Client ID and Secret there (never in frontend variables). The GitHub
OAuth callback must be the Supabase provider's URL:
`https://<project-ref>.supabase.co/auth/v1/callback`.

For development, set the Supabase Site URL to `http://localhost:5173` and add
`http://localhost:5173/` to its allowed Redirect URLs. Open the frontend using that
same hostname and port. Add your exact HTTPS frontend URL for production. The sign-in
button requests a redirect to the current frontend origin's `/` path.

The browser uses Supabase's implicit OAuth flow with URL detection and no persistent
session storage. It waits for callback initialization, removes callback fragments,
and subscribes to login, token-refresh and logout events. Refreshing the page requires
sign-in again. GitHub login creates/authenticates the user; organization membership
still needs trusted provisioning. It does not grant repository scanning access.
See [Supabase's implicit-flow documentation](https://supabase.com/docs/guides/auth/sessions/implicit-flow).

| Endpoint | Behavior |
| --- | --- |
| `GET /health` | Liveness, not provider readiness |
| `GET /api/v1/auth/me` | Verify Supabase bearer token and return user ID |
| `GET /api/v1/repos?limit=25&offset=0` | Bounded, tenant-scoped repository reads |
| `POST /api/v1/webhooks/github` | Verify signature and delivery ID; answer signed pings |

Actionable PR webhooks return **501** until durable dispatch is implemented. Missing
webhook configuration returns 503. Set the GitHub secret to the same random value
as `GITHUB_WEBHOOK_SECRET`. Scanner/AI stubs raise unavailable errors; adding keys
does not enable these services. Managed Redis is optional until workers are implemented.

## Verification

```sh
cd backend
.venv/bin/ruff check .
.venv/bin/pytest
```

```sh
cd frontend
npm run build
npm test
```

CI runs the same checks without cloud secrets. Tests cover authentication gates,
webhook tampering and limits, redacted validation, CORS, stub behavior and metrics.
The frontend lockfile records dependency versions. Python requirements use bounded
versions; produce a target-platform lock and pin image digests for release.
Hosted migration, cross-tenant RLS and provider calls require cloud integration
validation before release.

See [architecture and PDF analysis](docs/architecture.md) for trust boundaries,
metric definitions, source references and the remaining implementation sequence.
