# Run locally with Docker Compose

Requires Docker Desktop (or Docker Engine with Compose v2) running. The database
remains hosted Supabase; there is no local database or Redis container.

## One-time setup

1. Apply both Supabase migrations and provision your repository's GitHub installation
   mapping as described in [scan-dispatch.md](scan-dispatch.md).
2. Keep your existing root `.env`. If starting from a fresh checkout, copy
   `.env.example` to `.env` and replace the placeholders. Required values:

   ```dotenv
   ENVIRONMENT=development
   CORS_ORIGINS=["http://localhost:5173"]
   SUPABASE_URL=https://YOUR_PROJECT.supabase.co
   SUPABASE_ANON_KEY=YOUR_PUBLIC_SUPABASE_KEY
   SUPABASE_SERVICE_KEY=YOUR_SERVER_ONLY_SUPABASE_KEY
   GITHUB_WEBHOOK_SECRET=YOUR_RANDOM_SHARED_WEBHOOK_SECRET
   NGROK_AUTHTOKEN=YOUR_NGROK_AGENT_TOKEN
   VITE_DEMO_MODE=false
   ```

   Add `NGROK_AUTHTOKEN` from your Ngrok account. An authtoken installed by the host's
   `ngrok config add-authtoken` command is not automatically available in the container.
   The agent token is different from the GitHub webhook secret and OAuth client secret.
3. Ensure Supabase's Site URL and allowed OAuth redirect URL include
   `http://localhost:5173/`. Keep GitHub OAuth's callback pointing to Supabase.
4. Stop existing host processes using ports 8000 and 5173 and any separate Ngrok agent
   that would conflict with your account's endpoint/session limits.

## Start everything

From the repository root:

```sh
docker compose up
```

Compose builds missing images and starts the API, worker, scanner, webhook gateway,
frontend, and tunnel. Backend liveness gates
startup of the worker, frontend and tunnel. It does not prove Supabase/worker readiness;
check the logs for configuration/migration errors. Initial image pulls/builds require
internet access. The foreground command displays logs together; no extra terminals
are required. To run in the background instead, use `docker compose up -d`.

| Service | Access / behavior |
| --- | --- |
| Frontend | http://localhost:5173 |
| Backend | http://localhost:8000/health and /docs in development |
| Scan worker | Fetches source and polls the durable Supabase queue; no published port |
| Scanner | Runs Semgrep, Trivy, and TruffleHog without tenant credentials; no published port |
| Webhook gateway | Accepts only the signed webhook route; no published port |
| Ngrok | Tunnels to `http://webhook-gateway:8000` on the Compose network |

Ngrok's startup logs include the public HTTPS URL (`url` on the started-tunnel log).
You can inspect them later with `docker compose logs ngrok`. Configure the GitHub App
webhook with that URL followed by:

```text
/api/v1/webhooks/github
```

Set the GitHub App's webhook secret to the same root `GITHUB_WEBHOOK_SECRET` and
subscribe to Pull request events. Install it on the mapped test repository. If Ngrok's
hostname changes, update the webhook URL. See [local-webhooks.md](local-webhooks.md).
The local Ngrok inspection UI is not published by this configuration.

## Environment and rebuild behavior

Compose reads root `.env` automatically for interpolation. Backend/worker receive
only the configured server variables. Frontend receives only public Supabase values
and demo mode; Ngrok receives only its agent token. The frontend's `.env.local` remains
useful for running Vite directly but is excluded from Docker and is not used by Compose.
No `.env` files are copied into either image. Never put a service-role key in
`SUPABASE_ANON_KEY` or a `VITE_` variable.

Source code is copied into images rather than bind-mounted. After changing code or
dependencies, rebuild with:

```sh
docker compose up --build
```

After editing root `.env`, use `docker compose up -d` to recreate affected containers;
`docker compose restart` alone does not load updated environment configuration.
Use `docker compose config --quiet` to validate without printing resolved secrets.
A plain `docker compose config` includes secret values: do not share its output.

Useful commands:

```sh
docker compose ps
docker compose logs --tail=100 scan-worker
docker compose down
```

Ctrl+C stops a foreground Compose session; `docker compose down` also removes its
containers/network. No hosted Supabase data is deleted. Jobs interrupted during
shutdown recover after their five-minute leases expire when a worker resumes.

**Enable scanning:** follow [Live scan pipeline setup](live-scan-pipeline.md) to apply
the adapter migration, configure the GitHub App private key/OpenAI credentials, and
explicitly opt in repositories. Unconfigured adapters fail with a diagnostic code.
This is a local development setup; Vite and the Ngrok tunnel are not production hosting.

Reference: [Official Ngrok Docker instructions](https://ngrok.com/download/docker).
