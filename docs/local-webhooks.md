# Test GitHub webhooks locally with Ngrok

Traffic flow: GitHub → HTTPS Ngrok URL → local FastAPI on port 8000 →
`POST /api/v1/webhooks/github`. No deployed backend, frontend tunnel, Supabase
schema changes, or CORS changes are required.

The existing handler verifies HMAC-SHA256 over the **original request bytes** before
processing events, uses a constant-time comparison, caps bodies at 1 MiB by default,
validates delivery UUIDs and PR payloads, and avoids echoing payloads in errors.
The public hostname is not part of the signature, so Ngrok needs no special bypass.

## 1. Set the shared webhook secret

From the project root, generate a random value locally:

```sh
openssl rand -hex 32
```

Copy that value into the existing root `.env`:

```dotenv
ENVIRONMENT=development
GITHUB_WEBHOOK_SECRET=PASTE_YOUR_GENERATED_VALUE
```

Use exactly the same value in GitHub's **Webhook secret** field. It is separate
from your GitHub OAuth client secret, Supabase keys, and Ngrok authtoken. Do not put
it in `frontend/.env.local` or commit it. Restart FastAPI after changing `.env`.
The helper refuses the template's placeholder secret.

## 2. Start FastAPI (terminal A)

From the repository root, with backend dependencies already installed:

```sh
cd backend
source .venv/bin/activate
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

Check `http://127.0.0.1:8000/health`: expect a JSON response with `status: ok`.
No Supabase login is required for webhook delivery; HMAC authenticates the payload.

## 3. Test signature verification before opening the tunnel

In another terminal, from the repository root:

```sh
backend/.venv/bin/python backend/scripts/send_test_webhook.py
backend/.venv/bin/python backend/scripts/send_test_webhook.py --tamper
backend/.venv/bin/python backend/scripts/send_test_webhook.py --event pull_request
```

Expect PASS with 200/pong, 401, and 501 respectively. The last test verifies that a
signed, valid PR reaches the current dispatch boundary; **it does not run a scan**.
The helper loads the root `.env` automatically (process environment takes priority),
sends only synthetic data, and never prints the secret, signature or response body.

## 4. Install and authenticate Ngrok (terminal B)

Create an Ngrok account and install the agent using the
[official setup instructions](https://ngrok.com/download/mac-os).
On macOS with Homebrew:

```sh
brew install ngrok
ngrok config add-authtoken YOUR_NGROK_AUTHTOKEN
ngrok http 8000
```

Replace the authtoken placeholder with the value from your Ngrok account. This is a
one-time agent setup, not a project environment variable. Keep the token private.

Copy the **HTTPS forwarding URL** printed by Ngrok, for example
`https://YOUR_DOMAIN.ngrok-free.app`. Use the actual hostname your agent prints.
Keep both terminal A and terminal B running while testing. If your public hostname
changes, update GitHub's webhook URL. Stop the tunnel with Ctrl+C when finished.
The tunnel exposes the backend port, including development docs; use a test repository
and avoid leaving it running unattended. Tunnel inspection can retain payloads.

## 5. Configure a GitHub App

Your existing **OAuth App** handles sign-in. Repository webhook subscriptions belong
to a **GitHub App**, or alternatively a repository webhook. Do not replace the
Supabase OAuth callback with this webhook URL.

1. Go to GitHub **Settings → Developer settings → GitHub Apps**, then edit your
   AegisCode App or create one with **New GitHub App**.
2. Under **Webhook**, enable **Active** and enter:

   ```text
   https://YOUR_DOMAIN.ngrok-free.app/api/v1/webhooks/github
   ```

3. Set **Webhook secret** to the exact `GITHUB_WEBHOOK_SECRET` from your root `.env`.
   Keep SSL verification enabled wherever that option is presented.
4. Under **Permissions & events → Repository permissions**, set **Pull requests**
   to **Read-only** for receiving/testing PR events. Metadata read access is automatic.
   No write permissions, private key, or installation token are needed just to receive
   and verify deliveries. Fetching code and posting reviews later require additional
   implementation and appropriately scoped permissions.
5. Under **Subscribe to events**, enable **Pull request**, then save the app settings.
6. Under **Install App**, install it on your account/organization and select a test
   repository. Approve any requested permission updates for an existing installation.
7. Open a PR, push another commit to its branch, or reopen it. These should produce
   `opened`, `synchronize`, or `reopened` events. A draft becoming ready triggers
   `ready_for_review`, which the handler also recognizes.

If you only want to test without registering a GitHub App, use the test repository's
**Settings → Webhooks → Add webhook** instead. Use the same URL/secret, select
`application/json`, enable SSL verification and Active, and select **Pull requests**.
Configure one method to avoid duplicate deliveries.

See [GitHub App registration](https://docs.github.com/en/apps/creating-github-apps/registering-a-github-app/registering-a-github-app).

## 6. Inspect and replay deliveries

In the GitHub App's **Advanced → Recent deliveries**, inspect the request headers,
event, response status and body. For repository webhooks, open that webhook's
**Recent deliveries**. Use **Redeliver** after fixing configuration. GitHub does not
[automatically redeliver failed webhooks](https://docs.github.com/en/webhooks/using-webhooks/handling-failed-webhook-deliveries).
Ngrok's local inspector is normally available at `http://127.0.0.1:4040`.

You can also test the public tunnel from the project root:

```sh
backend/.venv/bin/python backend/scripts/send_test_webhook.py --url https://YOUR_DOMAIN.ngrok-free.app/api/v1/webhooks/github
backend/.venv/bin/python backend/scripts/send_test_webhook.py --url https://YOUR_DOMAIN.ngrok-free.app/api/v1/webhooks/github --tamper
```

Never disable HMAC to make a tunnel test pass. GitHub supplies the
`X-Hub-Signature-256`, `X-GitHub-Event` and `X-GitHub-Delivery` headers. The helper
supplies them too; visiting the webhook endpoint in a browser sends GET and yields 405.

| Result | Meaning / action |
| --- | --- |
| 200, `pong` | Signed ping reached the receiver successfully |
| 200, `ignored` | Event or PR action intentionally not handled |
| 401 | Missing/bad signature; compare secrets and restart FastAPI |
| 400 | Missing event header or invalid delivery UUID |
| 413 | Body exceeds `MAX_WEBHOOK_BYTES` |
| 422 | Signed PR payload failed validation; use JSON content type |
| 501 | Valid actionable PR reached the unimplemented durable dispatch boundary |
| 503 | Backend webhook secret is not configured |
| 404 / redirect | Check the complete path; use it without a trailing slash |
| Ngrok error / 502 | Check agent, forwarding port and running backend |
| HTML instead of JSON | Tunnel/interstitial/access policy response, not API success |

**Current boundary:** ping verification is complete. Real actionable PR deliveries
will show as failed (501) in GitHub until atomic receipt/outbox persistence and workers
are implemented. This prevents falsely acknowledging dropped work. UUID validation
is not deduplication; replay protection must be added with the durable dispatch layer.
No source code is cloned, no findings are stored, and no PR comments are posted yet.

HMAC reference: [GitHub signature validation](https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries).
