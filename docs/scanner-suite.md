# Repository scanner suite

The Compose `scan-worker` fetches the immutable snapshot. A separate `scanner`
container holds Semgrep, Trivy, and TruffleHog and receives a read-only view of
the disposable snapshot. The scanner container receives no Supabase, GitHub App,
or OpenAI keys. Neither container uses a Docker socket. SonarQube is planned later.

On a supported GitHub PR event, the existing durable worker obtains a short-lived
GitHub App installation token. It fetches the repository tree and individual Git
blobs at the queued commit into disposable `/scan-data` storage. It rejects symlinks,
submodules, malformed paths, truncated trees, and snapshots exceeding 2,000 tree
entries, 1 MB per file, or 40 MB total. These are deliberate completeness limits:
the job fails rather than showing a false clean result. Files are removed after
a normal scan; a hard crash can leave temporary files in the `scan-source` volume.
The worker and scanner use read-only root filesystems, non-root users, dropped
capabilities, process and memory limits, and bounded tmpfs storage. Trivy's vulnerability
database cache is a separate persistent volume; source files are never placed in it.

The tools run with fixed arguments and no shell:

- Semgrep scans source using the 14 versioned rules in `backend/rules/aegis.yaml`.
  Repository `.semgrepignore` files make the scan fail as incomplete, and the
  worker disables inline `nosemgrep` suppression and Git ignore targeting.
  These cover Python and JavaScript/TypeScript uses of dynamic code execution,
  unsafe Python deserialization, shell execution, disabled TLS checks, disabled
  JWT verification, debug configuration, and selected web-input-to-shell flows.
  Taint rules follow data within a file; they cannot prove an authorization
  policy is correct across the whole application. The displayed explanation
  comes from the bundled rule, not from scanned source text.
- Trivy scans repository dependencies from supported manifests/lockfiles.
- Trivy also scans up to eight distinct `FROM` images found in Dockerfiles, but
  only from Docker Hub, GHCR, Quay, or the Kubernetes registry. An unsupported
  registry makes the scan fail as incomplete. Those findings
  point to the relevant Dockerfile line. Mutable image tags are scanned as they
  resolve at scan time; digest-pinned references are more reproducible. This does
  not scan an application image built from the PR.
- TruffleHog scans the snapshot without online secret verification. Its findings
  are labeled **unverified**. Raw secret values are discarded and never persisted.

All three scanners must succeed before a scan can complete. Findings are normalized
into the existing Supabase `findings` table and appear in the dashboard. Rule IDs
begin with `semgrep.`, `trivy.`, or `trufflehog.`. A Trivy dependency finding uses
line 1 as a file-level location because a precise lockfile line is not supplied.
When an OpenAI key and explicit AI opt-in are present, the existing diff review
runs after the scanners; an AI failure fails the scan rather than marking it clean.
Manual AI review remains available after a completed or failed worker scan.

## Run

1. Start Docker Desktop or another Docker engine that supports Compose.
2. Ensure the existing Supabase migrations and GitHub App repository mapping are
   configured. GitHub App **Contents: read** and **Pull requests: read** permissions
   are required.
3. Allow the worker outbound access to GitHub and Supabase, and the scanner
   outbound access to vulnerability databases and the listed public registries.
   Private image registries are currently unsupported and fail the scan.
4. Apply `supabase/migrations/202611010001_review_reliability.sql` in the Supabase
   SQL editor, then run `docker compose up -d --build --force-recreate` from the project root.
5. Inspect `docker compose logs scan-worker` for scan completion or a generic
   adapter failure code. The worker does not log source code, credentials, or raw
   scanner output.

The first Trivy scan may need time to download its vulnerability database. The
worker keeps this database in the `trivy-cache` volume. No dependency package
installation or repository script execution occurs while scanning.

## Coverage and remaining work

The bundled Semgrep rules are a focused local set, not the full Semgrep registry.
Semgrep still has built-in targeting limits; a clean result covers only supported
files and rules that actually ran. Repository suppression files fail the scan.
Rule fixtures in `backend/tests/fixtures/semgrep/` contain safe and unsafe examples
used to check the bundled rules. TruffleHog does not detect every password or credential format.
Trivy checks known vulnerabilities in dependency manifests and `FROM` images; it
does not analyze a newly built application image unless an immutable image digest
is supplied through a future image artifact integration. SonarQube remains for a
later phase. A scanner pass is not a proof that a project has no vulnerabilities.
