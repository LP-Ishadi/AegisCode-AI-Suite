# Human-mediated repository review

This feature adds a manual LLM exchange to an existing PR scan. It uses the same
GitHub App installation and exact commit as the queued scan. It does not require an
OpenAI API key. Apply `202610230001_manual_reviews.sql` after the existing three
migrations, then recreate the API and frontend containers. Set `VITE_API_URL` to the
browser-reachable API origin (for local Compose, `http://localhost:8000`). The API's
`CORS_ORIGINS` must include the frontend origin.

The repository must already be connected, `AI_SCANNING_ENABLED=true`, and its
`ai_scan_enabled` flag must be true. An organization owner or admin opens a completed
or failed PR scan using **Manual review** in the dashboard. The screen displays a
structured prompt containing the redacted PR diff, security rules, allowed tools,
and the JSON output schema. Paste the request into one AI conversation. Paste its
JSON response back into the screen. The backend validates the reply and either
fetches a tool result or commits final findings. Repeat until the final response.

Allowed tools are `list_files`, `list_special_files`, and `read_file`. All operate
against the immutable PR commit. File reads are limited to 16,000 characters;
the tree is limited to 2,000 entries; a review is limited to 20 steps. The model
cannot write to GitHub or Supabase. Final findings must refer to a real file and
line at that commit. An empty final finding set means only that this review found
no supported issue; it does not certify the repository as secure.

The database stores each response, tool summary, and the next redacted prompt so
the exchange can resume after a browser refresh. A prompt containing a read file
also contains its redacted source text. Redaction is best effort, so inspect a
prompt before sharing it with any external AI service. Access to this history is
restricted to organization owners and admins by row-level security. Set an
appropriate retention policy before using this on sensitive repositories.

## Scanner integration status

The [scanner suite](scanner-suite.md) runs in the separate PR worker and writes
findings to the same scan records. This manual review can follow either a completed
or failed scanner run. SonarQube remains a later integration.
