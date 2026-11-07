# Human-mediated repository review

This feature adds a manual LLM exchange to an existing PR scan. It uses the same
GitHub App installation and exact commit as the queued scan. It does not require an
OpenAI API key. Apply all migrations in filename order, including
`202611060001_review_contracts.sql` and
`202611060002_coverage_ledger.sql`, before using the current backend. Recreate
the API and frontend containers. Set `VITE_API_URL` to the
browser-reachable API origin (for local Compose, `http://localhost:8000`). The API's
`CORS_ORIGINS` must include the frontend origin.

The repository must already be connected, `AI_SCANNING_ENABLED=true`, and its
`ai_scan_enabled` flag must be true. An organization owner or admin opens a completed
or failed PR scan using **Manual review** in the dashboard's PR table. The link opens
`/manual-review?scan=<scan-id>` in a separate browser tab. The dashboard remains open
and shows only the scan results. Because authentication tokens live only in each tab's
memory, sign in with GitHub again in the review tab if prompted. The sign-in uses
the existing root callback URL and stores only the scan ID in that tab until the
redirect completes; no additional Supabase redirect URL is needed.
The review screen displays a
structured prompt containing the redacted PR diff, security rules, allowed tools,
the JSON output schema, and a bounded summary of scanner findings. The summary
keeps counts for every scanner finding but includes only a severity-ranked sample;
the omitted count shows how many findings were not sent to the AI. The first prompt
also includes bounded full text
for changed files and likely related unchanged files at the exact PR commit.
Selection uses imports, matching file names, and directory proximity. This is a
context hint, not a guarantee that every relevant file was selected. The prompt's
`auto_context.included` entries show what was supplied; `auto_context.omitted`
shows files skipped by file or size limits. `coverage_pending` lists changed files
the model must request with `read_file` before submitting an empty final answer.
Every manual review must also make at least one successful `read_file` tool call
before any final answer, even when all changed files were supplied automatically.
The backend rejects an early final answer with HTTP 422 and keeps the review active.
If a changed file cannot be read within the tool limit, the manual review cannot
finish clean. Paste the request into one AI conversation. Paste its
JSON response back into the screen. The backend validates the reply and either
fetches a tool result or commits final findings. Repeat until the final response.
Return to the dashboard tab and refresh to see the saved final findings.
If the worker scan failed or was incomplete, the manual findings are saved but the
scan and PR remain **failed**. An empty manual answer cannot make a failed scan pass.
Fix the scanner issue and run a new successful scan before treating the PR as passed.

Allowed tools are `list_files`, `list_special_files`, and `read_file`. All operate
against the immutable PR commit. File reads are limited to 16,000 characters;
the tree is limited to 2,000 entries; a review is limited to 20 steps. The model
cannot write to GitHub or Supabase. Final findings must include `evidence`
references. Each names its commit, repository path, 1-based line, role, and
source (`diff`, `auto_context`, or `read_file`). The backend checks that the AI
was shown that location, then re-reads the exact commit to confirm the line.
The final response stores those locations and a coverage record with the
review result. Tool steps save pending coverage so a browser refresh can show
the same review state. These records describe only the bounded files selected
or requested for this review; they do not certify the full repository.
For a claim that depends on another file, set `cross_file_required` to `true`
and cite that other file too. One-file issues can use `false`; unrelated
citations should not be invented. A checked location does not prove the
vulnerability. An empty final finding set means only that this review found
no supported issue; it does not certify the repository as secure.

For example, one finding can use this shape. Replace the commit, path, line,
rule, and message with facts from the current review request:

```json
{
  "kind": "final",
  "findings": [{
    "rule_id": "example.authorization",
    "file_path": "app/route.py",
    "line": 12,
    "severity": "high",
    "message": "Explain the concrete authorization gap.",
    "evidence": [{
      "commit_sha": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "file_path": "app/route.py",
      "line": 12,
      "role": "changed_code",
      "source": "diff"
    }],
    "cross_file_required": false
  }]
}
```

Automatic context includes at most eight files total, of which at most four are
related unchanged files, with a total of 64,000 characters. Individual reads
still have the 16,000-character limit. Existing manual reviews keep their stored
prompts; start a new review on a new scan to use citation validation.

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
The scanner pipeline's automated OpenAI path now uses the same bounded file tools
and review gate when an API key and repository authorization are configured. See
[automated review architecture](ai-review-architecture.md) for current limits and
the remaining accuracy work.
