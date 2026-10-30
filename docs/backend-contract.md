# Qualified backend contract

The UI delegates to a separately installed operator source closure named `qualified-pilot-v1`. Infrastructure and secrets belong only in private installation settings. The public repository has no hostname, VM identifier, private address, model filename or credential for an installation.

## Fixed interface

The reviewed operator directory supplies:

- `SOURCE-MANIFEST.json`, containing a `files` mapping of relative paths to SHA-256 digests.
- `ui_entry.py`, the isolated Python bootstrap in `backend_extensions/`.
- `start_case.py`, accepting either `--manifest PATH --evidence-dir PATH` or `--resume CASE_ID`, plus `--output DIRECTORY --stop-file PATH`.
- A source-pinned collection bridge, immutable policy broker and qualified tool runtime.

The UI copies no secrets into the case manifest. It pins the complete operator source closure at attachment. Unpinned Python additions or changed files block subsequent launches. Keep the directory private and immutable while cases run. Source hashes do not resist another process running with the operator's own OS privileges.

New manifests contain a generated case ID, title, question, exact allowed hosts, seeds, request budget, local evidence descriptors, tool recipes, tool runtime digest and the fixed current-model IPC socket. The backend must validate these fields independently and freeze the source release per case. `workflow_mode` is either `tool_first` or `tools_only`; absent mode preserves the backend's legacy workflow.

The launcher must check the cooperative stop file before starting resources, between bounded startup operations and in the collection bridge loop. On stop or failure it must enter the same owned-resource cleanup path. Do not terminate the launcher from the web server. Stop latency includes the current tool/capture operation and backend read-retry interval.

Reports are atomically mirrored under the supplied output directory:

| File | Purpose |
|---|---|
| `osint-pilot-live-report.html` | Working report, treated as hostile HTML |
| `osint-pilot-live-report.md` | Preserved report text |
| `osint-pilot-status.json` | Checkpoint and supervisor state |
| `ui-session.json` | `{ "cleanup_complete": true }`, written only after all owned cleanup succeeds |

The terminal status is `supervisor.state = report_ready_unreviewed`. A successful UI state requires that status, a zero launcher exit and the cleanup receipt. A report by itself is never proof of successful execution or cleanup. Interrupted or uncertain runs show **needs attention** and preserve their data.

Record resource ownership before starting resources. The launcher must stop an isolated model container that it started, and preserve a model that was already running. `backend_extensions/model_lifecycle.py` provides this cleanup boundary: it attempts model cleanup even if collection/vault cleanup fails, then reads back the container state. Failed or empty inspections must prevent a success receipt. Add the helper to the pinned operator source closure when integrating it. A completed-case resume that starts no model must leave that model untouched.

Wrap creation, collection and broker import of the two temporary relay files in `backend_extensions/relay_cleanup.py`'s `temporary_relay` context manager. A collection or import failure must still remove both transfer files; a failed removal must surface as an error. Retain durable case inputs and reports under the case storage policy.

## Tool-first graph extension

Install `backend_extensions/tool_first.py` in the backend source closure and requalify the resulting release. In its graph:

1. Validate the workflow-mode enum before creating the immutable case policy.
2. For `tool_first` and `tools_only`, call `deterministic_plan(case)` instead of asking a model to choose tools. The plan is a persisted deterministic artifact, not a model receipt.
3. In `tool_first`, retain analysis, detractor, follow-up evidence checks and adjudication. Only already approved recipes may execute.
4. In `tools_only`, use collection → deterministic plan → initial recipes → review recipes → `tools_only_complete(case)`. Review recipes such as OCR do not imply a model detractor round.
5. Skip model startup in tools-only mode. Preserve the current model and its generation policy in model-review mode.
6. Resume each case against its original frozen graph release. A completed case must not repeat tool/model calls.

No catalog contents, model output or uploaded file may supply executable arguments. The model may request approved recipe IDs or already observed in-scope URLs; the host broker decides whether the request is allowed.

## Uploaded content and capture provenance

An uploaded HTML file with an operator-supplied URL has HTTP status `0` (unverified). Its bytes remain readable evidence. After validating the declared source and its hash, use `backend_extensions/source_content.py` to distinguish that local upload from a failed or partial network capture. Preserve the original status and provenance in model context and derived observations. Never substitute HTTP 200 to make an uploaded file pass a capture check.

Contact and technology parsers may report strings or hints in a readable upload. Account tools must keep live account existence inconclusive for an HTTP-unverified upload, even when account markers are present. Login walls and challenges remain inconclusive, including HTTP 200 responses. The helper recognizes common access-wall phrases; unknown pages still require source review. No marker or native tool verdict establishes a person's identity or control.

## Request-budget reporting

Use `backend_extensions/request_budget.py` with the broker-owned collection ledger for model inputs, live status and reports. Expose `maximum_unique_urls`, `used_unique_urls`, `remaining_unique_urls` and the ledger hash. Count unique requested URLs, including failed HTTP captures. Uploads, derived evidence, discovered links and tool jobs do not consume this particular budget. A failed Tor preflight does not add requests to the ledger. Missing or malformed accounting means unknown allowance, never a fresh budget.

Mount only the current case's ledger read-only into the network-isolated worker. Supply recorded rejected collection proposals to subsequent model rounds. These fields are planning information; the independent broker still authorizes every request. Reports must visibly override conflicting model budget prose with deterministic counts. Preserve original model artifacts and completed-case reports; a current broker status view may prepend corrected accounting without rerunning tools or inference.

Host disk encryption (including BitLocker on Windows) is optional deployment hardening. It is not a harness readiness gate and does not replace Whonix routing, scope enforcement, sandboxing or cleanup.

## Qualification checks

Before attaching an installation, verify:

- Whonix-only collection, remote DNS through Tor, positive Tor preflight and fail-closed behavior when the route is unavailable.
- Distinct case SOCKS isolation credentials and control-plane evidence of circuit separation. A different exit IP alone is insufficient.
- No direct networking from browser replay, PDF/OCR tools, specialist tools or model execution.
- Immutable host scope and request/job budgets, hostile redirects, URL parsing, receipt/runtime identity, input hashes and local path containment.
- Upload import, all enabled recipe types, live report updates, exact citations and conservative findings.
- Checkpoint resume without repeated completed jobs; cooperative cancellation and resource-state restoration; no success on cleanup failure.

The public tests validate the UI boundary. An existing qualified installation may reuse its underlying network/tool qualification only when those controls remain unchanged; changed launch or graph behavior needs focused regression and integration tests. Record limits explicitly: synthetic tests and a tools-only smoke run do not establish fresh model accuracy.
