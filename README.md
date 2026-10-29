# OSINT Harness

A local case desk for scoped, evidence-led research through a separately qualified Whonix backend. Create cases, add URLs and files, inspect tool plans, run or resume investigations, and watch the working report in a browser.

The UI uses Python's standard library and local HTML/CSS/JavaScript. It has no cloud account, telemetry, CDN or JavaScript build step. The current qualified model stays selected.

## What it does

- Forms for objectives, exact allowed hosts, HTTPS seeds, request budgets and job profiles.
- PDF, HTML, text and JSON uploads, hashed before execution; draft scope freezes when a case starts.
- Deterministic recipes for PDF text/OCR, offline browser replay, captured-page fingerprinting, scoped contacts, username markers and offline domain candidates.
- **Tools + model + detractor:** collection and extraction first, then analysis, adversarial review and adjudication. Planning does not consume a model round.
- **Tools only:** collection and extraction, with explicitly unreviewed observations and no model-generated conclusions.
- Checkpoints, live reports, resume and a cooperative stop that preserves owned VM state.

[Awesome OSINT](https://github.com/jivoi/awesome-osint) informs the reference library. Catalog entries never become executable commands, installations, MCP services, credentials or expanded collection scope. An upstream link describes a project, not a claim that its full capabilities are enabled here.

## Run locally

Install Python 3.11 or newer from its official distribution. On Windows, double-click **OSINT Harness.pyw**. The browser opens on a random loopback port. Running the launcher again opens the existing instance. The app remains running when its browser tab closes.

For development or other desktop platforms:

```console
python -m osint_harness.server
```

Then open **Installation → Attach a qualified backend** and select your reviewed operator directory and qualified runtime digest. There is no JSON editing in normal operation. Until a qualified backend is attached, execution fails closed.

**This repository is the UI, routing layer and backend extension contract. It is not a standalone Whonix or model provisioner.** You must supply a qualified backend implementing [the adapter contract](docs/backend-contract.md). Attaching a source manifest verifies file integrity; it does not prove the backend's isolation. Do not attach arbitrary Python directories.

## Use it

1. Choose **New case** and describe the question and competing explanations.
2. Enter exact hosts, starting HTTPS URLs and a page budget. Choose the job profile and review depth.
3. Save the draft and add files. A captured HTML file can include its original in-scope URL.
4. Review the selected tool recipes and their reasons, then choose **Start investigation**.
5. Read the working report as checkpoints arrive. **Stop & preserve** requests cleanup after the current bounded operation. **Resume case** continues the same frozen scope.

This adapter currently requires at least one seed URL, even for document jobs. It accepts at most 20 seeds, 40 allowed hosts, 40 collected URLs, 20 uploads of 20 MB each and 12 tool jobs. Browser replay starts at the first eligible page; it is not unrestricted live browsing. Tools-only deliberately omits model analysis and detractor/adjudication rounds.

## Privacy and boundaries

Case data, backend paths, infrastructure settings, source pins and report mirrors live in the operating system's private app-data directory, outside this checkout. **Local uploads and report mirrors are plaintext. Use an encrypted local disk.** The separately configured backend controls the encrypted case vault and collection network.

The server listens only on `127.0.0.1`. It checks Host and Origin, requires a local bootstrap session, uses an HttpOnly/SameSite cookie and CSRF tokens, and refuses cross-origin access. Reports are reduced to inert formatting inside a sandboxed iframe. Investigation URLs are never fetched by the UI server or displayed as clickable report links.

The backend must enforce Whonix/Tor collection, per-case isolation, request limits, encrypted storage, network-disabled model/tool execution, fixed recipes, provenance receipts and resource cleanup independently of the model. A model's promise to follow opsec is not an enforcement mechanism. See [the threat model](docs/security.md).

Do not publish your app-data directory, operator directory, real case reports, private logs or local screenshots containing infrastructure details. This repository contains generic source and synthetic tests only.

## Validation

```console
python -m unittest discover -s tests -v
```

The test suite covers routing, URL scope, integrity pins, concurrency, session protection, uploads and report sanitization. These tests do not qualify a new backend or Tor installation. [Backend qualification](docs/backend-contract.md#qualification) must include live negative network tests, receipt validation, stop/resume and cleanup.
