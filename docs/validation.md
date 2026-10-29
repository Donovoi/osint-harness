# Validation record

The initial release was tested against an existing, separately qualified backend. Infrastructure identifiers, case content and private operational receipts are excluded from this repository.

Observed on 2026-10-30:

- Local unit/integration tests cover host and origin validation, one-use launcher capabilities, CSRF, upload bounds and hashing, immutable scope, concurrency, fixed routing, source-pin failures, cleanup result gates and hostile report HTML.
- The backend's 68-test regression suite passed, including checkpoint resume and the new graph modes. The graph-mode tests use stub inference and verify three calls in model-review mode and zero calls in tools-only mode.
- A browser-created tools-only case collected one public example page after a positive Tor preflight, imported a synthetic PDF and completed six tool jobs: native PDF extraction, OCR, offline browser replay, fingerprinting, contact extraction and offline domain candidates. It produced eight evidence records and 32 report snapshots, with zero model calls and no adjudicated claims.
- Resuming that completed case preserved all 17 raw/text/round artifact hashes and did not repeat tool jobs or model calls.
- A second browser-created case was cooperatively stopped during startup, reported successful owned-resource cleanup, and resumed to completion with its original scope.
- The desktop and narrow-window layouts were checked in a browser. File upload, plan review, live report display, start, stop and resume were exercised through the UI.

This is evidence for the tested UI/backend combination, not automatic qualification of another installation. The live run did not re-evaluate model accuracy. Model weights and generation settings were retained. Tool outputs remain observations requiring human review.
