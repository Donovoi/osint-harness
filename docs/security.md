# Security model

## Trust boundaries

The local operator and reviewed backend are trusted. Web pages, files, extracted text, model output, reports, catalog descriptions and remote error messages are untrusted. Catalog references are advisory data. They cannot install software, enable tools or extend collection scope.

The browser holds an authenticated local session, not infrastructure credentials. The web server binds only IPv4 loopback and starts no target-facing client. A fixed, pinned operator launcher performs all remote control; the backend performs target collection through Whonix and validates policy independently. No model-controlled shell or arbitrary MCP endpoint is available.

Report HTML loses all incoming attributes and active content. A sandboxed iframe with a default-deny CSP permits only a hash-pinned, fixed formatting stylesheet. No source-supplied scripts, links, images, CSS, frames, forms or refresh directives survive.

## Limits

- This is a single-operator desktop application, not a multi-user web service. Do not reverse-proxy it, expose its port to a LAN or add remote access without a separate security design.
- Local OS compromise, a hostile process under the same account, or a malicious attached backend defeats the desktop trust boundary. Protect the private app-data folder and SSH/VM credentials with OS permissions. Host disk encryption is optional protection for stored data; BitLocker is not a harness prerequisite.
- App-data uploads and report mirrors are plaintext. The backend vault's encryption does not encrypt the Windows/Linux desktop copy. Deleting a file is not guaranteed secure erasure.
- Tor and circuit isolation reduce some linkability. They do not prove anonymity against endpoint compromise, browser fingerprinting, account logins, identifying source content or traffic correlation. Browser replay remains offline.
- If a worker stops reporting, execution is unconfirmed and new launches stay blocked. A human must resolve the existing process/resource state; a green old report cannot clear this condition.
- The backend supplies bounded process execution and cleanup. A cleanup failure is an error even if a report was generated.
- Files are parsed only by the backend sandbox. PDF/OCR and HTML parser vulnerabilities remain possible; qualification, patching and sandbox boundaries matter.
- Exact quote checks establish that text was present, not that a conclusion follows. Name matches, fingerprints, contact extraction and domain candidates are leads until corroborated.

## Publication hygiene

Keep installation settings, secrets, evidence, report mirrors, infrastructure paths and operational receipts outside Git. Review staged file names and content and use a publication identity that does not disclose a private email address. CI uses only synthetic examples and never connects to a real operator backend.
