// Single source of truth for CLI command summaries and flags. Used by:
//   sign --help                  → top-level command index
//   sign <cmd> [<sub>] --help    → focused per-command help
//   sign --catalog json          → machine-readable index
//   sign examples                → walkthrough snippets

// Bumped manually on each release; mirrored in package.json.
export const SIGN_CLI_VERSION = "0.8.0";

export type FlagSpec = {
  name: string;          // e.g. "--request-id" or "--token"
  required?: boolean;
  description: string;
};

export type CommandSpec = {
  command: string;       // e.g. "request create" or "signer policy run-all"
  summary: string;
  flags?: FlagSpec[];
  example?: string;
};

export const HELP_CATALOG: CommandSpec[] = [
  // Global flags — accepted on EVERY command. Listed here as a pseudo-entry
  // so `sign --help` / `sign --catalog json` surfaces them; they don't
  // belong to any single subcommand.
  {
    command: "(global flags)",
    summary: "Accepted on every command. Resolved BEFORE the per-command flags below. Resolution order for any value: flag > env > active profile > built-in default.",
    flags: [
      { name: "--provider", description: "dropbox | docusign | signwell | local. Env: `SIGN_PROVIDER`. Profile-driven via `--profile <name>`." },
      { name: "--strict-provider", description: "`true` to reject mismatches between the resolved provider and a request's persisted provider. Env: `SIGN_STRICT_PROVIDER`." },
      { name: "--profile", description: "Activate a named profile from `~/.config/sign-cli/profiles.json` (or `SIGN_PROFILES_FILE`). The active profile sets defaults for provider, dbPath, strictProvider, defaultTokenTtlMinutes, defaultSignerEmail, and credentials. Env: `SIGN_PROFILE`. See `sign profile show` for resolved state." },
      { name: "--verbose", description: "`true` to enable HTTP/SDK debug logging (sets `SIGN_DEBUG=1`). Headers like Authorization / API keys are auto-redacted." },
    ],
  },
  // Top-level lifecycle
  {
    command: "init",
    summary: "Interactive .env wizard for hosted-provider credentials.",
    flags: [{ name: "--out", description: "Path to write the generated .env (defaults to ./.env)." }],
  },
  {
    command: "doctor",
    summary: "Print an unstructured environment + key-detection report. Always exits 0 — for a machine-readable per-check result, use `doctor preflight`.",
  },
  {
    command: "doctor preflight",
    summary: "Structured per-check preflight. Env-health checks (`runtime:node_version`, `storage:db_path`) run on every provider; provider-scoped checks (env vars, API connectivity, RSA key file presence, canonical fixture for `local`) layer on top. Output: `{ provider, summary:{passed,failed,skipped,verdict}, checks:[{name, status:\"ok\"|\"failed\"|\"skipped\", detail, hint?}] }`. Exit `0` if verdict is `ok`, `1` if any check failed.",
    flags: [{ name: "--provider", description: "Override resolved provider (dropbox | docusign | signwell | local)." }],
  },
  {
    command: "doctor account-check",
    summary: "Live API check for the selected provider's account quota / configuration.",
    flags: [{ name: "--provider", description: "dropbox | docusign | signwell | local." }],
  },
  {
    command: "doctor providers",
    summary: "JSON capability matrix for all four providers.",
  },
  {
    command: "demo",
    summary: "Run the local-provider end-to-end demo: create + send + sign + bundle.",
    flags: [
      { name: "--document", description: "PDF to sign (optional; demo generates one if omitted)." },
      { name: "--out", description: "Bundle output directory (defaults to ./demo-bundle)." },
    ],
  },
  // Profiles
  {
    command: "profile list",
    summary: "List configured user profiles + show which is active. Active source: `flag` (--profile), `env` (SIGN_PROFILE), `default-profile` (file), or `project-file` (./sign-profile.json discovered upward from CWD).",
  },
  {
    command: "profile show",
    summary: "Print the resolved active profile and where each value came from (project vs user). Without --name, shows the resolved view; with --name, shows that user profile directly. Credentials redacted by default — pass --show-secrets true to reveal resolved values.",
    flags: [
      { name: "--name", description: "Show a specific user profile by name instead of the active resolved view." },
      { name: "--show-secrets", description: "Pass `true` to reveal resolved credential values (post-{{env:}}-expansion). Default redacts to keys-only." },
    ],
    example: "sign profile show --show-secrets true",
  },
  {
    command: "profile use",
    summary: "Set the `defaultProfile` in the user file. Subsequent commands that don't pass --profile / SIGN_PROFILE use this one.",
    flags: [{ name: "--name", description: "Profile to use (alternatively: positional after `use`)." }],
    example: "sign profile use --name prod",
  },
  {
    command: "profile set",
    summary: "Set a single field on a profile. Validates the resulting profile before writing — `--value bogus` for `provider` fails fast. For credentials: `--key credentials.<NAME>`.",
    flags: [
      { name: "--name", required: true, description: "Profile name." },
      { name: "--key", required: true, description: "Field name (`provider`, `dbPath`, `strictProvider`, `defaultTokenTtlMinutes`, `defaultSignerEmail`) or `credentials.<NAME>`." },
      { name: "--value", required: true, description: "New value. Use `{{env:VAR}}` for shell-managed secrets." },
    ],
    example: "sign profile set --name prod --key credentials.DROPBOX_SIGN_API_KEY --value '{{env:DROPBOX_SIGN_API_KEY_PROD}}'",
  },
  {
    command: "profile unset",
    summary: "Remove a single field from a profile.",
    flags: [
      { name: "--name", required: true, description: "Profile name." },
      { name: "--key", required: true, description: "Field to remove." },
    ],
  },
  {
    command: "profile delete",
    summary: "Remove a named profile from the user file (requires --yes true).",
    flags: [
      { name: "--name", required: true, description: "Profile name." },
      { name: "--yes", required: true, description: "Confirmation flag (`true`)." },
    ],
  },
  {
    command: "profile init",
    summary: "Create a new profile. By default writes to the user file; pass `--project true` to write `./sign-profile.json` (single-profile shape, no map). Validates before writing.",
    flags: [
      { name: "--name", description: "Profile name (required unless --project)." },
      { name: "--project", description: "Pass `true` to write a project file `./sign-profile.json` instead of the user file." },
      { name: "--provider", description: "dropbox | docusign | signwell | local." },
      { name: "--db", description: "Path for `dbPath` (supports `~` and `{{env:VAR}}`)." },
      { name: "--strict-provider", description: "`true` / `false`." },
      { name: "--default-token-ttl-minutes", description: "Positive number." },
      { name: "--default-signer-email", description: "Default signer email." },
      { name: "--set-default", description: "`true` to mark this as the user file's defaultProfile." },
    ],
    example: "sign profile init --name prod --provider dropbox --db ~/.sign-cli/prod.db --set-default true",
  },
  {
    command: "selftest",
    summary: "In-process end-to-end smoke against a scratch DB: create → send → sign → fetch-final → verify-signed-pdf → audit verify → request receipt → verify-receipt. Exits 3 on any failure; drop-in for deploy health checks.",
    flags: [{ name: "--keep-workspace", description: "true to keep the temp directory for inspection (default cleans up)." }],
  },
  // Request creation
  {
    command: "request create",
    summary: "Create a signing request from CLI flags or a JSON spec file.",
    flags: [
      { name: "--title", description: "Document title." },
      { name: "--document", description: "Path to a PDF (repeatable for multi-doc)." },
      { name: "--signer", description: "Signer spec name:X,email:Y,order:N (repeatable)." },
      { name: "--field", description: "Field placement (repeatable). Keys: signer:N (1-based, matches --signer order), doc:N (0-based document index), page:N (1-based), x:N, y:N (provider pixels, top-left origin), type:signature|initials|date|text|name|email (default signature), width:N, height:N, required:true|false (default true). Anchor strings are not supported via this CLI. See docs/field-coordinates.md for the per-provider coordinate contract." },
      { name: "--prefill", description: "Template prefill name:K,value:V[,signer:N]." },
      { name: "--token-ttl-minutes", description: "Token lifetime in minutes (default 60)." },
      { name: "--auto-approve", description: "true to skip the approval gate (default false). Cannot be combined with --require-consent / --require-email-verification." },
      { name: "--require-consent", description: "true to require every signer to attest intent-to-sign + accept the electronic-records disclosure (approve --agree true --accept-disclosure true) before they can sign. See `sign consent show`." },
      { name: "--require-email-verification", description: "true to require every signer to prove control of their email with a verification code (`signer send-verification` / `signer verify-email`) before they can sign." },
      { name: "--provider", description: "dropbox | docusign | signwell | local." },
      { name: "--spec", description: "Load all of the above from a JSON file." },
      { name: "--param", description: "key=value substituted into spec via {{key}} (repeatable)." },
      { name: "--idempotency-key", description: "Same key + same args returns the cached result instead of re-running." },
    ],
    example:
      `sign request create --title "Mutual NDA" --document ./nda.pdf \\\n` +
      `  --signer name:Alice,email:alice@example.com,order:1 \\\n` +
      `  --signer name:Bob,email:bob@example.com,order:2 \\\n` +
      `  --provider local --auto-approve true`,
  },
  {
    command: "request from-template",
    summary: "Create a request from a provider-side template id.",
    flags: [
      { name: "--template-id", required: true, description: "Provider template id." },
      { name: "--signer", description: "role:Buyer,name:Alice,email:alice@example.com,order:1." },
      { name: "--prefill", description: "Template prefill name:K,value:V[,signer:N]." },
    ],
  },
  {
    command: "request run-email",
    summary: "Convenience: create + send in one step. Auto-approves.",
    flags: [
      { name: "--field", description: "Same as `request create --field` (repeatable). See docs/field-coordinates.md." },
      { name: "--test-mode", description: "true|false. SignWell defaults to true (non-binding, watermarked); pass false for a real binding send." },
      { name: "--ordered", description: "true|false (SignWell). true = sequential signing, false = parallel/unordered. Default: sequential when 2+ signers." },
    ],
  },
  {
    command: "request send",
    summary: "Dispatch a created request to the provider.",
    flags: [
      { name: "--request-id", required: true, description: "Request id." },
      { name: "--force", description: "Resend even if provider_request_id is already set." },
      { name: "--test-mode", description: "true|false. SignWell defaults to true (non-binding, watermarked); pass false for a real binding send." },
      { name: "--ordered", description: "true|false (SignWell). true = sequential signing, false = parallel/unordered. Default: sequential when 2+ signers." },
    ],
  },
  {
    command: "request send-embedded",
    summary: "Send via the provider's embedded-signing flow.",
    flags: [
      { name: "--request-id", required: true, description: "Request id." },
      { name: "--client-id", description: "Embedded client id (Dropbox Sign)." },
      { name: "--test-mode", description: "true|false. SignWell defaults to true (non-binding, watermarked); pass false for a real binding send." },
      { name: "--ordered", description: "true|false (SignWell). true = sequential signing, false = parallel/unordered. Default: sequential when 2+ signers." },
    ],
  },
  {
    command: "request sign-url",
    summary: "Fetch a per-signer sign URL.",
  },
  {
    command: "request launch-embedded",
    summary: "Generate an HTML launcher that wraps the embedded sign URL.",
  },
  {
    command: "request fetch-final",
    summary: "Download the completed PDF and persist to artifacts.",
  },
  {
    command: "request status",
    summary: "Poll the provider once for current status. Pass --watch true to poll until terminal (same flags as `request watch`).",
    flags: [
      { name: "--request-id", required: true, description: "Request id." },
      { name: "--watch", description: "true to keep polling; same flags + exit codes as `request watch`." },
      { name: "--interval-ms", description: "(--watch true) Poll interval; or --interval-seconds." },
      { name: "--timeout-ms", description: "(--watch true) Stop after N ms; or --timeout-seconds." },
      { name: "--fetch-final", description: "(--watch true) true to download the signed PDF on completion." },
      { name: "--out", description: "(--watch true) Path to write the signed PDF." },
    ],
  },
  {
    command: "request watch",
    summary: "Poll until terminal (completed/declined/expired/canceled) or timeout.",
  },
  {
    command: "request remind",
    summary: "Re-notify a pending signer (provider-dependent).",
  },
  {
    command: "request cancel",
    summary: "Cancel/void at the provider. Requires --yes true.",
  },
  {
    command: "request bulk",
    summary: "One-request-per-row from a CSV. Optionally emits a tokens roster (--emit-tokens ./tokens.json) compatible with `signer policy run-all --tokens-file …`.",
    flags: [
      { name: "--csv", required: true, description: "CSV file with name + email columns." },
      { name: "--document", description: "PDF to attach (repeatable for multi-doc)." },
      { name: "--title", description: "Title template; supports {{email}}, {{name}}, {{row}}." },
      { name: "--emit-tokens", description: "Write a per-row tokens roster to this path (skipped from stdout)." },
      { name: "--ndjson", description: "true to emit one JSON object per result row (plus a final summary line) — pipe-friendly for jq/grep/streaming consumers." },
    ],
  },
  {
    command: "request bulk-resend",
    summary: "Re-issue signer tokens en masse from a CSV roster. Rows: request_id,signer_email[,token_ttl_minutes]. Per-row failures (signer-not-recipient, already-signed, missing approval) are captured so the batch keeps going. Exits 3 if any row failed.",
    flags: [
      { name: "--csv", required: true, description: "CSV with request_id + signer_email columns." },
      { name: "--token-ttl-minutes", description: "Default TTL for new tokens (default 30); overridable per row." },
      { name: "--emit-tokens", description: "Write a tokens roster to this path (the canonical artifact; stdout strips raw tokens)." },
      { name: "--ndjson", description: "true to emit one JSON object per result row (plus a final summary line)." },
    ],
  },
  {
    command: "request list",
    summary: "List recent requests from local SQLite. JSON by default; --format table renders a fixed-width grep-able view.",
    flags: [
      { name: "--provider", description: "Filter by provider." },
      { name: "--status", description: "Filter by status." },
      { name: "--since", description: "Only rows created at or after this ISO 8601 timestamp." },
      { name: "--limit", description: "Cap rows (default 100, max 500)." },
      { name: "--format", description: "json (default) or table." },
    ],
  },
  {
    command: "request diff",
    summary: "Compare two requests (handy for repeat counterparties): title/status/provider deltas, added/removed/same signers, and whether the document hash changed. Exits 0 on identical, 1 on any diff.",
    flags: [
      { name: "--before", required: true, description: "Earlier request id." },
      { name: "--after", required: true, description: "Later request id." },
    ],
  },
  {
    command: "request rerun-policy",
    summary: "Re-evaluate a stored request against a (possibly updated) policy spec. Pure read — no state mutation, no signer token required. Companion to `signer policy try` for in-flight or completed requests.",
    flags: [
      { name: "--request-id", required: true, description: "Request to re-evaluate." },
      { name: "--spec", required: true, description: "Path to policy.json." },
      { name: "--signer-email", description: "Override signer email (defaults to first recipient)." },
    ],
  },
  {
    command: "request show",
    summary: "Enriched snapshot: request, approvals, signedBy[], nextSteps[]. With --metrics true, also returns counters (events, fetches, webhook replays, time-to-first-sign, time-to-complete). With --hash-only true, prints just { requestId, documentSha256, chainHead } — for diff-style scripted comparisons (jq, watch, sha256sum).",
    flags: [
      { name: "--request-id", required: true, description: "Request id." },
      { name: "--metrics", description: "true to include the metrics rollup." },
      { name: "--hash-only", description: "true to suppress everything except the request_id, document SHA-256, and current audit-chain head. Stable across builds." },
      { name: "--recipient", description: "Email of a signer on this request. Returns a redacted snapshot showing only that recipient's view — other signers, their approvals, and decline reasons from other recipients are stripped. Useful when sharing status with one signer without leaking others. Errors SIGNER_NOT_RECIPIENT if the email isn't on the request." },
    ],
  },
  {
    command: "request verify-signed-pdf",
    summary: "Inspect the embedded PKCS#7 signature(s) of a final PDF. Per signer, the output includes a structural `trust` label: `self_signed_local` (this CLI's built-in signer), `self_signed_other` (issuer==subject, but not from this CLI), `ca_signed` (issuer!=subject), or `unknown` (parse error). Labels are descriptive, not enforced — no trust-store lookup or chain validation. Pass `--recipient <email>` to scope the signer-match check to one expected signer (vs. requiring the full persisted-signer roster — useful for mid-flight multi-signer requests).",
    flags: [
      { name: "--request-id", required: true, description: "Request whose signed PDF should be verified." },
      { name: "--path", description: "Inspect a specific PDF path instead of the latest signed artifact." },
      { name: "--recipient", description: "Narrow the signer-match check to a single recipient email (the rest of the persisted-signer roster is ignored for that one check)." },
    ],
  },
  {
    command: "pdf stamp",
    summary: "Stamp an image (PNG / JPG / SVG / data URL) onto a PDF without a signing request. Shares the renderer with the integrated sign-flow.",
    flags: [
      { name: "--pdf", required: true, description: "Source PDF path." },
      { name: "--image", required: true, description: "Image path or `data:image/...;base64,...`." },
      { name: "--image-page", required: true, description: "1-indexed page number to stamp." },
      { name: "--image-x", required: true, description: "X coordinate in PDF points from the lower-left." },
      { name: "--image-y", required: true, description: "Y coordinate in PDF points from the lower-left." },
      { name: "--image-width", required: true, description: "Stamp width in points." },
      { name: "--image-height", required: true, description: "Stamp height in points." },
      { name: "--out", required: true, description: "Output PDF path." },
      { name: "--preserve-aspect-ratio", description: "Default `true`. Shrinks the image to fit inside the rectangle, top-left aligned, so it's never stretched. Pass `false` to restore legacy stretch-to-fill behavior." },
      { name: "--signature-image-auto-crop", description: "Pass `true` to trim white/transparent margins around the ink and replace near-white opaque pixels with transparent ones (PNG only; no-op on JPG/SVG). Removes the white-rectangle-around-signature look from photographed-on-paper signature scans." },
      { name: "--strict-quality", description: "Pass `true` to exit non-zero (code 3) when any quality warning fires (oversized stamp, overlap with body text, off-page rectangle, distorted aspect). Default is advisory — warnings are surfaced but the command still exits 0." },
    ],
  },
  {
    command: "pdf stamp verify",
    summary: "Confirm a previously-stamped image is at the expected position + size within ±1pt. Pairs with `pdf stamp` for CI tamper checks.",
    flags: [
      { name: "--pdf", required: true, description: "PDF to inspect." },
      { name: "--image-page", required: true, description: "Expected page (1-indexed)." },
      { name: "--image-x", required: true, description: "Expected X (points)." },
      { name: "--image-y", required: true, description: "Expected Y (points)." },
      { name: "--image-width", required: true, description: "Expected width (points)." },
      { name: "--image-height", required: true, description: "Expected height (points)." },
    ],
    example: "sign pdf stamp verify --pdf ./signed.pdf --image-page 1 --image-x 100 --image-y 200 --image-width 150 --image-height 60",
  },
  {
    command: "document",
    summary: "One-shot end-to-end signing: DOCX|PDF in, sealed (PAdES) PDF out. Converts the input to PDF via the bundled docx2pdf-cli (auto-selecting the available backend — LibreOffice, Pages, Word, Gotenberg, ConvertAPI, textutil), auto-detects the signature-field rectangle, stamps the signature image, PAdES-seals, verifies the audit chain, and writes the final PDF. All intermediate state lives in a temp DB scoped to the call — the user's main `./data/sign.db` is untouched. For backend control on the converter side, run docx2pdf directly first and pass the resulting PDF.",
    flags: [
      { name: "<input>", required: true, description: "Positional: input document. `.docx`, `.doc`, `.odt`, `.rtf`, or `.pdf`." },
      { name: "--signer", required: true, description: "Signer's full name (used on the signature cert + record)." },
      { name: "--out", required: true, description: "Output sealed PDF path." },
      { name: "--signature-image", description: "Visible signature image (PNG/JPG/SVG/data-URL). Mutually exclusive with --name-signature." },
      { name: "--name-signature", description: "Visible signature as rendered italic text. Mutually exclusive with --signature-image." },
      { name: "--auto-place", description: "Placement selector. Defaults to `first` (top-most signature anchor) when no explicit --image-* coords are given. Full selector set: true | first | last | all | page:N | index:N." },
      { name: "--image-page", description: "Explicit stamp page (1-indexed). Overrides --auto-place." },
      { name: "--image-x", description: "Explicit stamp x in PDF points." },
      { name: "--image-y", description: "Explicit stamp y in PDF points." },
      { name: "--image-width", description: "Explicit stamp width in points." },
      { name: "--image-height", description: "Explicit stamp height in points." },
      { name: "--signer-email", description: "Optional. Defaults to `<slugified-name>@local.invalid` for self-sign flows." },
      { name: "--title", description: "Optional document title. Defaults to the input filename." },
      { name: "--preserve-aspect-ratio", description: "Default `true`. Shrinks the image to fit, never stretches." },
      { name: "--signature-image-auto-crop", description: "Pass `true` to trim white/transparent PNG margins before stamping." },
    ],
    example: "sign document contract.docx --signer \"Alice\" --signature-image alice.png --auto-place first --out signed.pdf",
  },
  {
    command: "preview",
    summary: "Stamp a signature image (or rendered name) onto a PDF WITHOUT producing a PAdES envelope. Use this to iterate on placement before committing to a signed PDF — once you're happy with where the stamp lands, run `sign sign` with the same --signature-image/--auto-place flags to produce the real (sealed) PDF. No signing-request DB interaction. Quality warnings (oversized, overlap, off-page) are surfaced in the output the same way `pdf stamp` does.",
    flags: [
      { name: "--pdf", required: true, description: "Source PDF path." },
      { name: "--signature-image", description: "Image path or `data:image/...;base64,...`. Mutually exclusive with --name-signature." },
      { name: "--name-signature", description: "Render this text as a visible signature (italic Helvetica)." },
      { name: "--out", required: true, description: "Output PDF path for the preview (unsealed)." },
      { name: "--auto-place", description: "Auto-detect placement. Same selector values as `sign sign --auto-place` — true | first | last | all | page:N | index:N." },
      { name: "--image-page", description: "Explicit stamp page (1-indexed). Overrides --auto-place when set with the other --image-* coords." },
      { name: "--image-x", description: "Explicit stamp x in PDF points." },
      { name: "--image-y", description: "Explicit stamp y in PDF points." },
      { name: "--image-width", description: "Explicit stamp width in points." },
      { name: "--image-height", description: "Explicit stamp height in points." },
      { name: "--preserve-aspect-ratio", description: "Default `true`. Shrinks --signature-image to fit (top-left aligned). Pass `false` to stretch." },
      { name: "--signature-image-auto-crop", description: "Pass `true` to trim PNG margins + key-out near-white before stamping." },
    ],
    example: "sign preview --pdf doc.pdf --signature-image sig.png --auto-place all --out preview.pdf",
  },
  {
    command: "pdf detect-signature-field",
    summary: "Auto-detect signature-field placements in a PDF. Returns AcroForm /Sig widgets (confidence 1.0) first, then anchor-text matches (Signature:, Sign here, Signed by:, Initial:, X____) with overlap-adjusted rectangles. Pair with `sign sign --auto-place` for hands-off positioning. Date anchors are NOT included here — see `pdf detect-date-field`. Exit 2 when no candidates found.",
    flags: [
      { name: "--pdf", required: true, description: "PDF to inspect." },
      { name: "--verbose", description: "Pass `true` to include the raw pdfjs text items per page (`textItemsByPage`) and page dimensions (`pageDimensions`). Use to debug zero-candidate outcomes." },
    ],
    example: "sign pdf detect-signature-field --pdf ./nda.pdf --verbose true",
  },
  {
    command: "pdf detect-date-field",
    summary: "Auto-detect date-field placements in a PDF. Returns anchor-text matches for `Date:`, `Date de signature:`, `Date d'effet:`, `Date d'entrée en vigueur:`. Each candidate carries `alreadyFilled: true` when a recognisable date string is already present near the anchor — callers stamping a date can skip those by default. Pair with `sign pdf stamp-text --auto-place` for hands-off date filling. Exit 2 when no candidates found.",
    flags: [
      { name: "--pdf", required: true, description: "PDF to inspect." },
      { name: "--verbose", description: "Pass `true` to include the raw pdfjs text items per page (`textItemsByPage`) and page dimensions (`pageDimensions`)." },
    ],
    example: "sign pdf detect-date-field --pdf ./contract.pdf",
  },
  {
    command: "pdf inspect",
    summary: "Inspect signatures on ANY PADES-signed PDF — ours, Adobe's, DocuSign's, Dropbox Sign's, SignWell's. Pure read; no DB interaction, no audit events written. Returns per-signature signer CN/email, cert subject + issuer, validity window, fingerprint, trust label (self_signed_local | self_signed_other | ca_signed | unknown), message-digest match, and parse warnings. Trust label is structural (issuer vs subject) — no chain validation, no trust-store lookup, no expiry check; for those, use an external verifier. Exit 2 when the PDF has no signatures.",
    flags: [
      { name: "--pdf", required: true, description: "PDF to inspect." },
    ],
    example: "sign pdf inspect --pdf ./signed-by-adobe.pdf",
  },
  {
    command: "pdf stamp-text",
    summary: "Stamp a plain text string (Helvetica regular, no underline) onto a PDF — sibling of `pdf stamp` for image stamping. Used for dates and other non-signature text fills. Supports `--auto-place` to fill detected DATE anchors automatically. Candidates that already contain a date string are skipped by default; pass `--overwrite-filled true` to ignore that protection.",
    flags: [
      { name: "--pdf", required: true, description: "Source PDF path." },
      { name: "--text", required: true, description: "Text to stamp." },
      { name: "--out", required: true, description: "Output PDF path." },
      { name: "--auto-place", description: "Auto-detect placement at date anchors. Same selector values as `sign sign --auto-place` — true | first | last | all | page:N | index:N. Filtered to `category: date`." },
      { name: "--overwrite-filled", description: "Default `false`. Pass `true` to include date candidates flagged `alreadyFilled` (a date string is already present nearby). Otherwise those are skipped — preserving existing content." },
      { name: "--image-page", description: "Explicit stamp page (1-indexed). Overrides --auto-place when set with the other --image-* coords." },
      { name: "--image-x", description: "Explicit stamp x in PDF points." },
      { name: "--image-y", description: "Explicit stamp y in PDF points." },
      { name: "--image-width", description: "Explicit stamp width in points." },
      { name: "--image-height", description: "Explicit stamp height in points." },
    ],
    example: "sign pdf stamp-text --pdf contract.pdf --text \"12 mai 2026\" --auto-place all --out stamped.pdf",
  },
  {
    command: "workflow nda",
    summary: "One-shot: render the bundled mutual-NDA template into a PDF and create the signing request. Exits 3 on validation errors (same-email, missing values, missing placeholders — all gaps surface at once).",
    flags: [
      { name: "--values", description: "JSON map of {{PLACEHOLDER}} → value." },
      { name: "--value", description: "Inline override `KEY=VALUE` (repeatable; wins over --values)." },
      { name: "--party-a-email", required: true, description: "Signer A email (must differ from party-b)." },
      { name: "--party-b-email", required: true, description: "Signer B email." },
      { name: "--template", description: "Override the bundled template path." },
      { name: "--out", required: true, description: "Output PDF path." },
      { name: "--token-ttl-minutes", description: "Token lifetime (default 60)." },
      { name: "--auto-approve", description: "true to skip the approval gate." },
    ],
    example:
      `sign workflow nda --values fixtures/templates/mutual-nda.example.json \\\n` +
      `  --party-a-email alice@example.com --party-b-email bob@example.com \\\n` +
      `  --out ./nda.pdf`,
  },
  {
    command: "request receipt",
    summary: "Audit-export bundle plus a detached manifest.sig + manifest.cert.pem.",
    flags: [
      { name: "--request-id", required: true, description: "Request id." },
      { name: "--out", required: true, description: "Output directory." },
    ],
  },
  {
    command: "request verify-receipt",
    summary: "Standalone verifier for a request receipt bundle (no DB required).",
    flags: [
      { name: "--bundle", required: true, description: "Path to a directory produced by `request receipt`." },
      { name: "--html", description: "Also write a static HTML report to this path (printable, openable by non-CLI recipients)." },
    ],
    example: "sign request verify-receipt --bundle ./receipt/ --html ./receipt/report.html",
  },
  // Signer-side
  {
    command: "approve",
    summary: "Spend the signer's approval token (the requester pre-flight gate). Optionally capture consent attestations while doing so.",
    flags: [
      { name: "--request-id", required: true, description: "Request id." },
      { name: "--token", required: true, description: "Per-signer token from request create." },
      { name: "--agree", description: "true = attest intent to sign (records the canonical intent-to-sign statement in the audit chain). Required when the request was created with --require-consent." },
      { name: "--accept-disclosure", description: "true = accept the electronic-records (ESIGN) disclosure. Required when the request was created with --require-consent. Read both texts with `sign consent show`." },
      { name: "--verification-code", description: "One-step email verification: the code issued by `signer send-verification`." },
      { name: "--identity-assurance", description: "Record how the signer's identity was checked out-of-band: method:<in-person|video-call|document-check|provider-idv|known-contact|other>[,verifier:...][,reference:...][,notes:...]. Store a pointer to evidence, never the evidence itself." },
    ],
    example:
      `sign approve --request-id req_abc --token alice-tok-... \\\n` +
      `  --agree true --accept-disclosure true`,
  },
  {
    command: "consent show",
    summary: "Print the canonical consent statements (intent-to-sign + electronic-records disclosure) with their version ids and SHA-256 — the exact texts recorded when a signer approves with --agree / --accept-disclosure.",
  },
  {
    command: "sign",
    summary: "Sign a local-provider request as the holder of --token. Without a visible-signature flag the PAdES envelope is invisible; pass --signature-image OR --name-signature to add a visible stamp.",
    flags: [
      { name: "--request-id", required: true, description: "Request id." },
      { name: "--token", required: true, description: "Per-signer token." },
      { name: "--signer-email", description: "Optional: must match the token's signer (typo catch)." },
      { name: "--signer-name", description: "Override the signer name on this signature. When used with `--name-signature true` this is the text rendered." },
      { name: "--require-hash", description: "Pre-sign safety: expected document SHA-256." },
      { name: "--require-title", description: "Pre-sign safety: regex the title must match." },
      { name: "--require-signer-email", description: "Pre-sign safety: expected signer email." },
      { name: "--signature-image", description: "Visible signature: PNG/JPG/SVG file path or `data:image/...;base64,...`. Mutually exclusive with --name-signature." },
      { name: "--name-signature", description: "Visible signature: render the signer name as italic text (no image asset needed). Pass `true` (use --signer-name as the text) or a literal string like `--name-signature \"Baher Al Hakim\"`. Mutually exclusive with --signature-image." },
      { name: "--image-page", description: "Stamp position (1-indexed). Required when a visible-signature flag is set and the sender didn't already place a SignatureField for this signer." },
      { name: "--image-x", description: "Stamp x in PDF points (lower-left origin)." },
      { name: "--image-y", description: "Stamp y in PDF points (lower-left origin)." },
      { name: "--image-width", description: "Stamp width in points." },
      { name: "--image-height", description: "Stamp height in points." },
      { name: "--auto-place", description: "Auto-detect the stamp rectangle via `sign pdf detect-signature-field`. Accepted values: `true` (requires a unique high-confidence candidate), `first` (earliest page, top), `last` (latest page, bottom), `all` (multi-stamp: one stamp per high-confidence candidate), `page:N` (the unique candidate on page N), `index:N` (Nth candidate, 0-indexed from the confidence-sorted list). Errors with `AUTO_PLACE_*` codes + the candidate list when the selector can't pick. Explicit --image-* coords override --auto-place." },
      { name: "--preserve-aspect-ratio", description: "Default `true`. Shrinks --signature-image to fit inside the stamp rectangle (top-left aligned) so it's never stretched. Pass `false` to restore legacy stretch-to-fill behavior." },
      { name: "--signature-image-auto-crop", description: "Pass `true` to trim white/transparent margins around the ink and replace near-white opaque pixels with transparent ones (PNG only). Removes the white-rectangle-around-signature look from scans." },
      { name: "--idempotency-key", description: "Same key returns the cached SignerSignResult instead of double-signing on retry." },
    ],
    example:
      `sign sign --request-id req_abc --token alice-tok-... \\\n` +
      `  --name-signature "Alice Anderson" \\\n` +
      `  --auto-place true   # or pass --image-page/--image-x/--image-y/--image-width/--image-height`,
  },
  {
    command: "signer list",
    summary: "Pending inbox; entries include tokens[] with expiresSoon flags.",
    flags: [{ name: "--signer-email", description: "Filter to a single signer." }],
  },
  {
    command: "signer fetch-document",
    summary: "Read the unsigned PDF; records request.signer_fetched_document.",
  },
  {
    command: "signer decline",
    summary: "Decline as the token holder.",
  },
  {
    command: "signer reissue-token",
    summary: "Mint a new per-signer token and invalidate the old one.",
  },
  {
    command: "signer send-verification",
    summary: "Issue a 6-digit email-verification code for a signer (invalidates prior unverified codes). Only the code's hash is stored; the plaintext is returned once for delivery to the signer's mailbox — via SIGN_VERIFICATION_WEBHOOK_URL if set, otherwise deliver it out-of-band.",
    flags: [
      { name: "--request-id", required: true, description: "Request id." },
      { name: "--email", required: true, description: "Signer email (must be on the request)." },
      { name: "--ttl-minutes", description: "Code lifetime (default 15)." },
    ],
  },
  {
    command: "signer verify-email",
    summary: "Redeem a verification code, proving the signer controls the mailbox. Records request.signer_email_verified in the audit chain. 5 wrong attempts lock the code (re-issue to retry).",
    flags: [
      { name: "--request-id", required: true, description: "Request id." },
      { name: "--email", required: true, description: "Signer email." },
      { name: "--code", required: true, description: "The 6-digit code from signer send-verification." },
    ],
  },
  {
    command: "signer record-identity",
    summary: "Record an out-of-band identity check for a signer in the audit chain (the assertion, not the evidence). Also available inline on approve via --identity-assurance.",
    flags: [
      { name: "--request-id", required: true, description: "Request id." },
      { name: "--email", required: true, description: "Signer email." },
      { name: "--identity-assurance", required: true, description: "method:<in-person|video-call|document-check|provider-idv|known-contact|other>[,verifier:...][,reference:...][,notes:...]" },
    ],
    example: `sign signer record-identity --request-id req_abc --email alice@example.com \\\n  --identity-assurance method:video-call,verifier:ops@acme.com,reference:TICKET-123`,
  },
  {
    command: "signer watch",
    summary: "Long-running tail of the signer inbox; emits new entries as they appear.",
    flags: [
      { name: "--signer-email", description: "Filter the inbox to one signer." },
      { name: "--exit-on-first", description: "true to exit on the first new entry (otherwise runs forever / until --timeout-seconds)." },
      { name: "--interval-seconds", description: "Belt-and-suspenders poll interval (default 1s)." },
      { name: "--timeout-seconds", description: "Exit code 4 after this many seconds with no new entry." },
    ],
  },
  {
    command: "signer policy run",
    summary: "Apply a declarative policy spec to a single request.",
  },
  {
    command: "signer policy run-all",
    summary: "Loop the inbox and apply a policy to every request the agent has a token for.",
  },
  {
    command: "signer policy run-watch",
    summary: "Long-running: tail the inbox and apply a policy to every NEW entry (initial snapshot is informational). Composes signer watch + signer policy run-all so an agent can stay attached. Exits 3 if any row failed, 4 on --timeout-seconds.",
    flags: [
      { name: "--tokens-file", required: true, description: "JSON map { requestId: token } or array of { requestId, token } — same shape as run-all." },
      { name: "--spec", required: true, description: "Path to policy.json." },
      { name: "--signer-email", description: "Restrict to one signer's inbox view." },
      { name: "--dry-run", description: "true to run evaluatePolicy + log decisions without applying state changes." },
      { name: "--exit-on-first", description: "true to exit after the first new entry is evaluated." },
      { name: "--interval-seconds", description: "Belt-and-suspenders poll interval (default 1s)." },
      { name: "--timeout-seconds", description: "Exit code 4 after this many seconds with no new entry." },
      { name: "--report", description: "Append one NDJSON line per evaluated entry to this file (plus a final {summary:true,…} line). Replay/audit-friendly." },
      { name: "--on-decision", description: "Shell command spawned per evaluated entry. Receives the entry JSON on stdin and SIGN_HOOK_REQUEST_ID/SIGN_HOOK_SIGNER_EMAIL/SIGN_HOOK_OK/SIGN_HOOK_ACTION/SIGN_HOOK_SKIPPED env vars. Fire-and-forget — child errors land on stderr but don't affect the watcher's exit code." },
      { name: "--since-anchor", description: "`latest` or an explicit anchor `artifactId`. Skips entries created at or before the anchor's createdAt — useful when an anchor already attests to all chains up to that point and you only want to act on what's newer." },
    ],
  },
  {
    command: "signer policy try",
    summary: "Offline tester for a policy spec — supply a synthetic context and print the decision without touching state.",
    flags: [
      { name: "--spec", required: true, description: "Path to policy.json." },
      { name: "--title", description: "Title for the synthetic context (or use --snapshot)." },
      { name: "--document-sha256", description: "SHA-256 for the synthetic context (or use --snapshot)." },
      { name: "--signer-email", description: "Signer email for the synthetic context (or use --snapshot)." },
      { name: "--snapshot", description: "Path to a request show JSON file; pulls title/sha256/signer from it." },
      { name: "--batch", description: "Path to a JSON array of { title, documentSha256, signerEmail, label? } contexts. Emits { sign, decline, report, errored } counters + a per-row decisions[] array. Per-row errors are caught — one bad row doesn't poison the batch." },
    ],
    example:
      `sign signer policy try --spec ./policy.json \\\n` +
      `  --title "Mutual NDA" --document-sha256 abc... --signer-email alice@example.com`,
  },
  {
    command: "signer policy lint",
    summary: "Static checks for a policy spec: invalid regexes, unreachable rules after match: \"any\", redundant rules (same action as a broader earlier rule), CONTRADICTORY rules (different action than a broader earlier rule — the engine can never distinguish them, so the second is dead), decline actions without a reason. Exits 3 if errors are present; warnings are non-fatal.",
    flags: [
      { name: "--spec", required: true, description: "Path to policy.json." },
    ],
    example: `sign signer policy lint --spec ./policy.json`,
  },
  {
    command: "signer policy diff",
    summary: "Compare two policy specs against the same context(s) and report which rows would flip action. Pure preview — never touches request state.",
    flags: [
      { name: "--before", required: true, description: "Path to the current/baseline policy.json." },
      { name: "--after", required: true, description: "Path to the proposed policy.json." },
      { name: "--snapshot", description: "Diff a single context loaded from a request show JSON file." },
      { name: "--inbox", description: "true to diff against every pending inbox row (filtered by --signer-email)." },
      { name: "--signer-email", description: "Inbox filter / fallback signer for the synthetic context." },
      { name: "--format", description: "json (default) or markdown — markdown renders a reviewer-friendly table sorted changed-first." },
    ],
    example:
      `sign signer policy diff --before ./policy.v1.json --after ./policy.v2.json \\\n` +
      `  --inbox true --signer-email alice@example.com`,
  },
  // Audit + bundles
  {
    command: "audit show",
    summary: "List all audit events for a request. JSON by default; --format csv emits an RFC 4180 CSV (CRLF line endings, quoted payloads) for spreadsheet-driven compliance review. --event-type filters to one or more event_type values.",
    flags: [
      { name: "--request-id", required: true, description: "Request to dump." },
      { name: "--format", description: "json (default), csv (RFC 4180), or pretty (human-readable timeline)." },
      { name: "--event-type", description: "Repeatable. Restrict the dump to events whose event_type matches one of the given values (e.g. --event-type request.signed --event-type request.declined)." },
      { name: "--since", description: "ISO 8601 lower bound on created_at." },
      { name: "--until", description: "ISO 8601 upper bound on created_at." },
    ],
  },
  {
    command: "audit verify",
    summary: "Verify the audit chain's hash linkage; exits 3 on a break.",
  },
  {
    command: "audit search",
    summary: "Log-style filter across the full audit_events table. All flags are AND'd; --payload-contains does a substring match on the JSON-serialized payload.",
    flags: [
      { name: "--request-id", description: "Scope to a single request." },
      { name: "--event-type", description: "Exact event_type match (e.g. request.signed)." },
      { name: "--since", description: "ISO 8601 lower bound on created_at." },
      { name: "--until", description: "ISO 8601 upper bound on created_at." },
      { name: "--payload-contains", description: "Substring search across the JSON payload — handy for grepping an email or token hint." },
      { name: "--limit", description: "Cap rows (default 1000, max 5000)." },
    ],
  },
  {
    command: "audit scan",
    summary: "Verify the audit chain for every request in the local DB at once. Exits 3 if any chain is broken.",
    flags: [
      { name: "--provider", description: "Filter by provider (dropbox/docusign/signwell/local)." },
      { name: "--status", description: "Filter by request status." },
      { name: "--limit", description: "Cap rows scanned (default 1000, max 5000)." },
    ],
  },
  {
    command: "audit watch",
    summary: "Long-running tamper alarm: re-verifies the chain on every audit-event notification (or every --interval-seconds). Exits 3 on first break, 4 on timeout.",
    flags: [
      { name: "--request-id", description: "Watch a single request_id (default: scan all requests)." },
      { name: "--interval-seconds", description: "Belt-and-suspenders poll interval (default 5s)." },
      { name: "--timeout-seconds", description: "Stop after N seconds with no break detected." },
    ],
  },
  {
    command: "audit timestamp",
    summary: "Append an RFC 3161 timestamp to the chain head.",
  },
  {
    command: "audit anchor",
    summary: "Cross-request anchor: snapshot every request's chain head and timestamp the digest of the manifest in one TSA call. Re-running over time builds a continuity proof — anyone tampering with an old chain breaks the anchor's digest. Records audit.anchored on every covered request.",
    flags: [
      { name: "--tsa-url", description: "RFC 3161 TSA endpoint (default DigiCert)." },
      { name: "--out", description: "Output dir for the .tsr + manifest.json (default ./artifacts/)." },
      { name: "--since", description: "ISO 8601 cutoff. Only chains whose latest event lands at or after this timestamp are anchored — smaller manifest, cheaper to verify." },
      { name: "--since-anchor", description: "`latest` or an explicit anchor artifactId. Resolves to that anchor's createdAt and uses it as --since." },
      { name: "--dry-run", description: "true to print the manifest + digest that would be anchored without contacting the TSA or writing artifacts. Honors --since/--since-anchor for accurate previews." },
    ],
  },
  {
    command: "audit verify-chain-bundle",
    summary: "Re-check a previously-issued chain bundle in one shot. No DB needed — the bundle is supposed to be self-contained. Re-hashes the anchor manifest and confirms the digest matches INDEX.json; runs verifyRequestReceiptBundle on every per-request directory. Accepts either a directory or a .tar.gz produced by `audit chain-bundle --tarball`. Exits 3 on any failure.",
    flags: [
      { name: "--bundle", description: "Path to a directory previously written by `audit chain-bundle`." },
      { name: "--tarball", description: "Path to a .tar.gz produced by `audit chain-bundle --tarball`. Extracted in-process to a temp dir." },
      { name: "--report", description: "Append one NDJSON line per per-request result + a final {summary:true,…} line. Useful when verifying many bundles in one run; same shape as the bulk commands' --ndjson mode." },
    ],
  },
  {
    command: "audit chain-bundle",
    summary: "Self-contained compliance bundle. Writes a directory containing INDEX.json + the most recent anchor (.tsr + manifest.json) + a per-request receipt bundle for every request that has audit events. Self-contained — auditors can re-verify offline (re-hash the anchor manifest, compare to .tsr; verifyRequestReceiptBundle each request).",
    flags: [
      { name: "--out", required: true, description: "Output directory for the bundle." },
      { name: "--request-id", description: "Repeatable. Restrict to specific request_ids; default includes every request with audit events." },
      { name: "--tarball", description: "Path to also write a gzipped tarball of the bundle (USTAR format, no external deps). The archive's top-level directory matches basename(--out)." },
      { name: "--include-source-pdf", description: "true to copy the unsigned source PDF (requests.document_path) into each per-request receipt dir as source.pdf — auditors can re-hash it and confirm it matches the recorded document_hash." },
    ],
  },
  {
    command: "audit anchors-list",
    summary: "List stored audit_anchor artifacts (newest first) with their digest, TSA URL, manifest path, and covered-request count. Companion to `audit anchor` (write) and `audit verify-anchor` (read-back).",
    flags: [
      { name: "--limit", description: "Cap rows (default 100, max 1000)." },
    ],
  },
  {
    command: "audit verify-anchor",
    summary: "Re-check a previously-issued anchor manifest against the current DB. Per-row outcomes: matches (identical hash), shifted (anchored hash exists earlier in the chain — typical), tampered (anchored hash is gone — strong signal of rewrite), missing (request_id no longer exists). Exits 3 if any tampered/missing.",
    flags: [
      { name: "--manifest", required: true, description: "Path to the audit-anchor-<ts>.manifest.json file emitted by `audit anchor`." },
    ],
  },
  {
    command: "audit export",
    summary: "Bundle audit.json + signed.pdf + audit.tsr + manifest.json.",
  },
  {
    command: "audit export-jsonld",
    summary: "Export the audit chain as a JSON-LD document with a stable @context (interoperable with external auditors / SBOM-style tooling).",
    flags: [
      { name: "--request-id", required: true, description: "Request id." },
      { name: "--out", required: true, description: "Output path for audit.jsonld." },
    ],
  },
  {
    command: "audit sign-head",
    summary: "Sign the latest audit chain hash with the local signer key. Produces a small standalone proof.",
    flags: [
      { name: "--request-id", required: true, description: "Request id." },
      { name: "--out", description: "Optional path to write the proof JSON." },
    ],
  },
  {
    command: "audit verify-head",
    summary: "Verify a head-proof JSON file produced by `audit sign-head`.",
    flags: [{ name: "--proof", required: true, description: "Path to the proof JSON." }],
  },
  {
    command: "audit issue-receipts",
    summary: "Bulk-issue one signed receipt-bundle per matching request (filters: --provider, --status, --limit). Exits 3 if any row failed.",
    flags: [
      { name: "--out", required: true, description: "Parent directory; one subdir per request id." },
      { name: "--provider", description: "Only consider requests for this provider." },
      { name: "--status", description: "Only consider requests with this status (e.g. completed)." },
      { name: "--limit", description: "Cap rows processed (default 1000, max 5000)." },
      { name: "--ndjson", description: "true to emit one JSON object per result row (plus a final summary line)." },
    ],
  },
  // Webhooks
  {
    command: "webhook verify",
    summary: "Verify a webhook payload's signature without ingesting.",
  },
  {
    command: "webhook ingest",
    summary: "Verify + persist a webhook payload (writes signedBy[] for hosted providers).",
  },
  {
    command: "webhook listen",
    summary: "Run an HTTP receiver that ingests provider callbacks. Pass --pretty true to also tail audit events as human-readable lines on stderr.",
    flags: [
      { name: "--provider", description: "dropbox | signwell | docusign." },
      { name: "--port", description: "HTTP port (default 3000)." },
      { name: "--path", description: "URL path the provider POSTs to." },
      { name: "--pretty", description: "Tail audit events as human-readable lines on stderr." },
    ],
  },
  // Infra
  {
    command: "db backup",
    summary: "Snapshot SQLite via VACUUM INTO.",
  },
  {
    command: "db verify",
    summary: "PRAGMA integrity_check; exits 3 on failure.",
  },
  {
    command: "db migrate",
    summary: "Apply pending versioned migrations from src/lib/migrations.ts. Migrations also run automatically on every openDatabase; this command is for one-shot ops + dry-run inspection.",
    flags: [
      { name: "--dry-run", description: "Print the pending queue without applying anything." },
    ],
  },
  {
    command: "db indexes",
    summary: "Ops introspection over the SQLite catalog: list every index (with table, columns, unique/partial flags, original CREATE INDEX SQL); optionally EXPLAIN QUERY PLAN for a SQL string; optionally suggest under-indexed tables.",
    flags: [
      { name: "--explain", description: "SQL string. Runs EXPLAIN QUERY PLAN and includes the steps in the response." },
      { name: "--suggest", description: "true to include a suggestions[] array — user tables with > --suggest-threshold rows and zero user-created indexes." },
      { name: "--suggest-threshold", description: "Row count above which a table is considered for suggestions (default 1000)." },
    ],
  },
  {
    command: "db rotate-keys",
    summary: "Re-issue the local signer keypair (RSA 2048 + self-signed cert). Backs up the old cert+key with a timestamped suffix in the same directory so previously-issued receipts stay verifiable. Limitation: existing receipt manifests stay signed by the old key — re-signing every prior receipt is a separate operation, not yet implemented.",
    flags: [
      { name: "--key-dir", description: "Directory holding signer.key.pem + signer.cert.pem (default ./data/local-keys, overridable via SIGN_LOCAL_KEY_DIR)." },
      { name: "--re-sign-receipts", description: "true to walk every previously-issued receipt (sourced from request.receipt_signed audit events) and re-sign each manifest with the new key — overwrites manifest.sig + manifest.cert.pem, appends request.receipt_resigned per row. Receipt directories that have moved or been deleted are reported as failures, not aborts." },
    ],
  },
  {
    command: "db vacuum",
    summary: "Reclaim space + refresh planner stats. SQLite: VACUUM + PRAGMA optimize, reports pages/bytes before/after. Postgres: VACUUM ANALYZE. Both block writers briefly; pick a maintenance window.",
    flags: [
      { name: "--backend", description: "sqlite (default) or postgres." },
      { name: "--pg-url", description: "postgres://… connection string (when --backend postgres; defaults to SIGN_PG_URL)." },
    ],
  },
  {
    command: "db indexes-postgres",
    summary: "Postgres companion to `db indexes`. Reads pg_indexes / pg_class for the active connection, runs EXPLAIN (FORMAT JSON), and uses pg_class.reltuples for cheap row-count estimates in the suggestions heuristic.",
    flags: [
      { name: "--pg-url", description: "postgres://… connection string (defaults to SIGN_PG_URL)." },
      { name: "--schema", description: "Schema to scan (default public)." },
      { name: "--explain", description: "SQL string. Runs EXPLAIN (FORMAT JSON) and includes the plan tree." },
      { name: "--suggest", description: "true to include a suggestions[] array of under-indexed tables (uses pg_class.reltuples; run ANALYZE first if numbers look stale)." },
      { name: "--suggest-threshold", description: "Row-estimate threshold (default 1000)." },
    ],
  },
  {
    command: "db migrate-postgres",
    summary: "One-shot Postgres bootstrap: connects to --pg-url, creates the ported schema (CREATE TABLE IF NOT EXISTS) and the audit_events append-only triggers via PL/pgSQL. Idempotent — safe to re-run.",
    flags: [
      { name: "--pg-url", description: "postgres://… connection string (defaults to SIGN_PG_URL)." },
    ],
  },
  {
    command: "db postgres-smoke",
    summary: "End-to-end integration probe for the Postgres async path. Bootstraps the schema, inserts a synthetic request, extends a 3-event audit chain via appendAuditEventAsync, then verifies it via verifyAuditChainAsync + listAuditEventsAsync + searchAuditEventsAsync. Exits 3 on any step failure. Use this to confirm a fresh Postgres deployment is wired up end-to-end before pointing real workload at it.",
    flags: [
      { name: "--pg-url", description: "postgres://… connection string (defaults to SIGN_PG_URL)." },
    ],
  },
  {
    command: "db backend",
    summary: "Report the active storage backend (sqlite | postgres).",
    flags: [{ name: "--backend", description: "Override SIGN_DB_BACKEND for this call." }],
  },
  {
    command: "mcp serve",
    summary: "Stdio Model Context Protocol server (tools + resources for LLM agents). --read-only blocks lifecycle-mutating tools (sign, signer_decline) with FORBIDDEN_READ_ONLY — same shape as the HTTP --read-only knob.",
    flags: [
      { name: "--read-only", description: "true to block the sign + signer_decline tools with code FORBIDDEN_READ_ONLY. Read tools (signer_list, request_show, audit_verify, …) stay available." },
      { name: "--tool", description: "Repeatable. Restrict tools/list + tools/call to the named subset — anything outside returns the same UNKNOWN_TOOL envelope as a real unknown tool, so an agent can't probe for hidden capabilities. Useful for least-privilege agent loops." },
      { name: "--capability", description: "Repeatable: tools / resources / prompts. Advertises only the named capabilities at initialize; disabled capabilities answer their list/read methods with INVALID_ARGS. Useful when an agent only needs one surface (e.g. tools-only)." },
      { name: "--emit-events", description: "Append every JSON-RPC message (in/out) to this file as NDJSON ({ direction, at, message }). Compliance-grade replay log — pair with a strict file ACL." },
      { name: "--emit-events-redact", description: "true to mask token-shaped fields (token, token_hash, token_hint, authorization, bearer, api_key) in the log before they're written. Wire bytes to the client are unchanged." },
    ],
  },
  {
    command: "serve",
    summary: "HTTP REST surface mirroring the MCP tools for non-MCP clients. Bearer auth via --auth-token or SIGN_HTTP_AUTH_TOKEN. --tls-cert + --tls-key flips to https.",
    flags: [
      { name: "--port", description: "Port to bind (default 4000)." },
      { name: "--bind", description: "Bind address (default 127.0.0.1)." },
      { name: "--auth-token", description: "Required Bearer token; falls back to SIGN_HTTP_AUTH_TOKEN env var." },
      { name: "--tls-cert", description: "TLS server certificate PEM path (with --tls-key, listens on https)." },
      { name: "--tls-key", description: "TLS private key PEM path." },
      { name: "--tls-ca", description: "Optional CA bundle PEM (forwarded to https.createServer)." },
      { name: "--web-demo", description: "true to serve the bundled dashboard from fixtures/web-demo, or a path to your own static dir. Mounts at /web-demo/index.html, same-origin (no CORS)." },
      { name: "--rate-limit", description: "Tokens per second per IP (token bucket). Over-budget requests get 429 with Retry-After. Keys on the socket peer address by default; pass --trust-proxy to honor X-Forwarded-For behind a trusted reverse proxy." },
      { name: "--rate-limit-burst", description: "Bucket capacity (max burst). Defaults to 2× --rate-limit." },
      { name: "--trust-proxy", description: "true to key the rate-limiter on the first X-Forwarded-For hop. Set ONLY when a trusted reverse proxy rewrites XFF — otherwise clients can spoof it to bypass the limit and exhaust memory." },
      { name: "--read-only", description: "true to block the four lifecycle-mutating routes (POST /v1/sign, /v1/signer/decline, /v1/signer/reissue-token, /v1/request/receipt) with HTTP 403 + code FORBIDDEN_READ_ONLY. Read endpoints stay available — useful for compliance or production-clone dashboards." },
    ],
  },
  {
    command: "mcp tools",
    summary: "Print the MCP tool catalog without starting the server. Each tool ships an inputSchema; tools that return structured responses also ship an outputSchema so generic agent loops can validate without per-tool code.",
    flags: [
      { name: "--format", description: "json (default) or markdown — markdown renders a docs page including input + output schemas." },
    ],
  },
  {
    command: "metrics show",
    summary: "Render Prometheus text from the local DB and write it to stdout. Same body as GET /v1/metrics, no server required.",
  },
  {
    command: "metrics ship",
    summary: "Long-running pusher that POSTs the Prometheus text to a remote endpoint on a cadence. Exits cleanly on SIGINT/SIGTERM. Errors don't crash the loop — backs off (capped at 10× the base interval) instead.",
    flags: [
      { name: "--url", required: true, description: "Endpoint that accepts POST text/plain (e.g. a Prometheus pushgateway-equivalent)." },
      { name: "--bearer", description: "Optional Bearer token; sent as Authorization header." },
      { name: "--header", description: "Repeatable. KEY=VALUE pairs added to each request." },
      { name: "--interval-seconds", description: "Cadence between pushes (default 30)." },
      { name: "--max-pushes", description: "Stop after this many pushes — useful for scripted runs." },
      { name: "--batch-size", description: "Render every interval, but POST every Nth interval. The body bundles N snapshots separated by `# BATCH BOUNDARY <iso>` comment lines. Same data volume, N× fewer round-trips." },
    ],
  },
  {
    command: "completion",
    summary: "Print a shell completion script (bash | zsh | fish).",
  },
  {
    command: "examples",
    summary: "Curated walkthrough snippets for the most common flows.",
  },
];

export function findCommand(query: string): CommandSpec | null {
  const normalized = query.trim().replace(/\s+/gu, " ");
  return HELP_CATALOG.find((entry) => entry.command === normalized) ?? null;
}

// A parent command like "mcp" has no entry of its own, but "mcp serve" / "mcp tools"
// do. Return those subcommands so `sign mcp --help` lists them instead of erroring.
export function findCommandGroup(query: string): CommandSpec[] {
  const prefix = query.trim().replace(/\s+/gu, " ") + " ";
  return HELP_CATALOG.filter((entry) => entry.command.startsWith(prefix));
}

export function formatCommandGroupHelp(query: string, specs: CommandSpec[]): string {
  const lines: string[] = [`sign ${query} — subcommands`, ""];
  for (const spec of specs) {
    lines.push(`  sign ${spec.command.padEnd(28)}  ${spec.summary}`);
  }
  lines.push("", "Run `sign <command> --help` for focused help on any subcommand.");
  return lines.join("\n");
}

export function formatTopLevelHelp(): string {
  const lines: string[] = ["sign — consent-gated, auditable e-sign CLI", ""];
  // Group by first word for readability.
  const buckets = new Map<string, CommandSpec[]>();
  for (const cmd of HELP_CATALOG) {
    const root = cmd.command.split(" ")[0];
    if (!buckets.has(root)) buckets.set(root, []);
    buckets.get(root)!.push(cmd);
  }
  for (const [root, list] of buckets) {
    lines.push(`# ${root}`);
    for (const cmd of list) {
      lines.push(`  sign ${cmd.command.padEnd(28)}  ${cmd.summary}`);
    }
    lines.push("");
  }
  lines.push("Run `sign <command> --help` for focused help on any command.");
  lines.push("Run `sign --catalog json` for a machine-readable catalog.");
  return lines.join("\n");
}

export function formatCommandHelp(spec: CommandSpec): string {
  const lines: string[] = [`sign ${spec.command}`, "", spec.summary];
  if (spec.flags && spec.flags.length > 0) {
    lines.push("", "Flags:");
    for (const flag of spec.flags) {
      const tag = flag.required ? " (required)" : "";
      lines.push(`  ${flag.name.padEnd(28)}  ${flag.description}${tag}`);
    }
  }
  if (spec.example) {
    lines.push("", "Example:");
    for (const line of spec.example.split("\n")) {
      lines.push(`  ${line}`);
    }
  }
  return lines.join("\n");
}

export function buildCatalogJson(): {
  name: string;
  bin: string;
  version: string;
  description: string;
  commands: Array<{ name: string; help: string } & Partial<Pick<CommandSpec, "flags" | "example">>>;
  exitCodes: Record<string, string>;
} {
  return {
    // Shared suite catalog contract: name/bin/version/description/commands/exitCodes
    // (matches draft-cli, compare-cli, docx2pdf-cli, template-vault-cli, nda-review-cli).
    name: "sign-cli",
    bin: "sign",
    version: SIGN_CLI_VERSION,
    description: "Consent-gated, auditable e-sign CLI.",
    commands: HELP_CATALOG.map((cmd) => ({
      name: cmd.command,
      help: cmd.summary,
      ...(cmd.flags ? { flags: cmd.flags } : {}),
      ...(cmd.example ? { example: cmd.example } : {}),
    })),
    exitCodes: {
      "0": "success",
      "2": "invalid input (missing/malformed flag, schema fail)",
      "3": "policy / chain / verification failed",
      "4": "not found / out of range",
    },
  };
}

export const EXAMPLE_WALKTHROUGHS: Array<{ title: string; commands: string[] }> = [
  {
    title: "Local-provider sanity check",
    commands: [
      "sign demo --out ./demo-bundle",
      "ls demo-bundle/  # signed.pdf, audit.json, manifest.json",
    ],
  },
  {
    title: "Two-signer NDA, agent-as-signer",
    commands: [
      `sign request create --title "Mutual NDA" --document ./nda.pdf \\
  --signer name:Alice,email:alice@example.com,order:1 \\
  --signer name:Bob,email:bob@example.com,order:2 \\
  --provider local --auto-approve true`,
      "sign request send --request-id <id> --provider local",
      "# requester DMs each signer their token from tokens[]",
      "",
      "# Alice's agent:",
      "sign signer list --signer-email alice@example.com",
      "sign signer fetch-document --request-id <id> --token alice-tok-... --out ./nda-review.pdf",
      "sign sign --request-id <id> --token alice-tok-... \\",
      `  --require-hash <expected-sha256> --require-title "^Mutual NDA$"`,
    ],
  },
  {
    title: "Declarative policy enforcement",
    commands: [
      "cat > policy.json <<'JSON'",
      `{"expectations":{"titleMatches":"^Mutual NDA"},"rules":[{"match":"any","action":"sign"}]}`,
      "JSON",
      "sign signer policy run --request-id <id> --token alice-tok-... --spec ./policy.json",
    ],
  },
  {
    title: "Cryptographic receipt for compliance",
    commands: [
      "sign request receipt --request-id <id> --out ./receipt/",
      `openssl dgst -sha256 \\
  -verify <(openssl x509 -pubkey -noout -in receipt/manifest.cert.pem) \\
  -signature receipt/manifest.sig receipt/manifest.json`,
    ],
  },
  {
    title: "MCP server for an LLM agent",
    commands: [
      'export SIGN_LOCAL_AUTOCOMPLETE=false',
      "sign mcp serve  # stdio; pipe a Claude Desktop / Code session here",
      "sign mcp tools  # one-shot tool catalog (no server)",
    ],
  },
  {
    title: "Spec template + variable substitution",
    commands: [
      "sign request create --spec ./fixtures/request-spec.example.json \\",
      "  --param counterparty=alice@example.com --param name=Alice",
    ],
  },
  {
    title: "Webhook ingestion (hosted providers)",
    commands: [
      "sign webhook listen --provider signwell --port 3000",
      "# in another terminal:",
      "sign request show --request-id <id>  # signedBy[] now reflects hosted-provider state",
    ],
  },
];

export function formatExamples(): string {
  const lines: string[] = ["sign — common flow walkthroughs", ""];
  for (const example of EXAMPLE_WALKTHROUGHS) {
    lines.push(`# ${example.title}`);
    for (const command of example.commands) {
      lines.push(command);
    }
    lines.push("");
  }
  return lines.join("\n");
}
