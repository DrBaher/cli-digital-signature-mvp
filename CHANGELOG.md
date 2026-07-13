# Changelog

All notable changes to `sign-cli`. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning follows [Semantic Versioning](https://semver.org/).

`scripts/changelog.mjs` prints a Keep-a-Changelog-shaped block for commits
since the last tag — use it to seed the `[Unreleased]` section before a
release.

## [Unreleased]

### Added
- **Consent capture**: `request create --require-consent true` gates signing on
  each signer attesting intent-to-sign and accepting the electronic-records
  (ESIGN) disclosure via `approve --agree true --accept-disclosure true`. The
  canonical statement texts are versioned (`sign consent show`) and recorded in
  the audit chain (`request.consent_captured`, `request.esign_consent_captured`)
  with their SHA-256 and timestamp.
- **Signer email verification**: `request create --require-email-verification
  true` gates signing on proof of mailbox control. New commands `signer
  send-verification` (6-digit code, hashed at rest, 15-min TTL, 5-attempt
  lockout, optional delivery via `SIGN_VERIFICATION_WEBHOOK_URL`) and `signer
  verify-email`; `approve --verification-code` redeems in one step. Audit
  events: `request.signer_verification_issued`, `request.signer_email_verified`.
- **Identity-assurance records**: `signer record-identity --identity-assurance
  method:...,verifier:...,reference:...` (also inline on `approve`) records how
  a signer's identity was checked out-of-band — the assertion, never the
  evidence — as `request.identity_assurance_recorded`.
- Both gates are enforced in the shared signing service, so the CLI `sign`
  command, MCP `sign` tool, and `POST /v1/sign` all honor them; combining them
  with `--auto-approve` is rejected. `request show` now includes a per-signer
  `consent` block. New docs: `docs/reference/consent-and-identity.md`.

### Changed
- **`sign demo` now showcases the consent flow.** Both gates are enabled on the
  demo request; the demo drives real blocked sign attempts
  (`EMAIL_VERIFICATION_REQUIRED`, `CONSENT_REQUIRED`), verifies the signer
  email, captures the consent attestations + an identity-assurance record, then
  approves and signs through the token path (no more `--auto-approve` +
  provider auto-complete). The result gains a `consent` block; any configured
  `SIGN_VERIFICATION_WEBHOOK_URL` is ignored during the demo so codes never
  leave the machine.

## [0.8.0] — 2026-06-21

SignWell field-placement fixes from field feedback, plus signing-order control,
a test-mode safety banner, and the field-coordinate contract.

### Added

- **`--ordered true|false`** on `request send`, `request run-email`, and `request send-embedded` — controls SignWell `apply_signing_order`. `false` requests parallel/unordered signing; default stays sequential when there are 2+ signers.
- **`bottomLeftToTopLeft()`** helper in `field-placement` + **[`docs/field-coordinates.md`](docs/field-coordinates.md)** — documents the per-provider `--field` coordinate contract (top-left origin; 1-based `page`/`signer` vs 0-based `doc`) and converts bottom-left/pdfjs detector coordinates to provider space.
- Loud **SignWell test-mode banner** on every send. Test mode stays the default (non-binding, watermarked) but is no longer silent: a prominent stderr banner fires whenever it's active, pointing at `--test-mode false`. Suppressed when test mode is off.

### Fixed

- **SignWell: custom `--field` placements were silently dropped.** `with_signature_page` was hardcoded `true`, which makes SignWell discard supplied fields and auto-place its own. It is now `false` whenever custom fields are present.
- **SignWell: fields were sent in the wrong place in the payload.** Fields were nested under `files[].fields`; SignWell requires a top-level 2-D `fields` array (one inner array per file). With both fixes, custom placements reach SignWell instead of being silently dropped (or rejected with `recipients.with_no_fields`). Adds a payload-level regression test.
- **Stray `ExperimentalWarning: SQLite` no longer clutters stderr.** `node:sqlite` is loaded lazily and the warning is filtered (set `SIGN_SHOW_WARNINGS=1` to restore it), keeping machine-readable output clean.
- **`sign mcp --help` now lists subcommands** (`mcp serve`, `mcp tools`) instead of erroring with "No help entry for mcp". Applies to any parent command.

### Changed

- `--field` help now documents `width`, `height`, the full `type:` set (`signature|initials|date|text|name|email`), the 0-based `doc` vs 1-based `page`/`signer` indexing, and points at `docs/field-coordinates.md`. Send commands document `--ordered` and `--test-mode`.

## [0.7.1] — 2026-06-03

Build-tooling only — **no runtime or API changes** from 0.7.0. Cut so the SEA
binary fix lands in a tagged release (the release job builds binaries from the
tag's checkout, so the 0.7.0 binaries could not be produced retroactively).

### Fixed
- **`npm run build:sea` now succeeds and produces runnable binaries.** The
  `postject` injection passed a non-existent `sentinelFusesPath` option, so it
  defaulted to `POSTJECT_SENTINEL_<hash>` (absent from the Node binary) and failed
  with "Could not find the sentinel …". It now passes the correct
  `NODE_SEA_FUSE_<hash>` sentinel. On macOS the inherited code signature, which
  injection invalidates, is now stripped before injection and ad-hoc re-signed
  after, so the binary is no longer `SIGKILL`ed at launch.
- **Release `publish-npm` is now idempotent** — it skips when the version is
  already on npm, so re-dispatching a release to rebuild artifacts no longer fails
  on a duplicate-version error.

## [0.7.0] — 2026-06-03

Security release. PDF signature verification is now genuinely cryptographic, and the MCP/HTTP surfaces are hardened against secret exfiltration, path traversal, and DoS. **Read the "Security — breaking" notes below before upgrading: documents that previously verified `ok` against a forged or non-cryptographic signature will now correctly FAIL, and the MCP HTTP server now binds to loopback by default.** Bundles the offline-`local` provider default from the prior Unreleased entry.

### Security — breaking

- **PDF signature `verify` is now cryptographic.** `inspectPdfSignatures` previously only checked that the embedded `messageDigest` equalled the SHA-256 of the signed byte range — it never verified the PKCS#7/CMS signature value against the signer certificate's public key. A fully forged PKCS#7 (no private key) reported `verdict=ok` / exit 0. Verification now runs the real RSA/ECDSA `createVerify` against the signed attributes and binds the cert to the signature. **Forged or non-cryptographically-signed PDFs that used to pass will now fail (`verdict` ≠ `ok`, non-zero exit).** This is the intended correction of a core-promise defect; if a previously-"valid" PDF now fails, it was never cryptographically signed.
- **MCP HTTP server now binds `127.0.0.1` by default (was `0.0.0.0`).** `sign mcp serve --http` no longer listens on all interfaces unless you pass `--http-bind 0.0.0.0` explicitly. The hosted container entrypoint (`deploy/entrypoint-mcp-http.sh`) already passes `--http-bind 0.0.0.0`, so Railway/hosted deployments are unaffected; local/embedded runs are no longer exposed to the LAN by default.
- **`profile_show` no longer returns secrets without authentication.** The MCP `profile_show {show_secrets:true}` tool (and the HTTP path) now require an authenticated session; over HTTP that means a configured `--http-auth-token`. Previously provider API keys were reachable unauthenticated on the default bind.
- **`signer_fetch_document` absolute output paths are gated.** Writing a fetched document to an absolute path now requires `SIGN_ALLOW_ABSOLUTE_DOCS=1` and is refused entirely in `--read-only` mode; relative paths resolve under the working dir as before.

### Fixed

- Receipt/bundle verification no longer trusts an unpinned re-signed head: trust anchors are checked so a re-signed bundle can't verify `ok` against a different key.
- Hardened several MCP/HTTP read paths against path-traversal arbitrary-read oracles (bundle/receipt fetch), tightened webhook pre-auth DB lookups and 500-vs-400 error mapping, and bounded the HTTP rate-limiter (XFF-spoof bypass + unbounded-bucket DoS).

### Changed

- **Built-in default provider is now `local` (offline), not `dropbox`.** When no `--provider` flag, `SIGN_PROVIDER` env, or profile provider is set, commands now resolve to the fully-offline `local` PAdES signer instead of Dropbox Sign. Previously a brand-new user's first mutating command (`request create`/`send`) failed with `DROPBOX_SIGN_API_KEY is not set` — demanding hosted-provider credentials they never configured, despite the product's "no signup, no keys" promise. The resolution order is unchanged (`flag > env > project profile > user profile > built-in default`); only the final fallback changed. Users on a hosted provider via `--provider`, `SIGN_PROVIDER`, or a profile are unaffected. `.env.example` now ships `SIGN_PROVIDER=local`.
- `SIGN_CLI_VERSION` (drives `--version` and `--catalog`) corrected to track the package version; it had drifted to `0.6.4` while the published package was `0.6.5`.

## [0.6.4] — 2026-05-16

Fix-only release. The v0.6.3 npm tarball shipped `mcpName` as `io.github.drbaher/sign-cli` (lowercase), but the official MCP registry namespaces by GitHub login (`DrBaher`) and rejected the publish. v0.6.4 corrects the casing in `package.json` and `server.json` so the registry submission succeeds — every other surface is unchanged.

### Fixed

- `package.json` `mcpName` and `server.json` `name` now use `io.github.DrBaher/sign-cli`. The MCP registry validates the npm tarball's `mcpName` field against the GitHub login (case-sensitive), so the previous lowercase value blocked the registry publish even after the npm publish succeeded.

## [0.6.3] — 2026-05-16

Headline: **`sign mcp serve --http`** — second MCP transport that speaks JSON-RPC 2.0 over HTTP, so the same 19 tools / 4 prompts / 12 resources can be reached from remote MCP aggregators (Smithery, OpenAI Agents SDK over HTTP, custom services) without spawning a local `npx` process. Stdio remains the default. Listed on Smithery at [`drbaher/sign-cli`](https://smithery.ai/server/drbaher/sign-cli).

### Added

- **`sign mcp serve --http true`** — boots the MCP server over `node:http` instead of stdio. Flags: `--http-port` (default `$PORT` or `8080`), `--http-bind` (default `0.0.0.0`), `--http-path` (default `/mcp`), `--http-auth-token` (also reads `$SIGN_MCP_HTTP_AUTH_TOKEN`). CORS open, OPTIONS preflight handled, 1 MiB max body, JSON-RPC dispatched through the same code path as stdio (so `--read-only`, `--capability`, `--tool` allow-lists, `--emit-events` all apply). `GET /health` returns `{ ok, mcp, endpoint }` and is always unauthenticated. When a bearer token is set, every `/mcp` request must include `Authorization: Bearer <token>`; mismatched/missing tokens get a 401 with `WWW-Authenticate: Bearer realm="sign-cli MCP"`.
- **`deploy/Dockerfile.mcp-http` + `entrypoint-mcp-http.sh`** — hosted container variant that runs `sign mcp serve --http` on `$PORT`. Read-only + ephemeral SQLite + 4h TTL reset, same demo-safety model as the existing `serve` container. Powers [sign-cli-mcp-production.up.railway.app/mcp](https://sign-cli-mcp-production.up.railway.app/mcp).

### Changed

- `deploy/Dockerfile` and `Dockerfile.mcp-http` now copy `scripts/` **before** `npm install` so the postinstall `trim-pdfjs-dist.mjs` step can find itself. Fixes silent build breakage introduced when the postinstall hook was added.
- `railway.toml` no longer pins `dockerfilePath`; each service selects its Dockerfile via the `RAILWAY_DOCKERFILE_PATH` env variable. This lets the same repo deploy both `sign-cli-demo` (HTTP `/v1/*`) and `sign-cli-mcp` (MCP-over-HTTP) services from one config.

### Fixed

- `signer_list`'s `outputSchema` was the only tool whose top-level `type` was `"array"`. Per the MCP spec and Smithery's scanner, `outputSchema.type` must be `"object"` (it describes `structuredContent`, which is always an object). Dropped the schema annotation for this one tool rather than wrapping the wire payload — the actual JSON-RPC response shape is unchanged for existing clients.

## [0.6.2] — 2026-05-15

Headline: published to npm under the scoped name **`@drbaher/sign-cli`**. The unscoped `sign-cli` on npm was registered by someone unrelated to this project before this codebase existed. To avoid confusion (and because npm doesn't allow taking over a name owned by another account), this CLI now lives at `@drbaher/sign-cli`. The repo name (`DrBaher/sign-cli`), the bin name (`sign`), and the project identity are unchanged.

### Changed

- `package.json` `name` field: `"sign-cli"` → `"@drbaher/sign-cli"`.
- Install commands across README, AGENTS.md, DISTRIBUTION.md, docs/, and the showcase site now use the scoped name.
- The bin name is **still `sign`** — once installed globally (`npm i -g @drbaher/sign-cli`), every CLI invocation works identically (`sign demo`, `sign request create`, etc.).

### Migration

```bash
# If you previously installed the unrelated `sign-cli` package, uninstall it first:
npm uninstall -g sign-cli

# Install ours:
npm i -g @drbaher/sign-cli
sign --version    # → 0.6.2
```

## [0.6.1] — 2026-05-15

Headline: **`sign pdf inspect`** — verify ANY signed PDF (ours, Adobe's, DocuSign's, Dropbox Sign's, SignWell's). Pairs with `request verify-signed-pdf` for the request-bound check. **Pre-sign signature visibility** on `signer fetch-document` so signers see what they're countersigning. **`--recipient <email>`** filter on `verify-signed-pdf` for mid-flight multi-signer verification. Fixes a false `signer_mismatch` on RFC 4514-escaped certificate subjects.

### Added

- **`sign pdf inspect`** — new top-level command that inspects PADES signatures on ANY signed PDF (ours, Adobe's, DocuSign's, Dropbox Sign's, SignWell's). Returns per-signature signer CN/email, cert subject + issuer, validity window, fingerprint, trust label (`self_signed_local` / `self_signed_other` / `ca_signed` / `unknown`), message-digest match, and parse warnings. Pure read — no DB interaction, no audit events. Exit `2` when the PDF has no signatures. Pairs with `request verify-signed-pdf` (which adds request-level signer-match against the local DB); use `pdf inspect` when you don't have a request to bind against (e.g. inspecting an incoming counterparty PDF). Trust label is structural (issuer vs subject); no chain validation, no expiry check. Companion: new MCP tool `pdf_inspect_signatures` and HTTP route `POST /v1/pdf/inspect-signatures` — same `validateDocumentPath` guard as the other PDF surfaces.
- **Pre-sign signature visibility** — `signer fetch-document` (CLI + MCP `signer_fetch_document` + HTTP `POST /v1/signer/fetch-document`) now includes an `existingSignatures` field in every response: a compact summary of any PADES signatures already on the PDF when the signer fetches it. Fields: `count`, `hasSignature`, `allDigestsOk` (false if any prior signature is broken — tamper or parse failure), `signers[]` (subject / issuer / validity / fingerprint / trust / per-signer digestOk), `warnings[]`. Best-effort: if inspection throws on a malformed PDF, the field is populated with a degenerate summary plus a warning rather than failing the fetch. Same surface is added to `sign document`'s result for PDF (non-DOCX) inputs.
- **`request verify-signed-pdf --recipient <email>`** — narrows the `signer_match` check to a single recipient instead of requiring the full persisted-signer roster. Mirrors the semantics of `request show --recipient`. Useful mid-flight on multi-signer requests (verify Alice's signature without failing because Bob hasn't signed yet). Refuses unknown recipients with `SIGNER_NOT_RECIPIENT` rather than silently passing on vacuous truth. The flag was previously silent on this subcommand — that gap is now closed; `--help` and `--catalog json` list it.

### Fixed

- **`request verify-signed-pdf` no longer falsely reports `signer_mismatch` against per-signer certs** — Node's `X509Certificate.subject` returns the RFC 4514 / LDAP DN string, which backslash-escapes reserved chars (`+`, `<`, `>`, `,`). A per-signer cert subject like `CN=Baher Test \<baher\+dcc@example.com\>` was being compared with a raw `subject.includes("baher+dcc@example.com")` and failing — even though the signature was cryptographically valid (`digest_ok: true`). The matcher now strips backslash escapes before the substring check. Surfaced by a real-world signing test against GBrain agreements on 2026-05-14. Regression test in `verify-summary.test.ts` asserts an RFC 4514-escaped subject matches.

### Docs

- **Doc reorg: `AGENTS.md` + `docs/setup/` + `docs/reference/`** — adopts the shared three-file shape used across the three-CLI suite. README trimmed from 703 to ~280 lines by extracting provider setup into `docs/setup/{dropbox,docusign,signwell,embedded,providers}.md` and concept docs into `docs/reference/{architecture,audit-chain,exit-codes,profiles,security-controls,security-model,legal,comparison}.md`. New `AGENTS.md` is the agent quickstart (output contract / exit-code table / discovery commands / failure → recovery). Removed `ONBOARDING.md` and `CHECKLIST.md` (redundant with the new structure). `scripts/lint-legal-claims.mjs` and the affected tests updated for the new paths.

## [0.6.0] — 2026-05-14

Headline: cross-surface parity (every CLI command that has any of MCP / HTTP / both has them all), the profile system (named bundles of provider + dbPath + credentials), security-grade path-traversal guards on every input/output flag, and a structured `STORAGE_UNWRITABLE` error code in place of raw Node EACCES stack traces.

### Added

- **API parity: 7 new HTTP routes + 3 new MCP tools** ([#178](https://github.com/DrBaher/sign-cli/pull/178)) — closes the cross-surface gap surfaced by the second-round audit. **HTTP** gains `POST /v1/pdf/detect-signature-field`, `POST /v1/pdf/detect-date-field`, `POST /v1/pdf/stamp-text`, `POST /v1/preview`, `POST /v1/document`, `POST /v1/profile/list`, `POST /v1/profile/show` — every new MCP tool now has a REST equivalent with the same input shape, same `validateDocumentPath` / `validateOutputPath` guards, same `READ_ONLY_BLOCKED_ROUTES` gating for the three mutating ones. **MCP** gains `signer_reissue_token`, `audit_scan`, `request_receipt` — every HTTP-only route now has an MCP tool. `signer_reissue_token` and `request_receipt` join `READ_ONLY_BLOCKED_TOOLS`; `audit_scan` is read-only. OpenAPI spec (`GET /v1/openapi.json`) updated. Coverage: new `api-parity.test.ts` (12 tests) + updated `serve-read-only.test.ts` and `mcp-server.test.ts` exhaustive assertions.

- **Security: input-path traversal guard on PDF/document inputs** ([#177](https://github.com/DrBaher/sign-cli/pull/177)) — `sign pdf stamp`, `sign pdf stamp verify`, `sign pdf stamp-text`, `sign pdf detect-signature-field`, `sign pdf detect-date-field`, `sign preview`, and `sign document` now run `validateDocumentPath` on the `--pdf` / `--input` flag. Same `SIGN_ALLOW_ABSOLUTE_DOCS=1` opt-in as the existing output-path validator. The corresponding MCP tools (`pdf_detect_signature_field`, `pdf_detect_date_field`, `pdf_stamp_text`, `preview`, `document`) inherit the guard. Closes the parity gap with output-path validation: a malicious or buggy MCP client can no longer coax the server into reading arbitrary files via `pdf_path` or laundering an arbitrary file through `document`'s convert+stamp+seal pipeline. Regression coverage in `mcp-new-tools.test.ts` (input-path traversal across four tools).
- **Docs coverage for new MCP tools + new error codes** ([#177](https://github.com/DrBaher/sign-cli/pull/177), [#181](https://github.com/DrBaher/sign-cli/pull/181)) — `docs/agent-guide.md` §3 now lists every MCP tool name (split read-only vs mutating) with a "don't hardcode" note pointing at `sign mcp tools`; §1 error-codes table adds `STORAGE_UNWRITABLE` and `PROFILE_ENV_VAR_UNSET`; §7 Decision recipes adds rules for "escapes the working directory" path errors and the `SIGN_ALLOW_ABSOLUTE_DOCS` opt-in. `docs/recipes/agent-loop-mcp.md` regenerates the tool name list to match the catalog. `TROUBLESHOOTING.md` adds rows for `Output path escapes`, `Config path "..." is outside both $HOME`, `STORAGE_UNWRITABLE`, and `PROFILE_ENV_VAR_UNSET`. README also refreshed: MCP tool count and HTTP routes list now reflect the full 18+20 surface, with a profile + traversal-guard mention in the agent TL;DR.

- **MCP surface: seven new tools** ([#177](https://github.com/DrBaher/sign-cli/pull/177)) — `pdf_detect_signature_field`, `pdf_detect_date_field`, `profile_list`, `profile_show` (all read-only), and `pdf_stamp_text`, `preview`, `document` (mutating; gated by the existing `READ_ONLY_BLOCKED_TOOLS` set when `mcp serve --read-only true`). Wraps the same CLI handlers byte-for-byte, including `validateOutputPath` for every write — so an agent calling `document` over MCP gets the same path-traversal protection that `sign document --out` already has. `profile_show` redacts credentials by default; pass `show_secrets: true` to reveal. The existing `sign` tool's `outputSchema` is corrected to match `SignerSignResult` (was advertising `status` / `signedDocumentPath`, which the handler never returned). Coverage in `mcp-server.test.ts`, `mcp-new-tools.test.ts`, and `mcp-serve-read-only.test.ts`.
- **`STORAGE_UNWRITABLE` error code** ([#177](https://github.com/DrBaher/sign-cli/pull/177)) — `openDatabase` (`src/lib/db.ts`) now wraps `EACCES` / `EROFS` / `EPERM` from the parent-directory `mkdirSync` into a structured `SignCliError` with a code, message naming the unwritable directory, and a hint pointing at `SIGN_DB_PATH`, `~/.sign-cli/`, or a profile `dbPath`. Replaces a raw Node.js stack trace with an agent-actionable envelope. Test in `db-eacces.test.ts`.
- **`validateConfigPath` helper for profile-stored paths** ([#177](https://github.com/DrBaher/sign-cli/pull/177)) — new validator in `src/lib/validate.ts`, used by `sign profile init --db <path>`. Permissive about home-relative paths (`~/.sign-cli/prod.db` resolves without the opt-in, since that's the canonical example) and CWD-relative paths; rejects paths outside both `$HOME` and CWD unless `SIGN_ALLOW_ABSOLUTE_DOCS=1`. Same toggle as the existing input/output path validators — one knob for "let me touch paths outside the working directory." Coverage in `validate.test.ts`.

- **Security: path-traversal guard on output paths** ([#176](https://github.com/DrBaher/sign-cli/pull/176)) — `sign pdf stamp`, `sign pdf stamp-text`, `sign preview`, and `sign document` now reject `--out` paths that escape the working directory. Same `SIGN_ALLOW_ABSOLUTE_DOCS=1` opt-in as the existing input-path validator. Closes a gap where a malicious or buggy caller could write the stamped/sealed PDF anywhere on disk. New helper `validateOutputPath` (`src/lib/validate.ts`); regression test in `validate.test.ts` plus an end-to-end check in `preview-command.test.ts`.
- **Security: profile credentials now flow through the error-message redactor** ([#176](https://github.com/DrBaher/sign-cli/pull/176)) — `applyCredentialsToProcessEnv` (`src/lib/profiles.ts`) calls `registerSecretKey` for every credential it injects into `process.env`. `collectKnownSecrets` (`src/lib/secret.ts`) merges the dynamic set with its hardcoded list, so an error containing a profile-injected secret like `ACME_API_KEY` gets redacted just like `DROPBOX_SIGN_API_KEY` already was. Closes a gap where custom credential keys leaked in adapter logs and stack traces.
- **Output-shape parity polish across stamping commands** ([#176](https://github.com/DrBaher/sign-cli/pull/176)) — `sign pdf stamp-text` now emits the `warnings` array (matching `pdf stamp` and `sign preview`); `sign preview` now emits `drawnRects` (post-aspect-preserve rectangles, read back from the PDF — matching `sign document`); `sign sign`'s success JSON includes `ok: true` (matching every other command's success envelope). All three are additive; no flag changes; locked in by regression tests.
- **Profiles — `sign profile list / show / use / set / unset / delete / init` + global `--profile <name>` / `SIGN_PROFILE=<name>`** ([#175](https://github.com/DrBaher/sign-cli/pull/175)) — named bundles of provider, `dbPath`, `strictProvider`, `defaultTokenTtlMinutes`, `defaultSignerEmail`, and a `credentials` block. Activated by `--profile`, `SIGN_PROFILE`, the user file's `defaultProfile`, or implicitly via a `sign-profile.json` discovered by walking **upward from CWD** (matches git/npm/pnpm semantics). Resolution order for any field: `flag > env > project profile > user profile > built-in default`. **Atomic credentials** — the layer that resolved `provider` is the only one that contributes credentials; cross-profile reuse via `{{env:VAR}}` references that point at shell-managed secrets. **Unset `{{env:VAR}}` references error loudly** (`PROFILE_ENV_VAR_UNSET`) with a hint naming the missing var. **Schema versioning** with in-place migration chain. `sign profile show` **redacts credentials by default**; pass `--show-secrets true` to reveal resolved values. User file location overridable via `SIGN_PROFILES_FILE`; default is XDG-compliant `$XDG_CONFIG_HOME/sign-cli/profiles.json` (mode `0600`). New error codes: `INVALID_PROFILE`, `INVALID_PROFILE_NAME`, `PROFILE_NOT_FOUND`, `PROFILE_ALREADY_EXISTS`, `PROFILE_ENV_VAR_UNSET`. Provider banner gains new source strings: `via active profile`, `via project sign-profile.json`. `sign doctor preflight` adds a `profile:active` check. See `docs/profiles-design.md` for the full rationale and `docs/agent-guide.md` §6.7 for usage.

- **`sign doctor preflight`** — structured per-check report on `sign doctor preflight` (subcommand). Each check is `{ name: "<category>:<specific>", status: "ok"|"failed"|"skipped", detail, hint? }`; the wrapping object is `{ provider, summary: { passed, failed, skipped, verdict: "ok"|"failed" }, checks[] }`. Exit `0` if `verdict == "ok"`, `1` if `verdict == "failed"`. Env-health checks run on every provider: `runtime:node_version` (Node ≥ 22 for `node:sqlite`), `storage:db_path` (`SIGN_DB_PATH` parent writable with a probe-file round-trip, default `./data/sign.db`). Provider-scoped checks layer on: `env:*` (required env vars present), `connectivity:*` (provider API reachable), `permissions:*` (filesystem paths writable + RSA key files exist for DocuSign), `fixture:canonical_unsigned` (for `local`). Bare `sign doctor` (no subcommand) remains the unstructured env-report; always exits 0. Stderr always prints `[sign] preflight: <verdict> (provider=<p>, N ok, N failed, N skipped)` so the one-line summary is grep-able without parsing JSON.
- **`sign workflow nda`** — one command that renders the bundled mutual-NDA template into a PDF and creates a signing request in one shot. Wraps `scripts/render-template.mjs` + `request create`. Flags: `--values <file.json>` (variable map), `--value KEY=VALUE` (repeatable, overrides values), `--party-a-email <addr>`, `--party-b-email <addr>` (both required, must differ), `--template <path>` (override the bundled template), `--out <file>` (PDF output), `--token-ttl-minutes`, `--auto-approve`. Signer names are read from `PARTY_A_SIGNATORY` / `PARTY_B_SIGNATORY` in values. Missing placeholders surface **all** gaps at once before any PDF is written — no half-rendered output. Output includes `templateUsed: "bundled" | "custom"`, the resolved `title`, and the embedded `request.requestId`. Exit `3` on validation errors (same-email, missing placeholders, missing values file).
- **`sign pdf stamp verify`** — confirms a previously-stamped image is at the expected position and size, within a ±1pt tolerance. Pairs with `sign pdf stamp` for CI-time tamper checks: stamp at known coords on send, verify on receipt. Flags: `--pdf <path>`, `--image-page <n>`, `--image-x`, `--image-y`, `--image-width`, `--image-height`. Output: `{ ok, verdict: "ok"|"wrong_position"|"missing"|"out_of_range", found?: { page, x, y, width, height } }`. Exit `0` for `ok`; `3` for `wrong_position` (found ≠ expected, `found` shows the actual coords); `4` for `missing` (no stamp on page) or `out_of_range` (page index ≥ page count).
- **Extended audit export bundle** — `audit export` now emits `bundleVersion: 2` in the manifest. New files alongside the existing `audit.json` / `signed.pdf` / `manifest.json`: `original.pdf` (the unsigned source, byte-identical to the request's input), `README.md` (human-readable handoff with the request ID, signer list, and verify commands), `receipts/<signer-email>.json` (per-signer event subsets filtered by `payload.signerEmail`). All files are sha256'd in `manifest.json`. Per-signer event arrays populate only from signer-action events (`request.signed_by_signer`, `request.signer_declined`, `request.signer_fetched_document`) — an auto-approved-but-never-signed request will have empty per-signer arrays, by design. Separately: `sign request receipt` (always was) still emits the cryptographically-signed `bundleVersion: 1` (with detached `manifest.sig` + `manifest.cert.pem`), and `sign request verify-receipt` re-verifies it — use that when a third party needs to validate the manifest itself without trusting your DB.
- **Trust labels in signed-PDF inspection** — `request verify-signed-pdf` adds a `trust` field to every entry in `signatures[].signers[]`. Values: `"self_signed_local"` (issuer == subject AND issuer matches this CLI's built-in local signer subject string), `"self_signed_other"` (issuer == subject but not from this CLI), `"ca_signed"` (issuer != subject — chains to a different issuer), `"unknown"` (cert parse error or absent). Labels are **structural and descriptive** — there's no trust-store lookup, expiry check, or chain validation built in. For chain validation, use an external verifier; for expiry, read `validTo` on the signer entry.
- **Strict provider mode + resolved-provider banner** — every command that touches a provider prints `[sign] resolved provider: <provider> (<source>)` to stderr on start. `<source>` is one of `via --provider flag`, `via SIGN_PROVIDER env`, `default — no flag, no SIGN_PROVIDER set`. New global flag `--strict-provider true` (or env `SIGN_STRICT_PROVIDER=true`) rejects mismatches between the resolved provider and the request's persisted provider with error code `STRICT_PROVIDER_MISMATCH` and a hint telling the operator which flag to use instead. Resolution order: flag > env > default.
- **`audit verify` per-class exit codes + summary** — `sign audit verify` (the canonical command; there is no top-level `sign verify` alias) emits a one-line summary `{ ok, chainValid, events, signers, ... }` and uses exit codes that distinguish failure kinds: `0` ok, `2` invalid input (missing request, bad flag), `3` chain tampered (events present but `chainValid: false`), `4` request not found. Replaces the previous "0 or 1" coarse codes. Existing JSON shape preserved.
- **Canonical unsigned PDF fixture** — `fixtures/canonical-unsigned-v1.pdf` is a reproducible 1-page A4 PDF for tests and demos that need a clean unsigned input. Regeneration is byte-stable: `node dist/scripts/generate-canonical-unsigned-pdf.js` produces the same sha256 every time. Programmatic accessor: `import { canonicalUnsignedPdfPath } from "./lib/fixtures.js"`. Used as the default `--document` for the new `workflow nda` flow when no template is rendered.
- **`sign document` — one-shot DOCX|PDF → sealed PDF** — single command that takes a `.docx` (or `.doc` / `.odt` / `.rtf` / `.pdf`) input, optionally converts it via the bundled `docx2pdf-cli` companion CLI (auto-selecting an available backend — LibreOffice, Pages, Word, Gotenberg, ConvertAPI, textutil), auto-detects the signature-field rectangle, stamps the signature image, PAdES-seals the result, verifies the audit chain, and writes the final PDF. Output JSON includes both `placements` (where auto-place picked) and `drawnRects` (what was actually drawn after `--preserve-aspect-ratio` shrink-to-fit) so callers can round-trip the rectangle through `pdf stamp verify`. All intermediate state (audit events, signer records, key material) lives in a temp database scoped to the call — the user's main `./data/sign.db` is untouched. Defaults `--auto-place first` for the common single-anchor case. The DOCX-conversion side is a **thin** integration: sign-cli does not re-export `docx2pdf-cli`'s flags (backend selection, fidelity, timeout) — for backend control, run `docx2pdf` directly first and pass the resulting PDF.
- **Date-field detection + `sign pdf stamp-text`** — detection now recognizes date anchors alongside signature anchors. New patterns: `Date:` (with colon required to disambiguate), `Date de signature:`, `Date d'effet:`, `Date d'entrée en vigueur:`. Each `DetectedField` carries `category: "signature" | "date"` so callers can filter. Date candidates also carry `alreadyFilled: true` when a recognizable date string (numeric `12/05/2026`, French `12 mai 2026`, English `May 12, 2026`) sits near the anchor — protects against overwriting existing fills.
  - **`sign pdf detect-date-field`** — new command, sibling of `detect-signature-field`. Returns date candidates with the `alreadyFilled` flag. Exit 2 when none found.
  - **`sign pdf stamp-text`** — new command, sibling of `pdf stamp` for plain text instead of images. Used for stamping dates (or any other plain text content). Supports `--auto-place` with the full selector set (`true`/`first`/`last`/`all`/`page:N`/`index:N`). Filtered to date candidates. By default skips `alreadyFilled` candidates; pass `--overwrite-filled true` to include them. Uses Helvetica regular (no italic / no underline) — see also `sign sign --name-signature` for the signature-styled version.
  - **`sign pdf detect-signature-field` filtered to signature category** — backward-compat preserved: the existing command now explicitly returns only `category: signature` candidates so date anchors don't break existing scripts that check `candidates.length`.
  - **`sign sign --auto-place` filtered to signature category** — date anchors are no longer counted toward `AUTO_PLACE_AMBIGUOUS`; only signature anchors can drive a signature stamp.
- **`sign preview`** — new top-level command that stamps a signature image (or rendered name) onto a PDF WITHOUT producing a PAdES envelope. Lets you iterate on placement before committing to a signed PDF. Same flag set as `sign sign` for the stamping side: `--signature-image` or `--name-signature`, `--auto-place [selector]` or explicit `--image-*` coords, `--preserve-aspect-ratio`, `--signature-image-auto-crop`. Output JSON includes `sealed: false` so consumers can tell it apart from `sign sign` output. Surfaces the same quality warnings (`STAMP_OFF_PAGE` etc.). No DB interaction, no signing-request state mutation.
- **Multi-candidate selectors on `--auto-place`** — extends `--auto-place` from a boolean to a selector. Accepted values: `true` (legacy: requires unique high-confidence candidate), `first` (earliest page, top-of-page first), `last` (latest page, bottom-of-page first), `all` (multi-stamp: one stamp per high-confidence candidate, same image and options replayed at each position), `page:N` (the unique candidate on page N), `index:N` (the Nth candidate, 0-indexed from the confidence-sorted list). Closes the `AUTO_PLACE_AMBIGUOUS` foot-gun where the user knew the rule but had no way to tell the CLI. New error codes for the selector paths: `AUTO_PLACE_PAGE_NOT_FOUND`, `AUTO_PLACE_PAGE_AMBIGUOUS`, `AUTO_PLACE_INDEX_OUT_OF_RANGE`, `INVALID_AUTO_PLACE_VALUE` — all surface the full candidate list in `details.candidates` so the caller can recover.
- **Aspect-ratio preservation on visible-signature stamps (default ON)** — `sign sign --signature-image` and `sign pdf stamp` now shrink the image to fit inside the requested rectangle, top-left aligned, instead of stretching it. Fixes the stretched/distorted look when an image's natural aspect doesn't match an auto-detected or hand-specified box. Pass `--preserve-aspect-ratio false` to restore the legacy stretch-to-fill behavior.
- **`--signature-image-auto-crop true`** — for PNG inputs only, trims the white/transparent margin around the ink and replaces near-white opaque pixels with transparent ones before stamping. Removes the white-rectangle-around-signature look common in scanned-on-paper signature photos. Pure-JS PNG decoder (no native deps, no new install bytes); silently no-ops on JPG/SVG or unsupported PNG subsets (16-bit, interlaced, palette).
- **Stamp quality warnings on `sign pdf stamp`** — every `pdf stamp` run now appends a `warnings` array to the JSON output with up to four advisory codes: `STAMP_OFF_PAGE` (rectangle extends past page bounds), `STAMP_OUTSIZED_VS_TEXT` (stamp height > 5× median body-text height), `STAMP_OVERLAPS_TEXT` (rectangle intersects any text bbox), `ASPECT_RATIO_DISTORTED` (drawn aspect differs from natural by >5%, only fires when `--preserve-aspect-ratio false` was used). Pass `--strict-quality true` to exit non-zero (code `3`) when any warning fires; default is advisory and exits `0`. Warnings are also surfaced on `sign sign --signature-image` flows. that handles the French/European convention where the anchor (e.g., `Signature`) sits alone on its line and the signing area is the **blank space below** it, not to its right. Confidence `0.85`. When an anchor is alone on its line, this strategy is tried **before** `whitespace-probe`; when the anchor has neighbors on the same line, it's tried **after** as a fallback if right-side strategies fail (e.g., the proposed right-side rect overlaps text on the line above). Closes the auto-detect gap that left French-style attestations producing zero candidates.
- **`sign pdf detect-signature-field --verbose true`** — dumps the raw pdfjs-extracted text items per page (under `textItemsByPage`) and page dimensions (under `pageDimensions`). Use this to diagnose zero-candidate outcomes — you'll see exactly what text pdfjs extracted and where, so you can distinguish a missing anchor pattern from an embedded-font-without-ToUnicode problem from a signature line drawn as path operators rather than text.
- **Page-width clamp on right-side strategies** — `whitespace-probe` and `shrink-to-fit` now clamp their right edge to `pageWidth − 36pt` (a 0.5" right margin), preventing anchors near the page-right edge from producing rectangles that run off the page.
- **`sign pdf detect-signature-field`** — new command that returns ranked signature-field placement candidates for a PDF as JSON. AcroForm `/Sig` widgets (confidence `1.0`) rank first; anchor-text matches (Signature:, Sign here, Signed by:, Initial:, X____) follow with adjustment-method-derived confidence: `underline-snap` (`0.95`, anchor + adjacent underscore run), `below-anchor-probe` (`0.85`, anchor alone on its line + space below), `whitespace-probe` (`0.75`, anchor + adjacent empty space on same line), `shrink-to-fit` (`0.50`, default rect iteratively shrunk to avoid overlap). The safety contract: a candidate is never emitted with `overlapsText: true` — when no overlap-free rectangle exists, the candidate is dropped entirely. Exit `0` with candidates, exit `2` when none found. Uses `pdfjs-dist` for text-position extraction; a `scripts/trim-pdfjs-dist.mjs` postinstall hook drops unused subdirs (non-legacy build, viewer assets, image/WASM decoders, CJK cmaps, standard fonts) and all sourcemaps, bringing the installed `pdfjs-dist` footprint from ~36 MB to ~7.5 MB without affecting text extraction.
- **`sign sign --auto-place true`** — calls the detector and uses the top candidate iff there is a **unique** high-confidence (`≥ 0.8`) match. Multiple high-confidence candidates → `AUTO_PLACE_AMBIGUOUS` with the full candidate list. No high-confidence candidates → `AUTO_PLACE_NO_HIGH_CONFIDENCE` (with low-confidence candidates surfaced in `details` so the caller can pass `--image-*` explicitly). Without a visible-signature flag → `AUTO_PLACE_REQUIRES_VISIBLE_SIG`. Explicit `--image-*` coords always win over `--auto-place` (with a notice on stderr). The detector never silently picks a low-confidence rectangle.
- **`sign sign --name-signature`** — render the signer's name (or an explicit string) as a visible italic signature using pdf-lib's built-in `Helvetica-Oblique` font. Closes the UX gap where `--signature-image` was the only path to a visible stamp — now an agent or human can produce a signed PDF without preparing a signature image. Two forms: `--name-signature true` uses `--signer-name <text>` as the rendered text; `--name-signature "Custom Name"` renders that literal string. Mutually exclusive with `--signature-image` (caller bug → `SIGN_VISIBLE_SIG_BOTH`). Uses the same position resolution as image stamps (`--image-page/--image-x/--image-y/--image-width/--image-height` or fall back to a sender-placed SignatureField). Autosizes the text to fit the rectangle; draws an underline to signal "signature, not body text"; uses a signature-blue color matching the local-demo fixture.
- **`sign sign` help-catalog completeness** — `sign sign --help` and `sign --catalog json` now list every flag the command accepts. Previously they only advertised `--request-id`, `--token`, the `--require-*` safety checks, and `--idempotency-key`; the `--signature-image`, `--signer-name`, `--signer-email`, and `--image-page/--image-x/--image-y/--image-width/--image-height` flags existed in the code but couldn't be discovered from `--help`. (Plus the new `--name-signature` above.)
- **Visible photo signatures** — `sign sign --signature-image <path|data-url> --image-page <n> --image-x --image-y --image-width --image-height` stamps a PNG / JPG / SVG / `data:image/...;base64,...` onto the PDF *before* the PAdES envelope is sealed, so any post-signing tamper of the image breaks the cryptographic verification. Falls back to the sender's `--field signer:N,...` position when no explicit position flags are given. SVG inputs are rasterized at ~300 DPI of the target rectangle via `@resvg/resvg-wasm` (pure WASM, no native deps).
- **`sign pdf stamp`** — standalone command to stamp an image onto any PDF without a signing request. Shares the renderer with the integrated flow.
- **`docs/legal-posture.md`** — jurisdiction-by-use-case guide for when a `sign-cli` signature is enforceable. Covers US ESIGN/UETA, the eIDAS three-tier SES/AdES/QES breakdown, member-state nuances, and an EU-NDA deep-dive with the method-consent clause that materially improves enforceability for typical B2B NDAs.
- **`fixtures/templates/mutual-nda.md`** + **`scripts/render-template.mjs`** — bundled markdown template for a mutual NDA between two B2B parties (method-consent clause baked in per `legal-posture.md`) and a minimal `pdf-lib`-based renderer with `{{PLACEHOLDER}}` substitution. End-to-end recipe at [`docs/recipes/eu-nda.md`](docs/recipes/eu-nda.md).
- **`npm run lint:legal-claims`** — CI guardrail that scans user-facing docs + the web-demo landing page for unqualified legal claims ("legally binding" without a jurisdiction qualifier, "eIDAS-compliant", "court-ready", etc.) and fails loud. Exempts `docs/legal-posture.md` (the authoritative source) and `CHANGELOG.md`.
- **Web-demo signed-PDF artifact** — step 02 of the hosted demo now ships a downloadable PAdES-signed PDF with a visible SVG signature stamped on the page. Static fixture, generated by `scripts/generate-signed-fixture.mjs`.
- **Hosted-demo deploy kit** — `deploy/` ships a multi-stage Dockerfile, `seed-demo.mjs` (4 sample requests; one auto-completed), `entrypoint.sh` (wipe → seed → `sign serve --read-only true --web-demo true --rate-limit 5` → exit-after-TTL), and provider configs for Fly / Render / Railway plus a docker-compose for local validation.
- **Postgres async surface** — every read-only audit primitive (`verifyAuditChainAsync`, `listAuditEventsAsync`, `searchAuditEventsAsync`) and most write primitives (`appendAuditEventAsync`, `tryClaimWebhookEventAsync`, `insertApprovalRowAsync`, `insertArtifactRowAsync`, `markApprovalUsedAsync`, `markAllRequestApprovalsUsedAsync`, `updateRequestStatusAsync`, `reissueApprovalTokenRowAsync`, `persistRequestProviderMetadataAsync`) now run against `PostgresBackend`. Driver-level dialect translation (`?` → `$N`) handled by `db-backend.ts`.
- **`sign db postgres-smoke`** — eight-step integration probe for the async path: bootstrap → insert → extend chain → verify → list → search. Use after `sign db migrate-postgres` to confirm a fresh deployment.
- **`sign db migrate-postgres`** — Postgres-flavor schema bootstrap with PL/pgSQL append-only triggers. Idempotent.
- **`sign db rotate-keys`** — re-issues the local signer keypair with timestamped backups. `--re-sign-receipts true` walks every prior receipt and re-signs each manifest with the new key.
- **`sign audit anchor`** — cross-request RFC 3161 anchoring with `--since`, `--since-anchor`, and `--dry-run` modes. Companion commands: `audit anchors-list`, `audit verify-anchor`.
- **`sign audit chain-bundle`** — self-contained compliance directory (anchor + per-request receipts + INDEX.json). `--tarball` writes a portable `.tar.gz` (pure-Node USTAR + gzip writer); `--include-source-pdf true` includes the unsigned PDF for reproducibility.
- **`sign audit verify-chain-bundle`** — re-checks a stored bundle (dir or tarball) and reports per-request results; `--report` streams NDJSON.
- **`sign audit show`** gains `--format pretty` (human-readable timeline), `--format csv` (RFC 4180), `--event-type` (repeatable), and `--since`/`--until` (time window).
- **`sign audit search`** — log-style cross-request filter with `--request-id`, `--event-type`, `--since`, `--until`, `--payload-contains`.
- **`sign signer policy lint`** — static checks (invalid regex, empty rules, unreachable rules, redundant rules, decline-without-reason, contradictory rules).
- **`sign signer policy diff`** — preview action flips between two specs against a snapshot or the inbox; `--format markdown` renders a reviewer-friendly table.
- **`sign signer policy try`** — offline tester; `--batch` evaluates an array of contexts in one shot.
- **`sign signer policy run-watch`** — long-running tail-the-inbox + apply-policy loop. Flags: `--report` (NDJSON), `--on-decision <cmd>` (shellout hook), `--since-anchor` (skip already-anchored chains).
- **`sign request rerun-policy`** — re-evaluate a stored request against an updated spec. Pure read.
- **`sign request bulk-resend`** — re-issue tokens en masse from a CSV roster.
- **`sign request show`** gains `--hash-only true` (stable digest triple) and `--recipient <email>` (redacted single-signer view).
- **`sign request list`** gains `--since`, `--format json|table`.
- **`sign metrics show` / `sign metrics ship`** — Prometheus text output and a long-running pusher; `--batched` coalesces N snapshots per HTTP body.
- **`sign serve --rate-limit`** — token-bucket per-IP gate with `X-RateLimit-*` headers and `Retry-After`.
- **`sign serve --read-only` + `sign mcp serve --read-only`** — block lifecycle-mutating endpoints/tools with `FORBIDDEN_READ_ONLY`.
- **`sign mcp serve`** gains `--tool` allow-list, `--capability` toggle (tools/resources/prompts), `--emit-events` NDJSON tee log, `--emit-events-redact true` (mask token-shaped fields).
- **`sign serve --web-demo true`** — bundled static HTML/CSS/JS dashboard served from same origin under `/web-demo/*` (no CORS).
- **MCP tool catalog** — every tool ships an `inputSchema` and most ship an `outputSchema`; `request_watch` ships a `progressSchema`. `sign mcp tools --format markdown` renders the catalog as a docs page.
- **Selftest MCP leg** — `runSelftest` now also drives `initialize`, `tools/list`, `tools/call request_show`, `tools/call audit_verify` through the JSON-RPC server.

### Changed

- **`sign doctor preflight` env-health checks** — preflight now runs two env-scoped checks before any provider-specific ones, on every provider: `runtime:node_version` (Node ≥ 22) and `storage:db_path` (`SIGN_DB_PATH` parent writable via a probe-file round-trip). Closes the gap where `doctor preflight` only validated provider credentials and ignored the env that the CLI itself needs.
- **`sign serve` startup banner pulls from `listMockHttpRoutes()`** ([#179](https://github.com/DrBaher/sign-cli/pull/179)) — replaces the previously-hardcoded route list, which silently went stale every time `http-api.ts` got a new route. Banner now lists all 20 routes alphabetically; future route additions show up automatically.
- **`sign --catalog json` now includes `version`** ([#180](https://github.com/DrBaher/sign-cli/pull/180)) — matches the shape `docs/agent-guide.md` §3 already documented. Pulls from the existing `SIGN_CLI_VERSION` constant so it can't drift. Regression test in `help-and-catalog.test.ts`.

### Fixed

- **Web-demo signed-PDF fixture's signer subject** — the fixture-generation script passed the per-signer keypair under the wrong option key (`keyPair` instead of `signerKeyPair`), so `signPdfLocally` fell through to `loadOrCreateLocalSigner()` and the fixture's signature panel showed the generic `CN=Sign CLI Local Signer` instead of `CN=Alice Anderson <alice@example.com>`. Regenerated; added a `web-demo.test.ts` guard asserting the fixture cert subject contains an `@` so the script can't silently regress.
- **MCP `request_receipt` outputSchema corrected to match handler** ([#180](https://github.com/DrBaher/sign-cli/pull/180)) — the tool was advertising `manifestHash` / `certificatePath` / `requestId`, none of which `exportRequestReceipt` returns. The real `ReceiptResult` shape uses `manifestSha256` / `certPath` / `signatureBytes` / `chain` and `files` is an array of objects (not strings). Schema corrected; regression test in `api-parity.test.ts` asserts every `ReceiptResult` key is present AND no stale keys remain.

### Refactor

- All `INSERT INTO artifacts` call sites route through `insertArtifactRow`. Sync write primitives now share SQL constants + parameter projections with their async siblings — column order can't drift.

### Docs

- **[`docs/agent-guide.md`](docs/agent-guide.md)** — canonical agent reference. Output conventions (stdout JSON / stderr error envelope), cross-command exit-code map, per-command schemas + side-effects + idempotency for the new surfaces (`doctor preflight`, `pdf stamp verify`, `workflow nda`, `audit export` v2, trust labels, strict-provider, `audit verify`), and the failure-mode → recovery table.
- **[`docs/recipes/preflight.md`](docs/recipes/preflight.md)** — pre-production agent recipe: `doctor preflight` → strict-provider → `pdf stamp verify` → `audit export` for handoff. Shows exit-code branching at each step.
- **[`docs/regression-testing.md`](docs/regression-testing.md)** — per-item manual regression tests for every surface in the `[Unreleased]` block, plus an end-to-end smoke. Exit-code-driven and copy-pasteable. Pairs with `npm test` (which covers the same surfaces automatically); use this when validating a build against expected behavior outside the suite.
- **[`docs/profiles-design.md`](docs/profiles-design.md)** — design proposal for named provider/credential/dbPath bundles (Item 5 of the readiness feedback). No code; open for review in #162.
- New `docs/recipes/` — sign-as-Alice, weekly anchor, auditor handoff, agent loop over MCP.
- New `docs/architecture.md` — mermaid diagram + layer-by-layer prose.
- New `docs/comparison.md` — frank pros/cons vs. SaaS providers and DIY.
- New `docs/compliance-posture.md` — explicit threat model + what the audit chain proves and doesn't.
- New `integrations/` — Claude Desktop config + langchain wrapper starters.
- README intro tightened: one-line lede, `npx sign-cli demo` above the fold, "Read in this order" pointer to the four entry points.

## [0.5.0] — 2026-05-07

A large discoverability + agent-as-signer release.

### Added
- **Agent-as-signer flow for `--provider local`** — `sign sign`, `signer list`, `signer fetch-document`, `signer decline`, with per-signer token authentication (#11, #12). Pre-sign safety checks (`--require-hash` / `--require-title` / `--require-signer-email`) throw before any state mutation. New audit events: `request.signed_by_signer`, `request.signer_declined`, `request.signer_fetched_document`.
- **Structured error envelopes** — `{ ok, error: { code, message, hint?, details? } }` on stderr, with stable `code` values (`TOKEN_EXPIRED`, `PRE_SIGN_HASH_MISMATCH`, `NON_LOCAL_PROVIDER`, …). Toggle off with `SIGN_ERROR_FORMAT=text` (#13).
- **Enriched `request show`** — adds `signedBy[]`, `declinedBy`, per-approval `tokenHint`/`expiresAt`/`expired`/`signed`, and a `nextSteps[]` array of suggested commands (#14).
- **MCP stdio server** — `sign mcp serve` exposes 8 tools (`signer_list`, `signer_fetch_document`, `sign`, `signer_decline`, `request_show`, `request_status`, `request_watch`, `audit_verify`) and 3 resource shapes (`request://<id>` snapshot, `request://<id>/document` PDF blob, `request://<id>/audit` chain) over JSON-RPC 2.0 (#15, #19). `request_watch` streams `notifications/progress` when the client supplies a `progressToken`. Tool args are validated against each tool's `inputSchema`.
- **Token recovery** — `signer reissue-token` mints a fresh token in place of an expired/lost one (#16).
- **Inbox token expiry hints** — every `signer list` entry now includes `tokens[]` with `expiresAt`, `expired`, `expiresSoon` (#16).
- **Spec-file requests** — `request create --spec ./request.json [--param key=value]` (#17, #20). Variable substitution lets a single template be reused across counterparties.
- **Declarative signer policy** — `signer policy run --spec ./policy.json [--dry-run true]` and `signer policy run-all --tokens-file …` (#18, #21). Two-layer model: non-negotiable expectations (`titleMatches`, `documentSha256`, `signerEmail`) + first-match-wins rules (`sign` / `decline` / `report`).
- **Webhook notifications** — `SIGN_LOCAL_NOTIFY_URL` fires fire-and-forget JSON POSTs on allow-listed audit events (`request.signed_by_signer`, `request.signer_declined`, `request.final_pdf_downloaded`, etc.) (#21).
- **Cryptographic receipts** — `request receipt --request-id <id> --out ./receipt/` produces an audit-export bundle plus a detached `manifest.sig` + `manifest.cert.pem` that openssl can verify directly (#20).
- **Per-signer PAdES identity** — each signer gets a stable on-disk RSA-2048 key/cert keyed by email; `signedBy[]` entries now carry `certFingerprintSha256` + `certSubjectCommonName`, giving multi-party requests cryptographically distinguishable per-signer identities at the audit-chain level (#23).
- **Cross-provider `signedBy` parity** — new `signer_signing_states` table is fed by both local sign/decline and Dropbox/SignWell webhook ingestion. `request show` for hosted-provider requests now returns a populated `signedBy[]` instead of `null` (#24).
- **Shell completion** — `sign completion bash|zsh|fish` (#22).
- **Self-documenting CLI** — `sign --help` (grouped index), `sign <cmd> --help` (focused per-command help), `sign --catalog json` (machine-readable index), `sign examples` (7 curated walkthroughs), `sign --version`, `sign mcp tools` (catalog without spinning up the server) (#25).
- **Discoverability TL;DR** in the README plus a 5-line cheatsheet (#26).

### Changed
- `request show` snapshot shape preserved as a strict superset; existing keys unchanged.
- `--token` is now **required** for `sign`, `signer fetch-document`, and `signer decline` (signer-side flow was 2 days old; no other callers).

### Migration

The new `signer_signing_states` table is created via `CREATE TABLE IF NOT EXISTS` on `openDatabase`, so existing DBs upgrade transparently. No data migration required.

## [0.4.0] — earlier

See `git log --oneline 0.3.0..0.4.0` for the SignWell webhook ingest, embedded signing, audit timestamping, and PAdES-signer history.
