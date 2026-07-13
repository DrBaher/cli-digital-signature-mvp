<p align="center">
  <img src="assets/icon.svg" width="120" alt="sign-cli">
</p>

# sign-cli

Fully-offline e-signature CLI. The built-in PAdES signer (PKCS#7 in `/ByteRange`, self-issued cert) produces real, cryptographically verifiable signed PDFs with no signup and no third-party provider — or routes through Dropbox Sign / DocuSign / SignWell when you need an external trust anchor. Per-signer approval tokens (TTL-bounded, scoped to one email), hash-chained audit events, RFC 3161 timestamping, named profiles, a 19-tool MCP server, and a 20-route HTTP API.

**The asymmetry is the architecture**: an agent can drive every step except the actual signing gesture, which stays gated behind a human.

> **Part of the contract-ops CLI suite — optional.** sign-cli works entirely on its own; it's also the **signing + audit** step of the [contract-ops suite](https://cli.drbaher.com/): [template-vault-cli](https://github.com/DrBaher/template-vault-cli) → [draft-cli](https://github.com/DrBaher/draft-cli) → [nda-review-cli](https://github.com/DrBaher/nda-review-cli) → [docx2pdf-cli](https://github.com/DrBaher/docx2pdf-cli) → **sign-cli**, with drift detection via [compare-cli](https://github.com/DrBaher/compare-cli).

## Run this

```bash
npx @drbaher/sign-cli demo
```

That single command runs the entire lifecycle — create (consent + email-verification gates on) → send → watch the gates block signing → verify email → capture consent → approve → sign → verify chain → export receipt — against the offline local provider, then deletes everything. No signup. No keys. ~5 seconds.

> **[Live demo →](https://sign-cli-demo-production.up.railway.app/web-demo/)** — read-only, resets every 4 hours. Self-host: see [`deploy/README.md`](deploy/README.md).

## Where to go next

| If you are… | Start here |
|---|---|
| **A new user** evaluating the tool | This README's [Quick start](#quick-start), then [Standard user journey](#standard-user-journey) |
| **An operator** wiring up a hosted provider | [docs/setup/](docs/setup/) — Dropbox / DocuSign / SignWell / embedded |
| **An LLM agent** driving the CLI | [AGENTS.md](AGENTS.md) → [docs/agent-guide.md](docs/agent-guide.md) → [docs/recipes/](docs/recipes/) |
| **An auditor** verifying a signed bundle | [docs/reference/audit-chain.md](docs/reference/audit-chain.md), [docs/reference/legal.md](docs/reference/legal.md) |
| **A contributor** | [docs/reference/architecture.md](docs/reference/architecture.md), [docs/regression-testing.md](docs/regression-testing.md) |
| **Adding a new CLI to the suite** | The [build-a-CLI playbook](https://cli.drbaher.com/build-a-cli) — the conventions every suite CLI follows |

Concept deep-dives live in [docs/reference/](docs/reference/); task-oriented recipes in [docs/recipes/](docs/recipes/).

## Quick start

```bash
# Install
npm i -g @drbaher/sign-cli

# Or run without installing
npx @drbaher/sign-cli demo

# After install, the binary is named `sign`
sign --version
sign demo
sign init        # wizard: provider selection + .env
sign doctor preflight   # structured per-check readiness report
```

Or download a standalone binary from [Releases](https://github.com/DrBaher/sign-cli/releases) — `./sign-linux-x64 demo`. See [DISTRIBUTION.md](./DISTRIBUTION.md) for every install path.

## What this gives you

- **Offline PAdES signing** with a self-issued cert — real PKCS#7 signed PDFs, no signup, no API keys.
- **Three hosted providers** when you need them: Dropbox Sign, DocuSign, SignWell. Same surface across all four.
- **Per-signer approval tokens** (single-use, TTL-bounded, tied to one email). Tokens go to the human, not the agent.
- **Consent + attribution evidence, opt-in per request**: `--require-consent` gates signing on a recorded intent-to-sign attestation + electronic-records consent (versioned canonical texts, hashed into the audit chain); `--require-email-verification` gates it on a mailbox-control code; `signer record-identity` logs how identity was checked out-of-band. No KYC data is collected — by design. See [docs/reference/consent-and-identity.md](docs/reference/consent-and-identity.md).
- **Hash-chained audit chain** with append-only DB triggers + RFC 3161 anchors. See [docs/reference/audit-chain.md](docs/reference/audit-chain.md).
- **Idempotent `request send`** — refuses to double-send unless `--force true`; pair with `--idempotency-key` for safe retries.
- **Multi-document + multi-signer** requests; CSV-driven bulk send.
- **Templates** from each provider's dashboard via `request from-template`.
- **Auto-detect signature field** (`sign pdf detect-signature-field` + `sign sign --auto-place`). Detects AcroForm `/Sig` widgets and anchor text in English + French/EU conventions.
- **Inspect any signed PDF** with `sign pdf inspect` — parses PAdES PKCS#7 from sign-cli or any other producer (Adobe, DocuSign, Dropbox Sign, SignWell). Returns signer CN/email, cert subject + issuer, validity window, fingerprint, trust label (`self_signed_local` / `self_signed_other` / `ca_signed` / `unknown`), and message-digest match.
- **Counter-sign visibility** — `signer fetch-document` and the MCP `signer_fetch_document` tool surface `existingSignatures`, so a signer can see what they're countersigning before they sign.
- **One-shot DOCX → sealed PDF** via `sign document` (chains the bundled docx2pdf-cli, auto-place, stamp, PAdES-seal, verify in one call against a scoped temp DB).
- **Sandbox via `--read-only true`** on both `mcp serve` and `serve`. Mutating tools/routes return `FORBIDDEN_READ_ONLY`.
- **Path-traversal guards** on every input and output path. See [docs/reference/security-controls.md](docs/reference/security-controls.md).
- **Named profiles** bundle provider + dbPath + credentials (with `{{env:VAR}}` references for shell-managed secrets). See [docs/reference/profiles.md](docs/reference/profiles.md).
- **PDF verification** end-to-end offline: `request verify-signed-pdf` recomputes the digest, extracts X.509 signer certs, supports `--recipient <email>` for a redacted single-signer view, and reports per-signer `trust` labels.

## Standard user journey

```bash
sign request create \
  --title "Mutual NDA" \
  --document ./nda.pdf \
  --signer name:Alice,email:alice@acme.com,order:1 \
  --signer name:Bob,email:bob@beta.com,order:2 \
  --provider signwell

sign approve --request-id <id> --token <token1>
sign approve --request-id <id> --token <token2>

sign request send --request-id <id> --provider signwell --test-mode true

sign request watch \
  --request-id <id> --provider signwell \
  --interval-seconds 5 --fetch-final true \
  --out ./signed.pdf

sign audit show --request-id <id>
```

Or fully offline:

```bash
sign request create --title "Mutual NDA" --document ./nda.pdf \
  --signer name:Alice,email:alice@example.com,order:1 \
  --signer name:Bob,email:bob@example.com,order:2 \
  --provider local --auto-approve true
sign request send --request-id <id> --provider local
# Each signer runs:
sign sign --request-id <id> --token <their-token> \
  --require-hash <sha256> --require-title "^Mutual NDA$"
```

For full provider-specific setup, see [docs/setup/](docs/setup/).

## One-shot DOCX → sealed PDF

```bash
sign document contract.docx \
  --signer "Alice Founder" --signer-email "alice@acme.com" \
  --name-signature "Alice Founder" --auto-place first \
  --out contract.sealed.pdf
```

`sign document` chains: convert (via the bundled docx2pdf-cli) → detect signature field → stamp → PAdES-seal → verify chain. All intermediate state lives in a scoped temp DB.

## MCP server (for LLM agents)

```bash
sign mcp serve                  # stdio MCP server
sign mcp serve --read-only true # sandboxed: mutating tools return FORBIDDEN_READ_ONLY
sign mcp tools                  # print the catalog (live; don't hardcode the list)
```

19 tools, split read-only vs mutating. Backed by the same `SignCliError` envelopes you'd see at the CLI. The full discovery contract, wire-up snippets (Claude Desktop, Cursor), and read-only walkthrough are in [AGENTS.md](AGENTS.md). Three resource shapes (`request://<id>` snapshot, `.../document` PDF blob, `.../audit` chain) and four agent-as-signer prompt templates (`review_and_sign`, `policy_check`, `inbox_triage`, `verify_receipt`) are also exposed.

## HTTP API (for non-MCP clients)

```bash
sign serve --port 4000 --auth-token <t> --read-only true --rate-limit 5
curl http://127.0.0.1:4000/v1/openapi.json    # discover the route catalog
```

Twenty routes under `/v1/*`, 1:1 parity with the MCP tool surface — same input shape, same path-traversal guards, same read-only gating. Bearer auth via `--auth-token` or `SIGN_HTTP_AUTH_TOKEN`. Responses are `{ ok, result }` on success or the standard error envelope on failure.

## Signer-side flow (agent-friendly)

For `--provider local`, an agent can act as a signer end-to-end without an email link. Set `SIGN_LOCAL_AUTOCOMPLETE=false` so the local provider holds at `sent` until each signer explicitly runs `sign sign`.

```bash
# As the requester (agent or human)
sign request create --title "Mutual NDA" --document ./nda.pdf \
  --signer name:Alice,email:alice@example.com,order:1 \
  --signer name:Bob,email:bob@example.com,order:2 \
  --provider local --auto-approve true
# response includes per-signer tokens
sign request send --request-id <id> --provider local

# As the signer, with their token
sign signer list --signer-email alice@example.com
sign signer fetch-document --request-id <id> --token alice-tok-... --out ./nda.pdf
# fetch-document surfaces `existingSignatures` so the signer can see what they're countersigning
sign sign --request-id <id> --token alice-tok-... \
  --require-hash <sha256> --require-title "^Mutual NDA$" --require-signer-email alice@example.com
# or
sign signer decline --request-id <id> --token alice-tok-... --reason "Terms changed"
```

Multi-signer: status only flips to `completed` when every signer is in `signedBy[]`. Pre-sign safety checks (`--require-hash` / `--require-title` / `--require-signer-email`) throw `PRE_SIGN_*_MISMATCH` before any state mutation.

## Templates

Reuse a template defined in the provider dashboard (no PDF upload):

```bash
sign request from-template \
  --template-id tmpl_abc --provider dropbox \
  --signer role:Buyer,name:Alice,email:alice@example.com,order:1 \
  --signer role:Seller,name:Bob,email:bob@example.com,order:2 \
  --prefill name:purchase_price,value:1000 \
  --auto-approve true

sign request send --request-id <id> --provider dropbox --test-mode true
```

Each `--signer` must include `role:<roleName>` matching a template role. `--prefill name:K,value:V[,signer:N]` populates template fields. Per-provider behavior: DocuSign uses per-signer text tabs; Dropbox uses `custom_fields`; SignWell uses `placeholders`.

## Field placement

By default the hosted providers auto-append a generic signature page. For real contracts, pass `--field` (repeatable) on `request create`:

```bash
sign request create \
  --title "NDA" --document ./contract.pdf \
  --signer name:Alice,email:alice@example.com,order:1 \
  --field signer:1,page:1,x:100,y:200,type:signature \
  --field signer:1,page:1,x:100,y:240,type:date
```

Spec: `signer:<order>` (required), `doc:<i>` (multi-doc index), `type:signature|initials|date|text|name|email`, `page:<n>` `x:<pt>` `y:<pt>` (coordinate), or DocuSign-only `anchor:"text"` with optional `x-offset` / `y-offset` / `anchor-units`. The fields persist on the request and forward to the provider at send time.

## Auto-detect signature field

For `--provider local`, `sign sign --auto-place` calls the detector and uses the top candidate iff there's a **unique** high-confidence (`≥0.8`) match.

```bash
# Inspect candidates first
sign pdf detect-signature-field --pdf ./contract.pdf

# Auto-place (errors loudly on ambiguity)
sign sign --request-id <id> --token <t> --name-signature "Alice" \
  --auto-place first   # or true | last | all | page:N | index:N
```

Adjustment strategies in priority order: `underline-snap` (0.95), `below-anchor-probe` (0.85, French/EU conventions), `whitespace-probe` (0.75), `shrink-to-fit` (0.50). Date anchors are detected separately via `sign pdf detect-date-field`. Full reference in [`docs/agent-guide.md` §6.4a](docs/agent-guide.md).

## Bulk send

```bash
sign request bulk \
  --csv ./signers.csv \
  --document ./contract.pdf --provider dropbox \
  --title "Q2 NDA for {{email}}" --test-mode true
```

Each row becomes its own request with `autoApprove: true`. Title template supports `{{email}}`, `{{name}}`, `{{row}}`. Exit code `3` if any row failed; JSON output lists per-row results.

## Trust beyond the provider

```bash
# Inspect any signed PDF (ours, Adobe's, DocuSign's, …) — no DB lookup required
sign pdf inspect --pdf ./signed.pdf

# Inspect the embedded PKCS#7 of a request we sent
sign request verify-signed-pdf --request-id <id>
sign request verify-signed-pdf --request-id <id> --recipient alice@example.com   # single-signer view

# Anchor the audit head against a public RFC 3161 TSA
sign audit anchor --request-id <id>

# Bundle for archival
sign audit export --request-id <id> --out ./bundle/
```

`audit verify` walks the local hash chain. `request verify-signed-pdf` recomputes the SHA-256 over the `/ByteRange`, compares it to the `messageDigest` in the embedded PKCS#7, **and verifies the PKCS#7 signature value against the signer certificate's public key (RSA/ECDSA)** — so a forged or tampered signature fails, exit `3`, not just a modified-after-signing one. `sign pdf inspect` works on any signed PDF (no request id required). `audit anchor` issues a TimeStamp token from a TSA. See [docs/reference/audit-chain.md](docs/reference/audit-chain.md) for the full model.

## Profiles

```bash
sign profile init --name prod --provider signwell --db "~/.sign-cli/prod.db" --strict-provider true
sign profile set --name prod --key credentials.SIGNWELL_API_KEY --value "{{env:SIGNWELL_API_KEY}}"
sign --profile prod request show --request-id <id>
# Or implicitly via a project-level sign-profile.json (git/npm-style upward discovery)
```

Resolution order: flag > env > project profile > user profile > built-in default. Credentials redacted by default in `profile show` (`--show-secrets true` to reveal). Over the MCP HTTP transport, `show_secrets` is refused unless an `--http-auth-token` is configured (it stays available on stdio MCP and the CLI). See [docs/reference/profiles.md](docs/reference/profiles.md).

## Doctor

```bash
sign doctor                       # legacy env-report; always exits 0
sign doctor preflight             # structured per-check report; exit 0 ok, 1 failed
sign doctor providers             # capability matrix across all providers
sign doctor account-check --provider signwell   # provider /me check
```

`preflight` runs env-health checks (`runtime:node_version`, `storage:db_path`) on every provider, then provider-scoped checks layer on top. Branch on `checks[].name` for agent self-recovery.

## Security notes

- Never commit `.env` or API keys.
- Rotate keys if shared in chat/logs.
- Keep test mode on during development.
- For path-traversal guards, secret redaction, idempotency, and read-only mode, see [docs/reference/security-controls.md](docs/reference/security-controls.md).
- For what the chain proves vs. what it doesn't, see [docs/reference/security-model.md](docs/reference/security-model.md).

## License

MIT. See [LICENSE](LICENSE).

## See also

- [AGENTS.md](AGENTS.md) — the agent quickstart (output contract, exit codes, discovery, failure recovery).
- [docs/agent-guide.md](docs/agent-guide.md) — canonical agent reference (per-command schemas, side effects, idempotency).
- [docs/setup/](docs/setup/) — provider setup (Dropbox, DocuSign, SignWell, embedded).
- [docs/recipes/](docs/recipes/) — task-oriented recipes (preflight, agent-loop-mcp, weekly anchor, auditor handoff, sign as Alice, EU NDA).
- [docs/reference/](docs/reference/) — concept deep-dives (audit chain, exit codes, profiles, security model, architecture, legal posture, comparison).
- [TROUBLESHOOTING.md](TROUBLESHOOTING.md) — error catalog.
- [CHANGELOG.md](CHANGELOG.md) — what landed and when.
- [integrations/](integrations/) — Claude Desktop config, langchain starter.
- [deploy/](deploy/) — Fly / Render / Railway configs for the hosted demo.
