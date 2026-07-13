#!/usr/bin/env node
import "./lib/silence-warnings.js";
import process from "node:process";
import { openDatabase } from "./lib/db.js";
import { requireDropboxApiKey, requireDropboxClientId, resolveDropboxTestMode } from "./lib/dropbox-sign.js";
import { loadEnv } from "./lib/env.js";
import { loadCsvFile } from "./lib/csv.js";
import { backupDatabase, verifyDatabase } from "./lib/db-admin.js";
import { collectInitAnswers, createDefaultIo, writeEnvFile } from "./lib/init-wizard.js";
import { createLogger, resolveLogMode } from "./lib/logger.js";
import { redactErrorMessage } from "./lib/secret.js";
import { attachPrettyAuditPrinter } from "./lib/audit-pretty.js";
import { generateCompletionScript, type CompletionShell } from "./lib/completion.js";
import { runAuditWatch } from "./lib/audit-watch.js";
import { listMockHttpRoutes, startHttpApiServer } from "./lib/http-api.js";
import { diffRequests } from "./lib/request-diff.js";
import { renderReceiptVerificationHtml } from "./lib/receipt-html.js";
import { runSelftest } from "./lib/selftest.js";
import { verifyRequestReceiptBundle } from "./lib/receipt-verify.js";
import { runSignerWatch } from "./lib/signer-watch.js";
import {
  buildCatalogJson,
  findCommand,
  findCommandGroup,
  formatCommandGroupHelp,
  formatCommandHelp,
  formatExamples,
  formatTopLevelHelp,
  HELP_CATALOG,
} from "./lib/help-catalog.js";
import { formatCliError, SignCliError } from "./lib/sign-error.js";
import { listMcpTools, renderMcpToolsAsMarkdown, serveMcpStdio, startMcpHttpServer } from "./lib/mcp-server.js";
import { validateBulkRowCount, validateConfigPath, validateDocumentPath, validateEmail, validateFieldCount, validateOutputPath, validateReturnUrl, validateSignerCount } from "./lib/validate.js";
import {
  resolveSignProvider,
  resolveSignProviderWithSource,
  strictProviderEnabled,
  type SignProvider,
} from "./lib/providers.js";
import { emitJsonWithProvider, printProviderBanner } from "./lib/cli-output.js";
import { runPreflight, preflightExitCode } from "./lib/preflight.js";
import { requireSignWellApiKey, resolveSignWellTestMode } from "./lib/signwell.js";
import {
  loadDocuSignWebhookPayloadFile,
  requireDocuSignWebhookSecret,
  verifyDocuSignCallback,
} from "./lib/docusign-webhook.js";
import { loadSignWellWebhookPayloadFile, requireSignWellWebhookSecret, verifySignWellCallback } from "./lib/signwell-webhook.js";
import {
  approveSigningRequest,
  buildProviderMatrix,
  bulkReissueSignerTokens,
  bulkSendFromCsv,
  cancelSigningRequest,
  declineSigningRequestAsSigner,
  readLocalDocumentForResource,
  runLocalDemo,
  createSigningRequest,
  exportAuditBundle,
  exportAuditChainAsJsonLd,
  exportRequestReceipt,
  issueAuditReceiptsBulk,
  signAuditHead,
  verifyAuditHeadProof,
  fetchUnsignedDocumentForSigner,
  getRequestSnapshot,
  fetchFinalSignedPdf,
  getEmbeddedSignUrl,
  getSigningRequestStatus,
  ingestDocuSignWebhookPayload,
  ingestSignWellWebhookPayload,
  ingestWebhookPayload,
  inspectRequestSignedPdf,
  verifyVerdictExitCode,
  listAuditEvents,
  listSignerInbox,
  listSigningRequests,
  REQUEST_WATCH_EXIT_CODES,
  reissueSignerToken,
  issueSignerEmailVerification,
  verifySignerEmailCode,
  recordIdentityAssurance,
  remindSigningRequest,
  rerunPolicyForRequest,
  runSignerPolicy,
  runSignerPolicyAll,
  scanAllAuditChains,
  runDoctor,
  runProviderAccountCheck,
  runSignWellSmokeTest,
  sendEmbeddedSigningRequest,
  sendSigningRequest,
  signSigningRequest,
  getPersistedProviderForRequest,
  timestampRequestAuditChain,
  verifyRequestAuditChain,
  watchSigningRequestStatus,
} from "./lib/signing-service.js";
import { parseFieldSpec } from "./lib/field-placement.js";
import { loadPolicySpec } from "./lib/policy-engine.js";
import { parseImageInput, stampImageOnPdf, type StampPosition } from "./lib/pdf-image-stamp.js";
import { loadRequestSpec } from "./lib/request-spec.js";
import { parseBooleanFlag, parsePrefillSpec, parseSignerSpec } from "./lib/util.js";
import { describeConsentStatements, parseIdentityAssuranceSpec } from "./lib/consent.js";
import { loadWebhookPayloadFile, verifyDropboxCallback } from "./lib/webhook.js";
import { startWebhookServer } from "./lib/webhook-server.js";

type ParsedArgs = {
  positionals: string[];
  flags: Map<string, string[]>;
};

function parseArgs(argv: string[]): ParsedArgs {
  const flags = new Map<string, string[]>();
  const positionals: string[] = [];

  for (let index = 0; index < argv.length; index += 1) {
    const part = argv[index];
    if (!part.startsWith("--")) {
      positionals.push(part);
      continue;
    }
    const key = part.slice(2);
    const next = argv[index + 1];
    if (!next || next.startsWith("--")) {
      flags.set(key, [...(flags.get(key) ?? []), "true"]);
      continue;
    }
    flags.set(key, [...(flags.get(key) ?? []), next]);
    index += 1;
  }

  return { positionals, flags };
}

function flagValue(args: ParsedArgs, name: string, required = false): string | undefined {
  const values = args.flags.get(name);
  if ((!values || values.length === 0) && required) {
    throw new SignCliError({
      code: "MISSING_FLAG",
      message: `Missing required flag: --${name}`,
      details: { flag: name },
    });
  }
  return values?.at(-1);
}

function flagValues(args: ParsedArgs, name: string): string[] {
  return args.flags.get(name) ?? [];
}

/** Read the five --image-* flags into a partial StampPosition; caller decides if the partial is acceptable. */
function readImagePositionFlags(args: ParsedArgs): Partial<StampPosition> | undefined {
  const page = flagValue(args, "image-page");
  const x = flagValue(args, "image-x");
  const y = flagValue(args, "image-y");
  const width = flagValue(args, "image-width");
  const height = flagValue(args, "image-height");
  if (page === undefined && x === undefined && y === undefined && width === undefined && height === undefined) {
    return undefined;
  }
  return {
    ...(page !== undefined ? { page: Number(page) } : {}),
    ...(x !== undefined ? { x: Number(x) } : {}),
    ...(y !== undefined ? { y: Number(y) } : {}),
    ...(width !== undefined ? { width: Number(width) } : {}),
    ...(height !== undefined ? { height: Number(height) } : {}),
  };
}

function isCompletePosition(position: Partial<StampPosition>): position is StampPosition {
  return (
    typeof position.page === "number" && Number.isFinite(position.page) &&
    typeof position.x === "number" && Number.isFinite(position.x) &&
    typeof position.y === "number" && Number.isFinite(position.y) &&
    typeof position.width === "number" && Number.isFinite(position.width) &&
    typeof position.height === "number" && Number.isFinite(position.height)
  );
}

function formatAutoPlaceFlag(mode: { kind: string; page?: number; index?: number }): string {
  switch (mode.kind) {
    case "unique": return "true";
    case "first": return "first";
    case "last": return "last";
    case "all": return "all";
    case "page": return `page:${mode.page}`;
    case "index": return `index:${mode.index}`;
    default: return mode.kind;
  }
}

function parseStampOptions(args: ParsedArgs): import("./lib/pdf-image-stamp.js").StampOptions {
  // Defaults: preserve aspect ratio ON, auto-crop OFF. Reading the flag
  // explicitly (not `=== "false"`) so any non-falsy value (`yes`, `1`)
  // toggles on, matching the convention elsewhere in the CLI.
  const preserveRaw = flagValue(args, "preserve-aspect-ratio");
  const autoCropRaw = flagValue(args, "signature-image-auto-crop");
  return {
    preserveAspectRatio: preserveRaw === "false" || preserveRaw === "no" || preserveRaw === "0" ? false : true,
    autoCrop: autoCropRaw === "true" || autoCropRaw === "yes" || autoCropRaw === "1",
  };
}


function parseDurationMs(
  args: ParsedArgs,
  options: { msFlag: string; secondsFlag: string; defaultMs?: number; minMs?: number },
): number | undefined {
  // Reject non-numeric / non-positive durations up front. A NaN here (e.g.
  // --interval-seconds abc) used to flow into a poll loop as a 0/NaN delay,
  // producing a tight busy-loop that hammers the provider/DB.
  const coerce = (raw: string, flag: string, multiplier: number): number => {
    const value = Number(raw) * multiplier;
    if (!Number.isFinite(value) || value <= 0) {
      throw new SignCliError({
        code: "INVALID_ARGS",
        message: `${flag} must be a positive number; got ${JSON.stringify(raw)}.`,
      });
    }
    if (options.minMs !== undefined && value < options.minMs) return options.minMs;
    return value;
  };
  const msValue = flagValue(args, options.msFlag);
  if (msValue !== undefined) {
    return coerce(msValue, `--${options.msFlag}`, 1);
  }
  const secondsValue = flagValue(args, options.secondsFlag);
  if (secondsValue !== undefined) {
    return coerce(secondsValue, `--${options.secondsFlag}`, 1000);
  }
  return options.defaultMs;
}

function printUsage(): void {
  console.log(`sign request create --title "Doc" --document ./file.pdf [--document ./extra.pdf] --signer name:Alice,email:alice@example.com,order:1 [--field signer:1,doc:0,page:1,x:100,y:200,type:signature] [--provider dropbox|docusign|signwell]
  (Quick-start: use the bundled real PDF fixture at fixtures/canonical-unsigned-v1.pdf as --document to drive an end-to-end demo without sourcing your own file.)
sign request create --spec ./request.json   (CLI flags --provider and --auto-approve still apply on top of the spec)
sign request run-email --title "Doc" --document ./file.pdf [--document ./extra.pdf] --signer name:Alice,email:alice@example.com,order:1 [--field signer:1,doc:0,page:1,x:100,y:200,type:signature] [--provider dropbox|docusign|signwell] [--test-mode true]
sign request from-template --template-id <id> --signer role:Buyer,name:Alice,email:alice@example.com,order:1 [--prefill name:purchase_price,value:1000] [--title "..."] [--provider dropbox|docusign|signwell] [--auto-approve true]
sign approve --request-id <id> --token <token> [--agree true] [--accept-disclosure true] [--verification-code <code>] [--identity-assurance method:...,verifier:...,reference:...]
sign consent show   (print the canonical intent-to-sign + electronic-records disclosure texts, version ids, SHA-256)
sign sign --request-id <id> --token <token> [--signer-email <e>] [--signer-name <n>] [--require-hash <sha256>] [--require-title <regex>] [--require-signer-email <e>] [--signature-image <path-or-data-url> [--image-page <n> --image-x <pt> --image-y <pt> --image-width <pt> --image-height <pt>]]
sign pdf stamp --pdf ./doc.pdf --image ./sig.png|sig.svg|"data:image/svg+xml;base64,..." --image-page 1 --image-x 100 --image-y 200 --image-width 150 --image-height 60 --out ./stamped.pdf   (standalone — no signing request involved; SVG is rasterized at ~300 DPI of the target rectangle)
sign pdf stamp verify --pdf ./stamped.pdf --image-page 1 --image-x 100 --image-y 200 --image-width 150 --image-height 60
  Confirms an image is drawn at the expected box within ±1pt. Exit 0=ok, 3=wrong_position, 4=missing.
  Limitation: only matches stamps with unrotated transforms (the shape stampImageOnPdf itself produces).
sign workflow nda --values ./values.json --party-a-email alice@... --party-b-email bob@... --out ./nda.pdf [--template ./custom.md] [--title "..."] [--auto-approve] [--provider local|...]
  One-shot: renders the bundled mutual-NDA template (or --template) with --values, writes the PDF, and creates a 2-signer request. --auto-approve sends immediately.
sign signer list [--signer-email <e>]
sign signer fetch-document --request-id <id> --token <token> [--out ./doc.pdf] [--signer-email <e>]
sign signer decline --request-id <id> --token <token> [--signer-email <e>] [--reason "..."]
sign signer reissue-token --request-id <id> --signer-email <e> [--token-ttl-minutes 30]
sign signer send-verification --request-id <id> --email <signer> [--ttl-minutes 15]   (issue an email-verification code; delivered via SIGN_VERIFICATION_WEBHOOK_URL or out-of-band)
sign signer verify-email --request-id <id> --email <signer> --code <6-digit>   (redeem the code; records request.signer_email_verified)
sign signer record-identity --request-id <id> --email <signer> --identity-assurance method:in-person[,verifier:...][,reference:...]   (record how identity was checked — the assertion, not the evidence)
sign signer watch [--signer-email <e>] [--exit-on-first true] [--interval-seconds 1] [--timeout-seconds 600]
sign signer policy run --request-id <id> --token <token> --spec ./policy.json [--dry-run true]
sign signer policy run-all --tokens-file ./tokens.json --spec ./policy.json [--signer-email <e>] [--dry-run true]   (apply policy to every pending request the agent has a token for)
sign signer policy run-watch --tokens-file ./tokens.json --spec ./policy.json [--signer-email <e>] [--dry-run true] [--exit-on-first true] [--interval-seconds 1] [--timeout-seconds 600] [--report ./out.ndjson] [--on-decision "<cmd>"] [--since-anchor latest|<artifactId>]   (long-running: tail the inbox + apply the policy; --since-anchor evaluates only entries created after the named anchor was issued; exits 3 if any row failed, 4 on timeout)
sign signer policy try --spec ./policy.json (--title "..." --document-sha256 <hex> --signer-email <e> | --snapshot ./snap.json | --batch ./contexts.json)   (offline tester — single context or a JSON array of contexts; never touches state)
sign signer policy diff --before ./old.json --after ./new.json (--snapshot ./snap.json | --inbox [--signer-email <e>]) [--format json|markdown]   (preview action changes between two specs; --format markdown renders a reviewer-friendly table)
sign signer policy lint --spec ./policy.json   (static checks: invalid regex, unreachable rules after match: "any", redundant rules, decline-without-reason)
sign request send --request-id <id> [--provider dropbox|docusign|signwell] [--test-mode true] [--force true]
sign request send-embedded --request-id <id> [--client-id <clientId>] [--provider dropbox|docusign|signwell] [--test-mode true]
sign request sign-url --request-id <id> --signature-id <signatureId> [--provider dropbox|docusign|signwell] [--return-url https://...]
sign request launch-embedded --request-id <id> --signature-id <signatureId> [--client-id <clientId>] [--provider dropbox|docusign|signwell] [--return-url https://...]
sign request fetch-final --request-id <id> [--provider dropbox|docusign|signwell] [--out ./artifacts/signed.pdf]
sign request status --request-id <id> [--provider dropbox|docusign|signwell] [--watch true [--interval-ms 5000] [--timeout-ms 600000] [--fetch-final true] [--out ./artifacts/signed.pdf]]
sign request watch --request-id <id> [--provider dropbox|docusign|signwell] [--interval-ms 5000|--interval-seconds 5] [--timeout-ms 600000|--timeout-seconds 600] [--fetch-final true] [--out ./artifacts/signed.pdf] [--log human|json]
sign request remind --request-id <id> [--provider dropbox|docusign|signwell] [--email signer@example.com]
sign request cancel --request-id <id> [--provider dropbox|docusign|signwell] [--reason "Voided"] [--yes]
sign request bulk --csv ./signers.csv --document ./file.pdf [--document ./extra.pdf] [--provider dropbox|docusign|signwell|local] [--title "Bulk for {{email}}"] [--test-mode true] [--emit-tokens ./tokens.json] [--ndjson true]
sign request bulk-resend --csv ./resend.csv [--token-ttl-minutes 30] [--emit-tokens ./tokens.json] [--ndjson true]   (re-issue signer tokens from a CSV roster — rows: request_id,signer_email[,token_ttl_minutes]; per-row failures are captured, exits 3 if any failed)
sign request list [--provider dropbox|docusign|signwell|local] [--status created|sent|approved|completed|canceled] [--since 2026-05-01T00:00:00Z] [--limit 100] [--format json|table]
sign request show --request-id <id> [--metrics true] [--hash-only true] [--recipient <email>]
sign request diff --before <id> --after <id>   (compare two requests; exits 1 on any diff, 0 on identical)
sign request rerun-policy --request-id <id> --spec ./policy.json [--signer-email <e>]   (re-evaluate a stored request against an updated policy spec; pure read)
sign smoke signwell --document ./file.pdf [--signer-name Name] [--signer-email a@b] [--interval-seconds 5] [--timeout-seconds 60] [--fetch-final true] [--out ./artifacts/signed.pdf]
sign demo [--document ./file.pdf] [--out ./demo-bundle/]
sign selftest [--keep-workspace true]   (in-process E2E smoke; exits 3 on any failure — drop-in for deploy health checks)

Global flags affecting mutating commands:
  [--provider dropbox|docusign|signwell|local]  (also via SIGN_PROVIDER env; default local — offline, no credentials)
  [--strict-provider true]                      (or SIGN_STRICT_PROVIDER=true; fails if --provider mismatches the persisted provider)
Every mutating command (create / send / sign) prints a one-line "[sign] resolved provider: <p> (<source>)" banner to stderr and embeds the same in its JSON output under "resolved_provider".
sign init [--out ./.env]
sign db backup --out ./backup.db
sign db verify
sign db migrate [--dry-run true]   (apply pending versioned migrations; --dry-run prints the queue without changing state)
sign db indexes [--explain "SELECT ..."] [--suggest true [--suggest-threshold 1000]]   (SQLite catalog: list indexes, run EXPLAIN QUERY PLAN, suggest under-indexed tables)
sign db indexes-postgres --pg-url postgres://… [--schema public] [--explain "SELECT ..."] [--suggest true [--suggest-threshold 1000]]   (Postgres catalog: pg_indexes companion to db indexes)
sign db vacuum [--backend sqlite|postgres] [--pg-url postgres://…]   (SQLite: VACUUM + PRAGMA optimize; Postgres: VACUUM ANALYZE)
sign db rotate-keys [--key-dir ./data/local-keys] [--re-sign-receipts true]   (re-issue the local signer keypair; --re-sign-receipts also walks every previously-issued receipt and re-signs each manifest with the new key; records request.receipt_resigned per row)
sign db migrate-postgres --pg-url postgres://…   (one-shot Postgres bootstrap: create the ported schema + append-only triggers; idempotent)
sign db postgres-smoke --pg-url postgres://…   (end-to-end async-against-pg integration probe — bootstrap + insert + chain extension + verify; exits 3 on any step failure)
sign db backend [--backend sqlite|postgres]   (report the active storage backend)
sign mcp serve [--read-only true] [--tool <name> ...] [--capability tools|resources|prompts ...] [--emit-events ./mcp.ndjson [--emit-events-redact true]]  (stdio MCP server; --emit-events tees every JSON-RPC message in/out to NDJSON; --emit-events-redact masks token-shaped fields in the log; --capability/--tool/--read-only further restrict the surface)
sign mcp tools [--format json|markdown]   (one-shot tool catalog with input + output JSON-Schema; markdown renders a docs page)
sign serve [--port 4000] [--bind 127.0.0.1] [--auth-token <t>] [--tls-cert ./cert.pem --tls-key ./key.pem [--tls-ca ./ca.pem]] [--web-demo true|<dir>] [--rate-limit <rps> [--rate-limit-burst <n>]] [--read-only true]   (HTTP REST surface; --read-only blocks the four lifecycle-mutating routes with FORBIDDEN_READ_ONLY)
sign completion bash|zsh|fish   (print a completion script; pipe into your shell init)

Global flags: [--verbose true]   Env: SIGN_DEBUG=1, SIGN_HTTP_MAX_RETRIES, SIGN_HTTP_BASE_DELAY_MS, SIGN_MAX_DOCUMENT_BYTES, SIGN_ALLOW_ABSOLUTE_DOCS
sign doctor
sign doctor account-check [--provider dropbox|docusign|signwell]
sign doctor providers
sign doctor preflight [--provider dropbox|docusign|signwell|local]
  Cheap pre-run checks (env vars, dir permissions, lightweight provider connectivity).
  Exit 0 if all checks pass, 1 if any fail. Use to gate CI before running create/send.
sign audit show --request-id <id> [--format json|csv|pretty] [--event-type <t> ...] [--since <iso>] [--until <iso>]   (--format pretty renders a human-readable timeline; --since/--until clamp the time window)
sign audit search [--request-id <id>] [--event-type request.signed] [--since <iso>] [--until <iso>] [--payload-contains <substr>] [--limit 1000]   (log-style filter across the full audit_events table)
sign audit verify --request-id <id>
sign audit scan [--provider dropbox|docusign|signwell|local] [--status <s>] [--limit 1000]   (verify every request's chain in one shot; exits 3 if any break)
sign audit watch [--request-id <id>] [--interval-seconds 5] [--timeout-seconds 600]   (long-running tamper alarm; exits 3 on break, 4 on timeout)
sign audit timestamp --request-id <id> [--tsa-url http://timestamp.digicert.com]
sign audit anchor [--tsa-url http://timestamp.digicert.com] [--out ./artifacts/] [--since 2026-05-01T00:00:00Z | --since-anchor latest|<artifactId>] [--dry-run true]   (anchor every request's chain head with one TSA call; --dry-run prints the manifest + digest without contacting the TSA or writing artifacts)
sign audit verify-anchor --manifest ./audit-anchor-…manifest.json   (re-check a stored anchor against the current DB; exits 3 if any chain looks tampered or missing)
sign audit anchors-list [--limit 100]   (list stored anchors with digest/tsaUrl/coveredRequests so an operator can pick which one to verify)
sign audit chain-bundle --out ./bundle/ [--request-id <id> ...] [--tarball ./bundle.tar.gz] [--include-source-pdf true]   (compliance bundle: most-recent anchor + per-request receipts + INDEX.json; --tarball writes a portable .tar.gz; --include-source-pdf copies the unsigned source PDF into each receipt dir for reproducibility)
sign audit verify-chain-bundle (--bundle ./bundle/ | --tarball ./bundle.tar.gz) [--report ./out.ndjson]   (re-check a previously-issued chain bundle: INDEX.json + anchor digest + every per-request receipt; --tarball extracts to a temp dir; --report streams per-request results as NDJSON; exits 3 on any failure)
sign audit export --request-id <id> --out ./bundle/
sign request receipt --request-id <id> --out ./receipt/   (signed-manifest bundle: audit + signed PDF + signature.bin + cert.pem)
sign audit issue-receipts --out ./receipts/ [--provider local] [--status completed] [--limit 1000] [--ndjson true]   (bulk-emit one receipt-bundle per matching request; exits 3 if any row failed)
sign request create --spec ./request.json [--param key=value ...]   (variable substitution into the spec JSON)
sign request verify-signed-pdf --request-id <id> [--path ./signed.pdf]
  Exit codes: 0=ok, 2=warnings_only, 3=digest_mismatch, 4=no_signature, 5=signer_mismatch.
  JSON includes a top-level "summary" with signature_present/digest_ok/signer_match/warnings_count/verdict.
sign webhook verify [--provider dropbox|signwell|docusign] --payload-file ./fixtures/sample-webhook.json [--signature-header <hmac>]
sign webhook ingest [--provider dropbox|signwell|docusign] --payload-file ./fixtures/sample-webhook.json [--signature-header <hmac>] [--request-id <id>]
sign webhook listen [--provider dropbox|signwell|docusign] [--port 3000] [--path /dropbox/callback] [--request-id <id>] [--pretty true]
sign metrics show   (print Prometheus text rendered from the local DB once)
sign metrics ship --url https://example.com/metrics [--bearer <t>] [--header K=V ...] [--interval-seconds 30] [--max-pushes <n>] [--batch-size <n>]   (long-running pusher; --batch-size N renders every interval but POSTs every Nth, bundling N snapshots per body)`);
}

function resolveProviderApiKey(provider: ReturnType<typeof resolveSignProvider>): string | undefined {
  if (provider === "dropbox") {
    return requireDropboxApiKey();
  }
  if (provider === "signwell") {
    return requireSignWellApiKey();
  }
  return undefined;
}

function resolveWebhookProvider(provider: SignProvider): "dropbox" | "signwell" | "docusign" {
  if (provider === "signwell") return "signwell";
  if (provider === "docusign") return "docusign";
  return "dropbox";
}

function resolveProviderTestMode(provider: ReturnType<typeof resolveSignProvider>, flag?: string): boolean {
  if (provider === "dropbox") {
    return resolveDropboxTestMode(flag);
  }
  if (provider === "signwell") {
    const testMode = resolveSignWellTestMode(flag);
    if (testMode) {
      // SignWell defaults to test mode (non-binding, watermarked). That's a footgun
      // for "send the real thing" flows, so make it impossible to miss. Banner goes
      // to stderr to keep stdout machine-readable.
      process.stderr.write(
        "\n" +
        "  ┌────────────────────────────────────────────────────────────────┐\n" +
        "  │  ⚠  SIGNWELL TEST MODE — this document is NON-BINDING.          │\n" +
        "  │     Signatures are watermarked and have no legal effect.        │\n" +
        "  │     To send a real, binding document, pass --test-mode false    │\n" +
        "  │     (or set SIGNWELL_TEST_MODE=false).                          │\n" +
        "  └────────────────────────────────────────────────────────────────┘\n\n",
      );
    }
    return testMode;
  }
  return false;
}

// `--ordered true|false` controls signing order for providers that support
// parallel/unordered signing (SignWell). Undefined means "use the provider
// default" (sequential when there are 2+ signers).
function resolveOrderedFlag(flag?: string): boolean | undefined {
  if (flag === undefined) {
    return undefined;
  }
  return parseBooleanFlag(flag, true);
}

async function main(): Promise<void> {
  loadEnv();
  const parsed = parseArgs(process.argv.slice(2));
  if ((flagValue(parsed, "verbose") ?? "false") === "true") {
    process.env.SIGN_DEBUG = "1";
  }

  // ── Profile bootstrap (must run BEFORE openDatabase) ────────────────────
  // The active profile may set `dbPath` and `credentials`. Both need to be
  // resolved before we open the DB and before any adapter reads its env
  // vars. The profile flag itself is purely additive — existing flag-only /
  // env-only invocations see no change because the profile layer is
  // consulted only when nothing higher in the resolution chain produced a
  // value.
  const { loadProfileContext, resolveFromProfile, applyCredentialsToProcessEnv } =
    await import("./lib/profiles.js");
  const profileCtx = loadProfileContext({
    profileFlag: flagValue(parsed, "profile"),
  });
  // Apply the active profile's credentials block to process.env BEFORE any
  // adapter consults its env vars. Atomic semantics: only the layer that
  // resolved `provider` contributes credentials.
  applyCredentialsToProcessEnv(profileCtx);

  // Resolve dbPath: flag (none yet) > env > profile (project > user) > default.
  // We don't have a per-command dbPath flag today, so the flag layer is
  // effectively skipped here.
  let dbPath = process.env.SIGN_DB_PATH;
  if (!dbPath) {
    const profileDb = resolveFromProfile("dbPath", profileCtx);
    if (profileDb) dbPath = profileDb.value;
  }
  if (!dbPath) dbPath = "./data/sign.db";

  const db = openDatabase(dbPath);

  // Resolve the provider AND remember how it was resolved, so mutating
  // commands can both print a stderr banner and embed `resolved_provider`
  // in their JSON output. See Item 1 of the product-readiness feedback.
  // Profile layer is consulted between env and the persisted-fallback layer
  // (see resolveSignProviderWithSource overload).
  const profileProvider = resolveFromProfile("provider", profileCtx);
  const resolvedProvider = resolveSignProviderWithSource(
    flagValue(parsed, "provider"),
    undefined,
    profileProvider ? { value: profileProvider.value, layer: profileProvider.source } : undefined,
  );
  const selectedProvider = resolvedProvider.provider;

  // Strict-provider: flag > env > profile.
  const profileStrict = resolveFromProfile("strictProvider", profileCtx);
  const strictProvider = strictProviderEnabled(
    flagValue(parsed, "strict-provider"),
    profileStrict?.value,
  );

  // Version flag — handled before any positional dispatch.
  if ((flagValue(parsed, "version") ?? "false") === "true") {
    const { SIGN_CLI_VERSION } = await import("./lib/help-catalog.js");
    console.log(SIGN_CLI_VERSION);
    return;
  }

  // Catalog flag — machine-readable command index.
  if (flagValue(parsed, "catalog") !== undefined) {
    console.log(JSON.stringify(buildCatalogJson(), null, 2));
    return;
  }

  // Help flag — show top-level help, or focused help when a command is named.
  if ((flagValue(parsed, "help") ?? "false") === "true" || parsed.positionals[0] === "help") {
    const queryPositionals = parsed.positionals[0] === "help" ? parsed.positionals.slice(1) : parsed.positionals;
    if (queryPositionals.length === 0) {
      console.log(formatTopLevelHelp());
      return;
    }
    // Try to find the longest-matching command (e.g. "signer policy run-all" first, then "signer policy run").
    for (let len = queryPositionals.length; len >= 1; len -= 1) {
      const query = queryPositionals.slice(0, len).join(" ");
      const found = findCommand(query);
      if (found) {
        console.log(formatCommandHelp(found));
        return;
      }
    }
    // No exact match — fall back to listing subcommands for a parent like "mcp".
    const group = findCommandGroup(queryPositionals.join(" "));
    if (group.length > 0) {
      console.log(formatCommandGroupHelp(queryPositionals.join(" "), group));
      return;
    }
    console.error(`No help entry for "${queryPositionals.join(" ")}". Run \`sign --help\` to list commands.`);
    process.exitCode = 1;
    return;
  }

  if (parsed.positionals.length === 0) {
    console.log(formatTopLevelHelp());
    return;
  }

  const [root, sub, action] = parsed.positionals;

  if (root === "examples") {
    console.log(formatExamples());
    return;
  }


  if (root === "doctor" && sub === "providers") {
    console.log(JSON.stringify(buildProviderMatrix(), null, 2));
    return;
  }

  if (root === "db" && sub === "backup") {
    const out = flagValue(parsed, "out", true)!;
    const result = backupDatabase(db, dbPath, out);
    console.log(JSON.stringify(result, null, 2));
    return;
  }

  if (root === "db" && sub === "verify") {
    const result = verifyDatabase(db);
    console.log(JSON.stringify(result, null, 2));
    process.exitCode = result.ok ? 0 : 3;
    return;
  }

  if (root === "db" && sub === "backend") {
    const { describeBackend, resolveBackend } = await import("./lib/storage.js");
    const backend = resolveBackend(flagValue(parsed, "backend"));
    console.log(JSON.stringify(describeBackend(backend), null, 2));
    return;
  }

  if (root === "db" && sub === "migrate") {
    const dryRun = (flagValue(parsed, "dry-run") ?? "false") === "true";
    const { applyPendingMigrations, listAppliedMigrations, MIGRATIONS } = await import("./lib/migrations.js");
    if (dryRun) {
      const applied = new Set(listAppliedMigrations(db).map((row) => row.id));
      const pending = MIGRATIONS.filter((m) => !applied.has(m.id)).map((m) => ({ id: m.id, name: m.name }));
      console.log(JSON.stringify({ pending, dryRun: true }, null, 2));
      return;
    }
    const outcome = applyPendingMigrations(db);
    console.log(JSON.stringify(outcome, null, 2));
    return;
  }

  if (root === "db" && sub === "indexes-postgres") {
    const url = flagValue(parsed, "pg-url") ?? process.env.SIGN_PG_URL;
    if (!url) {
      throw new SignCliError({
        code: "MISSING_FLAG",
        message: "db indexes-postgres requires --pg-url <postgres://…> (or SIGN_PG_URL env var).",
      });
    }
    const explainSql = flagValue(parsed, "explain");
    const suggest = (flagValue(parsed, "suggest") ?? "false") === "true";
    const schema = flagValue(parsed, "schema") ?? "public";
    const { openStorageBackend } = await import("./lib/storage.js");
    const { listPgIndexes, explainPgQueryPlan, suggestPgMissingIndexes } = await import("./lib/db-indexes-postgres.js");
    const backend = openStorageBackend({ backend: "postgres", postgresUrl: url });
    try {
      const out: Record<string, unknown> = { indexes: await listPgIndexes(backend, schema) };
      if (explainSql) out.queryPlan = await explainPgQueryPlan(backend, explainSql);
      if (suggest) {
        const threshold = flagValue(parsed, "suggest-threshold");
        out.suggestions = await suggestPgMissingIndexes(backend, threshold ? Number(threshold) : undefined, schema);
      }
      console.log(JSON.stringify(out, null, 2));
    } finally {
      await backend.close();
    }
    return;
  }

  if (root === "db" && sub === "rotate-keys") {
    const keyDir = flagValue(parsed, "key-dir");
    const reSign = (flagValue(parsed, "re-sign-receipts") ?? "false") === "true";
    const { rotateLocalSignerKeys } = await import("./lib/local-keys.js");
    const report = rotateLocalSignerKeys({ keyDir });
    let reSignReport: unknown = null;
    if (reSign) {
      const { reSignAllReceipts } = await import("./lib/signing-service.js");
      reSignReport = await reSignAllReceipts(db);
    }
    console.log(JSON.stringify({ ...report, reSignReceipts: reSignReport }, null, 2));
    return;
  }

  if (root === "db" && sub === "vacuum") {
    const target = (flagValue(parsed, "backend") ?? "sqlite").toLowerCase();
    if (target === "sqlite") {
      // SQLite VACUUM rebuilds the database file, reclaiming space; PRAGMA
      // optimize lets the planner refresh stats. Both are safe but block
      // writers — we tag them as ops actions, not lifecycle.
      const before = (db.prepare("PRAGMA page_count").get() as { page_count: number }).page_count;
      const pageSize = (db.prepare("PRAGMA page_size").get() as { page_size: number }).page_size;
      db.exec("VACUUM;");
      db.exec("PRAGMA optimize;");
      const after = (db.prepare("PRAGMA page_count").get() as { page_count: number }).page_count;
      console.log(JSON.stringify({
        backend: "sqlite",
        ranVacuum: true,
        ranOptimize: true,
        pageSize,
        pagesBefore: before,
        pagesAfter: after,
        bytesBefore: before * pageSize,
        bytesAfter: after * pageSize,
        bytesReclaimed: (before - after) * pageSize,
      }, null, 2));
      return;
    }
    if (target === "postgres") {
      const url = flagValue(parsed, "pg-url") ?? process.env.SIGN_PG_URL;
      if (!url) {
        throw new SignCliError({
          code: "MISSING_FLAG",
          message: "db vacuum --backend postgres requires --pg-url <postgres://…> (or SIGN_PG_URL env var).",
        });
      }
      const { openStorageBackend } = await import("./lib/storage.js");
      const backend = openStorageBackend({ backend: "postgres", postgresUrl: url });
      try {
        // VACUUM ANALYZE refreshes both space + planner stats. Cannot run
        // inside a transaction — execAsync issues it as a one-shot.
        await backend.execAsync("VACUUM ANALYZE");
        console.log(JSON.stringify({ backend: "postgres", ranVacuumAnalyze: true }, null, 2));
      } finally {
        await backend.close();
      }
      return;
    }
    throw new SignCliError({
      code: "INVALID_ARGS",
      message: `db vacuum --backend must be sqlite or postgres; got ${JSON.stringify(target)}.`,
    });
  }

  if (root === "db" && sub === "indexes") {
    const { listDbIndexes, explainQueryPlan, suggestMissingIndexes } = await import("./lib/db-indexes.js");
    const explainSql = flagValue(parsed, "explain");
    const suggest = (flagValue(parsed, "suggest") ?? "false") === "true";
    const out: Record<string, unknown> = { indexes: listDbIndexes(db) };
    if (explainSql) out.queryPlan = explainQueryPlan(db, explainSql);
    if (suggest) {
      const threshold = flagValue(parsed, "suggest-threshold");
      out.suggestions = suggestMissingIndexes(db, threshold ? Number(threshold) : undefined);
    }
    console.log(JSON.stringify(out, null, 2));
    return;
  }

  if (root === "db" && sub === "postgres-smoke") {
    const url = flagValue(parsed, "pg-url") ?? process.env.SIGN_PG_URL;
    if (!url) {
      throw new SignCliError({
        code: "MISSING_FLAG",
        message: "db postgres-smoke requires --pg-url <postgres://…> (or SIGN_PG_URL env var).",
      });
    }
    const { openStorageBackend } = await import("./lib/storage.js");
    const { runPostgresSmoke } = await import("./lib/postgres-smoke.js");
    const backend = openStorageBackend({ backend: "postgres", postgresUrl: url });
    try {
      const report = await runPostgresSmoke(backend);
      console.log(JSON.stringify(report, null, 2));
      if (!report.ok) process.exitCode = 3;
    } finally {
      await backend.close();
    }
    return;
  }

  if (root === "db" && sub === "migrate-postgres") {
    const url = flagValue(parsed, "pg-url") ?? process.env.SIGN_PG_URL;
    if (!url) {
      throw new SignCliError({
        code: "MISSING_FLAG",
        message: "db migrate-postgres requires --pg-url <postgres://…> (or SIGN_PG_URL env var).",
      });
    }
    const { openStorageBackend } = await import("./lib/storage.js");
    const { bootstrapPostgresSchema } = await import("./lib/postgres-bootstrap.js");
    const backend = openStorageBackend({ backend: "postgres", postgresUrl: url });
    try {
      const report = await bootstrapPostgresSchema(backend);
      console.log(JSON.stringify({ ok: true, ...report }, null, 2));
    } finally {
      await backend.close();
    }
    return;
  }

  if (root === "init") {
    const { io, close } = createDefaultIo();
    try {
      const answers = await collectInitAnswers(io);
      const result = writeEnvFile(answers, { path: flagValue(parsed, "out") });
      console.log(JSON.stringify({ provider: answers.provider, ...result }, null, 2));
    } finally {
      close();
    }
    return;
  }

  if (root === "demo") {
    const out = flagValue(parsed, "out");
    const document = flagValue(parsed, "document");
    const result = await runLocalDemo(db, {
      documentPath: document,
      outDir: out,
      onProgress: (line) => console.error(line),
    });
    console.log(JSON.stringify(result, null, 2));
    return;
  }

  if (root === "selftest") {
    const keep = (flagValue(parsed, "keep-workspace") ?? "false") === "true";
    const report = await runSelftest({ keepWorkspace: keep });
    console.log(JSON.stringify(report, null, 2));
    process.exitCode = report.ok ? 0 : 3;
    return;
  }

  if (root === "smoke" && sub === "signwell") {
    const documentPath = flagValue(parsed, "document", true)!;
    const apiKey = requireSignWellApiKey();
    const signerName = flagValue(parsed, "signer-name");
    const signerEmail = flagValue(parsed, "signer-email");
    const intervalMs = parseDurationMs(parsed, { msFlag: "interval-ms", secondsFlag: "interval-seconds", defaultMs: 5000, minMs: 50 })!;
    const timeoutMs = parseDurationMs(parsed, { msFlag: "timeout-ms", secondsFlag: "timeout-seconds", defaultMs: 60_000 })!;
    const fetchFinalPdf = (flagValue(parsed, "fetch-final") ?? "false") === "true";
    const outPath = flagValue(parsed, "out");
    const result = await runSignWellSmokeTest(db, {
      apiKey,
      documentPath,
      title: flagValue(parsed, "title"),
      signerName,
      signerEmail,
      intervalMs,
      timeoutMs,
      fetchFinalPdf,
      outPath,
      onProgress: (line) => console.error(line),
    });
    console.log(JSON.stringify(result, null, 2));
    return;
  }

  if (root === "doctor" && sub === "account-check") {
    const result = await runProviderAccountCheck({
      provider: selectedProvider,
      apiKey: selectedProvider === "dropbox"
        ? process.env.DROPBOX_SIGN_API_KEY
        : selectedProvider === "signwell"
          ? process.env.SIGNWELL_API_KEY
          : undefined,
    });
    console.log(JSON.stringify(result, null, 2));
    return;
  }

  if (root === "doctor" && sub === "preflight") {
    const report = await runPreflight(selectedProvider);
    process.stderr.write(
      `[sign] preflight: ${report.summary.verdict} ` +
      `(provider=${report.provider}, ` +
      `${report.summary.passed} ok, ${report.summary.failed} failed, ${report.summary.skipped} skipped)\n`,
    );
    console.log(JSON.stringify(report, null, 2));
    process.exitCode = preflightExitCode(report.summary.verdict);
    return;
  }

  if (root === "doctor") {
    const apiKey = process.env.DROPBOX_SIGN_API_KEY;
    const result = await runDoctor(apiKey);
    console.log(JSON.stringify(result, null, 2));
    return;
  }


  if (root === "request" && sub === "run-email") {
    const title = flagValue(parsed, "title", true)!;
    const documentPaths = flagValues(parsed, "document");
    if (documentPaths.length === 0) {
      throw new Error("Missing required flag: --document");
    }
    documentPaths.forEach((p) => validateDocumentPath(p));
    const signers = flagValues(parsed, "signer").map(parseSignerSpec);
    signers.forEach((signer) => validateEmail(signer.email, "Signer email"));
    validateSignerCount(signers.length);
    const fields = flagValues(parsed, "field").map(parseFieldSpec);
    validateFieldCount(fields.length);
    const tokenTtlMinutes = Number(flagValue(parsed, "token-ttl-minutes") ?? "30");
    const created = createSigningRequest(db, {
      title,
      documentPaths,
      signers,
      fields,
      tokenTtlMinutes,
      provider: selectedProvider,
      autoApprove: true,
    });
    const sent = await sendSigningRequest(db, {
      requestId: created.requestId,
      provider: selectedProvider,
      apiKey: resolveProviderApiKey(selectedProvider),
      testMode: resolveProviderTestMode(selectedProvider, flagValue(parsed, "test-mode")),
      applySigningOrder: resolveOrderedFlag(flagValue(parsed, "ordered")),
    });
    console.log(JSON.stringify({
      mode: "email-only",
      provider: selectedProvider,
      requestId: created.requestId,
      documentHash: created.documentHash,
      approvals: "auto-approved",
      signatureRequestId: sent.signatureRequestId,
    }, null, 2));
    return;
  }

  if (root === "request" && sub === "from-template") {
    const templateId = flagValue(parsed, "template-id", true)!;
    const title = flagValue(parsed, "title") ?? `Template ${templateId}`;
    const signers = flagValues(parsed, "signer").map(parseSignerSpec);
    signers.forEach((signer) => validateEmail(signer.email, "Signer email"));
    validateSignerCount(signers.length);
    const prefills = flagValues(parsed, "prefill").map(parsePrefillSpec);
    const tokenTtlMinutes = Number(flagValue(parsed, "token-ttl-minutes") ?? "60");
    const result = createSigningRequest(db, {
      title,
      templateId,
      signers,
      prefills,
      tokenTtlMinutes,
      provider: selectedProvider,
      autoApprove: (flagValue(parsed, "auto-approve") ?? "false") === "true",
    });
    console.log(JSON.stringify(result, null, 2));
    return;
  }

  if (root === "request" && sub === "create") {
    const specPath = flagValue(parsed, "spec");
    if (specPath) {
      const params: Record<string, string> = {};
      for (const raw of flagValues(parsed, "param")) {
        const eq = raw.indexOf("=");
        if (eq <= 0) {
          throw new SignCliError({
            code: "MISSING_FLAG",
            message: `--param must be of the form key=value, got "${raw}".`,
          });
        }
        params[raw.slice(0, eq).trim()] = raw.slice(eq + 1);
      }
      const spec = loadRequestSpec(specPath, params);
      const docPaths = spec.documentPath ? [spec.documentPath] : (spec.documentPaths ?? []);
      docPaths.forEach((p) => validateDocumentPath(p));
      spec.signers.forEach((signer) => validateEmail(signer.email, "Signer email"));
      validateSignerCount(spec.signers.length);
      validateFieldCount((spec.fields ?? []).length);
      const provider = flagValue(parsed, "provider") ? selectedProvider : (spec.provider ?? selectedProvider);
      const autoApproveFlag = flagValue(parsed, "auto-approve");
      const autoApprove = autoApproveFlag !== undefined ? autoApproveFlag === "true" : Boolean(spec.autoApprove);
      const requireConsentFlag = flagValue(parsed, "require-consent");
      const requireEmailVerificationFlag = flagValue(parsed, "require-email-verification");
      const result = createSigningRequest(db, {
        title: spec.title,
        ...(spec.documentPath ? { documentPath: spec.documentPath } : {}),
        ...(spec.documentPaths ? { documentPaths: spec.documentPaths } : {}),
        ...(spec.templateId ? { templateId: spec.templateId } : {}),
        signers: spec.signers,
        ...(spec.fields ? { fields: spec.fields } : {}),
        ...(spec.prefills ? { prefills: spec.prefills } : {}),
        tokenTtlMinutes: spec.tokenTtlMinutes ?? 60,
        provider,
        autoApprove,
        requireConsent: requireConsentFlag !== undefined ? requireConsentFlag === "true" : Boolean(spec.requireConsent),
        requireEmailVerification: requireEmailVerificationFlag !== undefined
          ? requireEmailVerificationFlag === "true"
          : Boolean(spec.requireEmailVerification),
        ...(flagValue(parsed, "idempotency-key") ? { idempotencyKey: flagValue(parsed, "idempotency-key")! } : {}),
      });
      console.log(JSON.stringify(result, null, 2));
      return;
    }
    const title = flagValue(parsed, "title", true)!;
    const documentPaths = flagValues(parsed, "document");
    if (documentPaths.length === 0) {
      throw new Error("Missing required flag: --document");
    }
    documentPaths.forEach((p) => validateDocumentPath(p));
    const signers = flagValues(parsed, "signer").map(parseSignerSpec);
    signers.forEach((signer) => validateEmail(signer.email, "Signer email"));
    validateSignerCount(signers.length);
    const fields = flagValues(parsed, "field").map(parseFieldSpec);
    validateFieldCount(fields.length);
    const tokenTtlMinutes = Number(flagValue(parsed, "token-ttl-minutes") ?? "60");
    printProviderBanner(resolvedProvider);
    const result = createSigningRequest(db, {
      title,
      documentPaths,
      signers,
      fields,
      tokenTtlMinutes,
      provider: selectedProvider,
      autoApprove: (flagValue(parsed, "auto-approve") ?? "false") === "true",
      requireConsent: (flagValue(parsed, "require-consent") ?? "false") === "true",
      requireEmailVerification: (flagValue(parsed, "require-email-verification") ?? "false") === "true",
      ...(flagValue(parsed, "idempotency-key") ? { idempotencyKey: flagValue(parsed, "idempotency-key")! } : {}),
    });
    emitJsonWithProvider(result, resolvedProvider);
    return;
  }

  if (root === "approve") {
    const requestId = flagValue(parsed, "request-id", true)!;
    const token = flagValue(parsed, "token", true)!;
    const identityAssuranceSpec = flagValue(parsed, "identity-assurance");
    const result = approveSigningRequest(db, {
      requestId,
      token,
      agree: (flagValue(parsed, "agree") ?? "false") === "true",
      acceptDisclosure: (flagValue(parsed, "accept-disclosure") ?? "false") === "true",
      verificationCode: flagValue(parsed, "verification-code"),
      ...(identityAssuranceSpec ? { identityAssurance: parseIdentityAssuranceSpec(identityAssuranceSpec) } : {}),
    });
    console.log(JSON.stringify(result, null, 2));
    return;
  }

  if (root === "consent" && (sub === "show" || sub === undefined)) {
    console.log(JSON.stringify({ statements: describeConsentStatements() }, null, 2));
    return;
  }

  if (root === "sign" && sub === undefined) {
    const requestId = flagValue(parsed, "request-id", true)!;
    const token = flagValue(parsed, "token", true)!;
    const signatureImageFlag = flagValue(parsed, "signature-image");
    const signatureImage = signatureImageFlag ? parseImageInput(signatureImageFlag) : undefined;
    const nameSignatureFlag = flagValue(parsed, "name-signature");
    // Accept either `--name-signature true` (rendering signer-name) or
    // `--name-signature "Custom Text"` (explicit text override).
    const nameSignatureText = (() => {
      if (nameSignatureFlag === undefined) return undefined;
      const lower = nameSignatureFlag.trim().toLowerCase();
      if (lower === "true" || lower === "yes" || lower === "1") {
        const overrideName = flagValue(parsed, "signer-name");
        if (!overrideName) {
          throw new SignCliError({
            code: "NAME_SIGNATURE_MISSING_TEXT",
            message: "--name-signature true requires --signer-name <text> (or pass --name-signature <text> directly).",
            hint: "Either pass --signer-name \"Your Name\" alongside --name-signature true, or use --name-signature \"Your Name\".",
          });
        }
        return overrideName;
      }
      if (lower === "false" || lower === "no" || lower === "0") return undefined;
      return nameSignatureFlag;
    })();
    if (signatureImage && nameSignatureText) {
      throw new SignCliError({
        code: "SIGN_VISIBLE_SIG_BOTH",
        message: "--signature-image and --name-signature are mutually exclusive.",
        hint: "Pick one path: an image for a real handwritten signature, or --name-signature for a rendered-name italic stamp.",
      });
    }
    let imagePosition = readImagePositionFlags(parsed);
    if ((signatureImage || nameSignatureText) && imagePosition && !isCompletePosition(imagePosition)) {
      throw new SignCliError({
        code: "SIGN_IMAGE_INCOMPLETE_POSITION",
        message: "A visible-signature flag was given with a partial position. " +
          "Pass all of --image-page, --image-x, --image-y, --image-width, --image-height, or none (and rely on the sender's SignatureField).",
      });
    }

    // --auto-place: detect signature-field rectangle(s) in the PDF and use
    // them as stamp positions. Only consulted when (a) a visible-signature
    // flag is set, AND (b) no explicit --image-* coords were given.
    //
    // Selectors (set via --auto-place <value>):
    //   true | yes | 1   exactly one high-confidence (>=0.8) candidate
    //   first            earliest page, top-of-page first
    //   last             latest page, bottom-of-page first
    //   all              every high-confidence candidate (multi-stamp)
    //   page:N           the unique candidate on page N
    //   index:N          the Nth candidate (0-indexed, confidence-sorted)
    //
    // The detector itself never silently picks a low-confidence rectangle.
    const autoPlaceFlagRaw = flagValue(parsed, "auto-place");
    let extraImagePositions: StampPosition[] = [];
    const { parseAutoPlaceMode, selectAutoPlaceCandidates, formatAutoPlaceChoice, InvalidAutoPlaceValue } =
      await import("./lib/auto-place-selector.js");
    let autoPlaceMode;
    try {
      autoPlaceMode = parseAutoPlaceMode(autoPlaceFlagRaw);
    } catch (err) {
      if (err instanceof InvalidAutoPlaceValue) {
        throw new SignCliError({
          code: "INVALID_AUTO_PLACE_VALUE",
          message: err.message,
          hint: err.hint,
        });
      }
      throw err;
    }
    if (autoPlaceMode.kind !== "none") {
      if (!signatureImage && !nameSignatureText) {
        throw new SignCliError({
          code: "AUTO_PLACE_REQUIRES_VISIBLE_SIG",
          message: "--auto-place requires a visible-signature flag (--signature-image or --name-signature).",
          hint: "Pass --name-signature \"Your Name\" or --signature-image <path> alongside --auto-place.",
        });
      }
      if (imagePosition && isCompletePosition(imagePosition)) {
        process.stderr.write(
          "[sign] --auto-place ignored: explicit --image-page/--image-x/--image-y/--image-width/--image-height supplied.\n",
        );
      } else {
        const { detectSignatureFields } = await import("./lib/signature-field-detection.js");
        const resource = readLocalDocumentForResource(db, requestId);
        const detection = await detectSignatureFields(resource.pdf);
        // `sign sign --auto-place` is signature-category only. Date anchors
        // belong to `sign pdf stamp-text` instead. Filtering here keeps a
        // PDF with both Signature: and Date: anchors from breaking existing
        // flows with AUTO_PLACE_AMBIGUOUS.
        const result = selectAutoPlaceCandidates(detection.signatureCandidates, autoPlaceMode);
        if (!result.ok) {
          throw new SignCliError({
            code: result.errorCode,
            message: result.message,
            hint: result.hint,
            details: { candidates: result.allCandidates },
          });
        }
        const [primary, ...rest] = result.chosen;
        imagePosition = {
          page: primary.page, x: primary.x, y: primary.y, width: primary.width, height: primary.height,
        };
        extraImagePositions = rest.map((c) => ({
          page: c.page, x: c.x, y: c.y, width: c.width, height: c.height,
        }));
        process.stderr.write(
          `[sign] --auto-place ${formatAutoPlaceFlag(autoPlaceMode)} chose ${formatAutoPlaceChoice(result.chosen)}\n`,
        );
      }
    }

    printProviderBanner(resolvedProvider);
    if (flagValue(parsed, "provider") && strictProvider) {
      const persisted = getPersistedProviderForRequest(db, requestId);
      if (persisted !== selectedProvider) {
        throw new SignCliError({
          code: "STRICT_PROVIDER_MISMATCH",
          message: `Strict provider check failed: --provider ${selectedProvider} but request ${requestId} was created against ${persisted}.`,
          hint: `Either rerun with --provider ${persisted}, or unset --strict-provider/SIGN_STRICT_PROVIDER to bypass.`,
        });
      }
    }
    const result = signSigningRequest(db, {
      requestId,
      token,
      signerEmail: flagValue(parsed, "signer-email"),
      signerName: flagValue(parsed, "signer-name"),
      requireHash: flagValue(parsed, "require-hash"),
      requireTitle: flagValue(parsed, "require-title"),
      requireSignerEmail: flagValue(parsed, "require-signer-email"),
      ...(flagValue(parsed, "provider") ? { runtimeProvider: selectedProvider, strictProvider } : {}),
      ...(signatureImage ? { signatureImage } : {}),
      ...(nameSignatureText ? { nameSignatureText } : {}),
      ...(imagePosition && isCompletePosition(imagePosition) ? { signatureImagePosition: imagePosition } : {}),
      ...(extraImagePositions.length > 0 ? { signatureImageExtraPositions: extraImagePositions } : {}),
      ...(signatureImage ? { signatureImageOptions: parseStampOptions(parsed) } : {}),
      ...(flagValue(parsed, "idempotency-key") ? { idempotencyKey: flagValue(parsed, "idempotency-key")! } : {}),
    });

    // Wrap with `ok: true` so the success envelope matches every other
    // command (audit gap closed). drawnRects intentionally omitted here:
    // `sign sign` writes the sealed PDF to the local provider's internal
    // store, not back to a caller-controlled path, so callers that want
    // to round-trip rectangles should use `sign document` (which probes
    // its own output) or fetch via `request fetch-final` + `pdf stamp
    // verify`.
    emitJsonWithProvider({ ok: true, ...result }, resolvedProvider);
    return;
  }

  if (root === "pdf" && sub === "stamp" && action === "verify") {
    const pdfPath = flagValue(parsed, "pdf", true)!;
    validateDocumentPath(pdfPath);
    const position = readImagePositionFlags(parsed);
    if (!position || !isCompletePosition(position)) {
      throw new SignCliError({
        code: "MISSING_FLAG",
        message:
          "sign pdf stamp verify requires --image-page, --image-x, --image-y, --image-width, and --image-height (all in PDF points; origin = bottom-left).",
      });
    }
    const fs = await import("node:fs");
    const pdfBytes = fs.readFileSync(pdfPath);
    const { verifyPdfStamp, stampVerifyExitCode } = await import("./lib/pdf-stamp-verify.js");
    const report = await verifyPdfStamp(pdfBytes, position);
    process.stderr.write(
      `[sign] pdf stamp verify: ${report.verdict} ` +
      `(page=${position.page}, ${report.candidates.length} draw${report.candidates.length === 1 ? "" : "s"} found)\n`,
    );
    console.log(JSON.stringify({ pdf: pdfPath, ...report }, null, 2));
    process.exitCode = stampVerifyExitCode(report.verdict);
    return;
  }

  if (root === "pdf" && sub === "stamp") {
    const pdfPath = flagValue(parsed, "pdf", true)!;
    validateDocumentPath(pdfPath);
    const imageFlag = flagValue(parsed, "image", true)!;
    const outPath = validateOutputPath(flagValue(parsed, "out", true)!);
    const position = readImagePositionFlags(parsed);
    if (!position || !isCompletePosition(position)) {
      throw new SignCliError({
        code: "MISSING_FLAG",
        message:
          "sign pdf stamp requires --image-page, --image-x, --image-y, --image-width, and --image-height (all in PDF points; origin = bottom-left).",
      });
    }
    const fs = await import("node:fs");
    const pdfBytes = fs.readFileSync(pdfPath);
    const stampOptions = parseStampOptions(parsed);
    const stamped = await stampImageOnPdf(pdfBytes, parseImageInput(imageFlag), position, stampOptions);
    fs.writeFileSync(outPath, stamped);

    // Quality warnings: run on the stamped PDF so the user sees any
    // structural issues (overlap, off-page, oversized) before they sign.
    // `--strict-quality true` makes the command exit non-zero when any
    // warning fires; default is advisory (still exit 0).
    const { assessStampQuality } = await import("./lib/stamp-quality.js");
    const warnings = await assessStampQuality({
      pdfBytes: stamped,
      page: position.page,
      x: position.x,
      y: position.y,
      width: position.width,
      height: position.height,
    });
    console.log(JSON.stringify(
      { ok: true, pdf: pdfPath, out: outPath, position, bytes: stamped.length, stampOptions, warnings },
      null, 2,
    ));
    const strictRaw = flagValue(parsed, "strict-quality");
    if (warnings.length > 0 && (strictRaw === "true" || strictRaw === "yes" || strictRaw === "1")) {
      process.stderr.write(`[sign] --strict-quality: ${warnings.length} quality warning(s); failing.\n`);
      process.exit(3);
    }
    return;
  }

  if (root === "profile") {
    const sub = parsed.positionals[1];
    const {
      defaultUserFilePath,
      findProjectFile,
      readUserFile,
      readProjectFile,
      writeProjectFile,
      initUserProfile,
      setProfileKey,
      deleteUserProfile,
      useUserProfile,
      resolveProfileView,
      redactCredentials,
      loadProfileContext: loadCtx,
    } = await import("./lib/profiles.js");
    const userFilePath = defaultUserFilePath();

    if (sub === "list") {
      const file = readUserFile(userFilePath);
      const projectPath = findProjectFile(process.cwd());
      console.log(JSON.stringify({
        ok: true,
        userFilePath,
        defaultProfile: file?.defaultProfile,
        profiles: file ? Object.keys(file.profiles).sort() : [],
        projectFile: projectPath ?? null,
        active: (() => {
          try { return loadCtx({ userFilePath }).activeSource; } catch { return { kind: "none" }; }
        })(),
      }, null, 2));
      return;
    }

    if (sub === "show") {
      const name = flagValue(parsed, "name");
      const showSecrets = flagValue(parsed, "show-secrets") === "true";
      // If --name given, show that user profile directly (with provenance =
      // user only). If not, show the active resolved view.
      if (name) {
        const file = readUserFile(userFilePath);
        if (!file || !file.profiles[name]) {
          throw new SignCliError({
            code: "PROFILE_NOT_FOUND",
            message: `No profile named '${name}' in ${userFilePath}.`,
            hint: file ? `Available: ${Object.keys(file.profiles).sort().join(", ")}.` : `No user profile file yet.`,
          });
        }
        const profile = file.profiles[name];
        const display = showSecrets ? profile : redactCredentials(profile);
        console.log(JSON.stringify({ ok: true, name, userFilePath, profile: display }, null, 2));
        return;
      }
      const ctx = loadCtx({ userFilePath });
      const view = resolveProfileView(ctx, { showSecrets });
      console.log(JSON.stringify({ ok: true, ...view }, null, 2));
      return;
    }

    if (sub === "use") {
      const name = flagValue(parsed, "name") ?? parsed.positionals[2];
      if (!name) {
        throw new SignCliError({
          code: "MISSING_FLAG",
          message: "sign profile use requires --name <name> (or a positional name).",
        });
      }
      const file = useUserProfile(userFilePath, name);
      console.log(JSON.stringify({ ok: true, defaultProfile: file.defaultProfile, userFilePath }, null, 2));
      return;
    }

    if (sub === "set") {
      const name = flagValue(parsed, "name", true)!;
      const key = flagValue(parsed, "key", true)!;
      const value = flagValue(parsed, "value", true)!;
      const file = setProfileKey({ filePath: userFilePath, name, key: key as never, value });
      console.log(JSON.stringify({ ok: true, name, key, profiles: Object.keys(file.profiles).sort(), userFilePath }, null, 2));
      return;
    }

    if (sub === "unset") {
      const name = flagValue(parsed, "name", true)!;
      const key = flagValue(parsed, "key", true)!;
      setProfileKey({ filePath: userFilePath, name, key: key as never, value: undefined });
      console.log(JSON.stringify({ ok: true, name, key, userFilePath }, null, 2));
      return;
    }

    if (sub === "delete") {
      const name = flagValue(parsed, "name", true)!;
      const yes = flagValue(parsed, "yes") === "true";
      if (!yes) {
        throw new SignCliError({
          code: "MISSING_FLAG",
          message: "sign profile delete requires --yes true to confirm.",
          hint: "Re-run with --yes true.",
        });
      }
      const file = deleteUserProfile(userFilePath, name);
      console.log(JSON.stringify({ ok: true, deleted: name, remaining: Object.keys(file.profiles).sort(), userFilePath }, null, 2));
      return;
    }

    if (sub === "init") {
      const name = flagValue(parsed, "name");
      const project = flagValue(parsed, "project") === "true";
      const setDefault = flagValue(parsed, "set-default") === "true";
      const provider = flagValue(parsed, "provider");
      const dbPathFlag = flagValue(parsed, "db");
      const strictFlag = flagValue(parsed, "strict-provider");
      const tokenTtl = flagValue(parsed, "default-token-ttl-minutes");
      const signerEmail = flagValue(parsed, "default-signer-email");

      const values: import("./lib/profiles.js").ProfileV1 = { version: 1 };
      if (provider) values.provider = provider as never;
      if (dbPathFlag) {
        // Validate the dbPath at config-write time so a malicious or
        // typo'd path doesn't get baked into the profile file. Allows
        // home-relative paths (~/...) without the absolute-docs opt-in,
        // since `~/.sign-cli/prod.db` is the documented example.
        values.dbPath = dbPathFlag;
        validateConfigPath(dbPathFlag);
      }
      if (strictFlag === "true") values.strictProvider = true;
      else if (strictFlag === "false") values.strictProvider = false;
      if (tokenTtl !== undefined) values.defaultTokenTtlMinutes = Number(tokenTtl);
      if (signerEmail) values.defaultSignerEmail = signerEmail;

      if (project) {
        const pathMod = await import("node:path");
        const target = pathMod.join(process.cwd(), "sign-profile.json");
        // Write the project-file shape (single object, no profiles{} map).
        writeProjectFile(target, values);
        console.log(JSON.stringify({ ok: true, kind: "project", path: target, profile: values }, null, 2));
        return;
      }
      if (!name) {
        throw new SignCliError({
          code: "MISSING_FLAG",
          message: "sign profile init requires --name <name> (or --project for a project-file init).",
        });
      }
      const file = initUserProfile({
        filePath: userFilePath, name,
        values,
        setAsDefault: setDefault,
      });
      console.log(JSON.stringify({ ok: true, kind: "user", name, userFilePath, profiles: Object.keys(file.profiles).sort(), defaultProfile: file.defaultProfile }, null, 2));
      return;
    }

    throw new SignCliError({
      code: "UNKNOWN_COMMAND",
      message: `Unknown profile subcommand: ${JSON.stringify(sub)}.`,
      hint: "Valid: list, show, use, set, unset, delete, init.",
    });
  }

  if (root === "document") {
    // One-shot DOCX|PDF → signed PDF. Delegates the heavy lifting to
    // signDocumentOneShot which orchestrates: docx2pdf conversion (if
    // needed) → auto-place detection → stamp + PAdES seal → verify →
    // copy output → cleanup. All temp DB / store / key state is
    // scoped to the call (the user's main ./data/sign.db is untouched).
    const inputPath = parsed.positionals[1] ?? flagValue(parsed, "input", true)!;
    validateDocumentPath(inputPath);
    const outPath = validateOutputPath(flagValue(parsed, "out", true)!);
    const signerName = flagValue(parsed, "signer") ?? flagValue(parsed, "signer-name");
    if (!signerName) {
      throw new SignCliError({
        code: "MISSING_FLAG",
        message: "sign document requires --signer \"<name>\" (the signer's full name).",
        hint: "Example: sign document file.docx --signer \"Baher Al Hakim\" --signature-image sig.png --auto-place first --out signed.pdf",
      });
    }
    const signerEmail = flagValue(parsed, "signer-email") ?? undefined;
    const title = flagValue(parsed, "title") ?? undefined;
    const signatureImage = flagValue(parsed, "signature-image");
    const nameSig = flagValue(parsed, "name-signature");

    const autoPlaceRaw = flagValue(parsed, "auto-place");
    const { parseAutoPlaceMode, InvalidAutoPlaceValue } = await import("./lib/auto-place-selector.js");
    let autoPlaceMode;
    try {
      autoPlaceMode = parseAutoPlaceMode(autoPlaceRaw);
    } catch (err) {
      if (err instanceof InvalidAutoPlaceValue) {
        throw new SignCliError({ code: "INVALID_AUTO_PLACE_VALUE", message: err.message, hint: err.hint });
      }
      throw err;
    }
    // Default for `sign document` is "first" — most one-shot flows have a
    // single signature anchor and "just sign there" is what the user wants.
    if (autoPlaceMode.kind === "none" && !readImagePositionFlags(parsed)) {
      autoPlaceMode = { kind: "first" } as const;
    }

    const imagePosition = readImagePositionFlags(parsed);

    const { signDocumentOneShot } = await import("./lib/sign-document.js");
    const result = await signDocumentOneShot({
      inputPath,
      outPath,
      signerName,
      signerEmail,
      title,
      signatureImage: signatureImage ? parseImageInput(signatureImage) : undefined,
      nameSignatureText: nameSig,
      autoPlaceMode,
      imagePosition: imagePosition && isCompletePosition(imagePosition) ? imagePosition : undefined,
      signatureImageOptions: signatureImage ? parseStampOptions(parsed) : undefined,
    });
    console.log(JSON.stringify(result, null, 2));
    return;
  }

  if (root === "preview") {
    // Standalone visual preview: stamp the image (or rendered name) onto the
    // PDF using the same pipeline as `sign sign`, but WITHOUT producing a
    // PAdES envelope or touching any signing-request state. The output is a
    // draft PDF you can open in a viewer to confirm the placement looks
    // right before sealing.
    const pdfPath = flagValue(parsed, "pdf", true)!;
    validateDocumentPath(pdfPath);
    const imageFlag = flagValue(parsed, "signature-image");
    const nameSig = flagValue(parsed, "name-signature");
    const outPath = validateOutputPath(flagValue(parsed, "out", true)!);
    if (!imageFlag && !nameSig) {
      throw new SignCliError({
        code: "MISSING_FLAG",
        message: "sign preview requires --signature-image or --name-signature.",
        hint: "Pass --signature-image <path|data-url> or --name-signature \"Your Name\".",
      });
    }
    if (imageFlag && nameSig) {
      throw new SignCliError({
        code: "SIGN_VISIBLE_SIG_BOTH",
        message: "--signature-image and --name-signature are mutually exclusive.",
        hint: "Pick one for the preview.",
      });
    }
    const fs = await import("node:fs");
    let pdfBytes: Buffer = fs.readFileSync(pdfPath);

    // Resolve position(s): either explicit --image-* or --auto-place.
    let primary = readImagePositionFlags(parsed);
    let extras: StampPosition[] = [];
    const autoPlaceFlagRaw = flagValue(parsed, "auto-place");
    const { parseAutoPlaceMode, selectAutoPlaceCandidates, formatAutoPlaceChoice, InvalidAutoPlaceValue } =
      await import("./lib/auto-place-selector.js");
    let mode;
    try {
      mode = parseAutoPlaceMode(autoPlaceFlagRaw);
    } catch (err) {
      if (err instanceof InvalidAutoPlaceValue) {
        throw new SignCliError({ code: "INVALID_AUTO_PLACE_VALUE", message: err.message, hint: err.hint });
      }
      throw err;
    }
    if (mode.kind !== "none") {
      if (primary && isCompletePosition(primary)) {
        process.stderr.write("[sign] --auto-place ignored: explicit --image-* coords supplied.\n");
      } else {
        const { detectSignatureFields } = await import("./lib/signature-field-detection.js");
        const detection = await detectSignatureFields(pdfBytes);
        // `sign preview` is a draft of the signature stamp — uses signature
        // candidates only. For preview of date stamps, use `sign pdf
        // stamp-text` (which writes the stamp directly; preview is implicit).
        const result = selectAutoPlaceCandidates(detection.signatureCandidates, mode);
        if (!result.ok) {
          throw new SignCliError({
            code: result.errorCode,
            message: result.message,
            hint: result.hint,
            details: { candidates: result.allCandidates },
          });
        }
        const [first, ...rest] = result.chosen;
        primary = { page: first.page, x: first.x, y: first.y, width: first.width, height: first.height };
        extras = rest.map((c) => ({ page: c.page, x: c.x, y: c.y, width: c.width, height: c.height }));
        process.stderr.write(`[sign] preview --auto-place chose ${formatAutoPlaceChoice(result.chosen)}\n`);
      }
    }
    if (!primary || !isCompletePosition(primary)) {
      throw new SignCliError({
        code: "MISSING_FLAG",
        message: "sign preview requires a stamp position: pass --auto-place or --image-page/--image-x/--image-y/--image-width/--image-height.",
      });
    }

    const stampOptions = parseStampOptions(parsed);
    const positions = [primary, ...extras];
    for (const pos of positions) {
      if (imageFlag) {
        pdfBytes = await stampImageOnPdf(pdfBytes, parseImageInput(imageFlag), pos, stampOptions);
      } else {
        const { stampTextOnPdf } = await import("./lib/pdf-image-stamp.js");
        pdfBytes = await stampTextOnPdf(pdfBytes, nameSig!, pos);
      }
    }
    fs.writeFileSync(outPath, pdfBytes);

    // Quality assessment + drawn-rect probe on the final preview, summed
    // across positions. `drawnRects` are read back from the PDF's content
    // streams, so callers can round-trip them through `pdf stamp verify`
    // even when --preserve-aspect-ratio shrunk the actual draw. Same
    // semantic as `sign document`'s drawnRects field.
    const { assessStampQuality } = await import("./lib/stamp-quality.js");
    const { verifyPdfStamp } = await import("./lib/pdf-stamp-verify.js");
    const allWarnings = [];
    const drawnRects: StampPosition[] = [];
    for (const pos of positions) {
      const w = await assessStampQuality({
        pdfBytes, page: pos.page, x: pos.x, y: pos.y, width: pos.width, height: pos.height,
      });
      allWarnings.push(...w);
      const probe = await verifyPdfStamp(pdfBytes, pos);
      if (probe.found) {
        drawnRects.push({
          page: probe.found.page, x: probe.found.x, y: probe.found.y,
          width: probe.found.width, height: probe.found.height,
        });
      }
    }
    console.log(JSON.stringify({
      ok: true,
      pdf: pdfPath,
      out: outPath,
      positions,
      drawnRects,
      bytes: pdfBytes.length,
      sealed: false,
      stampOptions,
      warnings: allWarnings,
    }, null, 2));
    return;
  }

  if (root === "pdf" && sub === "detect-signature-field") {
    // Backward-compat: returns only signature candidates. Date candidates
    // (added in the date-handling feature) live under `sign pdf
    // detect-date-field`.
    const pdfPath = flagValue(parsed, "pdf", true)!;
    validateDocumentPath(pdfPath);
    const verboseFlag = flagValue(parsed, "verbose");
    const verbose = verboseFlag === "true" || verboseFlag === "yes" || verboseFlag === "1";
    const fs = await import("node:fs");
    const { detectSignatureFields } = await import("./lib/signature-field-detection.js");
    const pdfBytes = fs.readFileSync(pdfPath);
    const result = await detectSignatureFields(pdfBytes, { verbose });
    // Project the response down to signature candidates so existing scripts
    // continue to see only the rectangles relevant to stamping a signature.
    const payload = {
      ok: true,
      pdf: pdfPath,
      pageCount: result.pageCount,
      acroFormFields: result.acroFormFields,
      anchorMatches: result.signatureCandidates.length,
      candidates: result.signatureCandidates,
      ...(verbose ? { textItemsByPage: result.textItemsByPage, pageDimensions: result.pageDimensions } : {}),
    };
    console.log(JSON.stringify(payload, null, 2));
    if (payload.candidates.length === 0) process.exit(2);
    return;
  }

  if (root === "pdf" && sub === "detect-date-field") {
    // Mirror of detect-signature-field, but for date anchors (Date:, Date de
    // signature:, Date d'effet:, etc.). Each candidate carries
    // `alreadyFilled: true` when a recognisable date string is already
    // present near the anchor — callers stamping a date can skip those.
    const pdfPath = flagValue(parsed, "pdf", true)!;
    validateDocumentPath(pdfPath);
    const verboseFlag = flagValue(parsed, "verbose");
    const verbose = verboseFlag === "true" || verboseFlag === "yes" || verboseFlag === "1";
    const fs = await import("node:fs");
    const { detectSignatureFields } = await import("./lib/signature-field-detection.js");
    const pdfBytes = fs.readFileSync(pdfPath);
    const result = await detectSignatureFields(pdfBytes, { verbose });
    const payload = {
      ok: true,
      pdf: pdfPath,
      pageCount: result.pageCount,
      anchorMatches: result.dateCandidates.length,
      candidates: result.dateCandidates,
      ...(verbose ? { textItemsByPage: result.textItemsByPage, pageDimensions: result.pageDimensions } : {}),
    };
    console.log(JSON.stringify(payload, null, 2));
    if (payload.candidates.length === 0) process.exit(2);
    return;
  }

  if (root === "pdf" && sub === "inspect") {
    // Inspect signatures on ANY signed PDF — ours, Adobe's, DocuSign's,
    // Dropbox Sign's, SignWell's. Pure read; no DB interaction, no audit
    // events. Returns the full PdfSignatureReport: signer CN/email, cert
    // subject + issuer, validity window, fingerprint, trust label, message
    // digest match, parse warnings, and the canonical /ByteRange bounds.
    //
    // Trust label is structural (issuer == subject → self-signed; issuer
    // matches our built-in subject → self_signed_local; otherwise
    // self_signed_other or ca_signed). We don't chain to any trust store
    // and don't check expiry; for that, use an external verifier.
    const pdfPath = flagValue(parsed, "pdf", true)!;
    validateDocumentPath(pdfPath);
    const { inspectPdfSignatures } = await import("./lib/pdf-signature.js");
    const report = await inspectPdfSignatures(pdfPath);
    process.stderr.write(
      `[sign] pdf inspect: ${report.signatureCount} signature${report.signatureCount === 1 ? "" : "s"} ` +
      `(hasSignature=${report.hasSignature}, warnings=${report.warnings.length})\n`,
    );
    console.log(JSON.stringify({ ok: true, ...report }, null, 2));
    // Exit 2 when the file isn't signed — same convention as
    // `pdf detect-signature-field` (no candidates → exit 2). Lets a CI
    // gate "fail if not signed" with a one-line check.
    if (!report.hasSignature) process.exit(2);
    return;
  }

  if (root === "pdf" && sub === "stamp-text") {
    // Stamp a text string (e.g. a date) onto a PDF. Mirrors `pdf stamp` for
    // images but uses Helvetica regular without italic/underline. Supports
    // --auto-place to fill detected DATE anchors (sign sign --auto-place
    // covers SIGNATURE anchors). By default, candidates where a date is
    // already filled in nearby are skipped — pass `--overwrite-filled true`
    // to ignore that protection.
    const pdfPath = flagValue(parsed, "pdf", true)!;
    validateDocumentPath(pdfPath);
    const text = flagValue(parsed, "text", true)!;
    const outPath = validateOutputPath(flagValue(parsed, "out", true)!);
    const fs = await import("node:fs");
    let pdfBytes: Buffer = fs.readFileSync(pdfPath);

    let primary = readImagePositionFlags(parsed);
    let extras: StampPosition[] = [];
    const autoPlaceFlagRaw = flagValue(parsed, "auto-place");
    const overwriteFilledRaw = flagValue(parsed, "overwrite-filled");
    const overwriteFilled = overwriteFilledRaw === "true" || overwriteFilledRaw === "yes" || overwriteFilledRaw === "1";
    const { parseAutoPlaceMode, selectAutoPlaceCandidates, formatAutoPlaceChoice, InvalidAutoPlaceValue } =
      await import("./lib/auto-place-selector.js");
    let mode;
    try {
      mode = parseAutoPlaceMode(autoPlaceFlagRaw);
    } catch (err) {
      if (err instanceof InvalidAutoPlaceValue) {
        throw new SignCliError({ code: "INVALID_AUTO_PLACE_VALUE", message: err.message, hint: err.hint });
      }
      throw err;
    }
    if (mode.kind !== "none") {
      if (primary && isCompletePosition(primary)) {
        process.stderr.write("[sign] --auto-place ignored: explicit --image-* coords supplied.\n");
      } else {
        const { detectSignatureFields } = await import("./lib/signature-field-detection.js");
        const detection = await detectSignatureFields(pdfBytes);
        // Filter to DATE candidates. Default: skip alreadyFilled. Caller
        // can opt back in with --overwrite-filled true.
        const datePool = overwriteFilled
          ? detection.dateCandidates
          : detection.dateCandidates.filter((c) => !c.alreadyFilled);
        const result = selectAutoPlaceCandidates(datePool, mode);
        if (!result.ok) {
          // When the date pool is empty BECAUSE alreadyFilled candidates
          // were filtered out, point the user at --overwrite-filled rather
          // than the generic AUTO_PLACE_NO_HIGH_CONFIDENCE hint about
          // missing anchors.
          const skippedFilled =
            !overwriteFilled &&
            datePool.length === 0 &&
            detection.dateCandidates.some((c) => c.alreadyFilled);
          throw new SignCliError({
            code: result.errorCode,
            message: result.message,
            hint: skippedFilled
              ? `${detection.dateCandidates.filter((c) => c.alreadyFilled).length} date candidate(s) were skipped because a date string appears already filled in nearby. Pass --overwrite-filled true to include them, or pass --image-* explicitly with one of the rectangles in details.allDateCandidates.`
              : result.hint,
            details: { candidates: datePool, allDateCandidates: detection.dateCandidates },
          });
        }
        const [first, ...rest] = result.chosen;
        primary = { page: first.page, x: first.x, y: first.y, width: first.width, height: first.height };
        extras = rest.map((c) => ({ page: c.page, x: c.x, y: c.y, width: c.width, height: c.height }));
        process.stderr.write(`[sign] stamp-text --auto-place chose ${formatAutoPlaceChoice(result.chosen)}\n`);
      }
    }
    if (!primary || !isCompletePosition(primary)) {
      throw new SignCliError({
        code: "MISSING_FLAG",
        message: "sign pdf stamp-text requires a position: --auto-place or --image-page/--image-x/--image-y/--image-width/--image-height.",
      });
    }

    const { stampPlainTextOnPdf } = await import("./lib/pdf-image-stamp.js");
    const positions = [primary, ...extras];
    for (const pos of positions) {
      pdfBytes = await stampPlainTextOnPdf(pdfBytes, text, pos);
    }
    fs.writeFileSync(outPath, pdfBytes);

    // Quality assessment — same shape as `pdf stamp` and `sign preview`, so
    // users get a consistent warnings array regardless of which stamping
    // command they ran.
    const { assessStampQuality } = await import("./lib/stamp-quality.js");
    const allWarnings = [];
    for (const pos of positions) {
      const w = await assessStampQuality({
        pdfBytes, page: pos.page, x: pos.x, y: pos.y, width: pos.width, height: pos.height,
      });
      allWarnings.push(...w);
    }
    console.log(JSON.stringify({
      ok: true,
      pdf: pdfPath,
      out: outPath,
      text,
      positions,
      bytes: pdfBytes.length,
      warnings: allWarnings,
    }, null, 2));
    return;
  }

  if (root === "workflow" && sub === "nda") {
    const valuesPath = flagValue(parsed, "values");
    const valuesFromFile: Record<string, string> = valuesPath
      ? JSON.parse((await import("node:fs")).readFileSync(valuesPath, "utf8"))
      : {};
    const valuesFromFlags: Record<string, string> = {};
    for (const raw of flagValues(parsed, "value")) {
      const eq = raw.indexOf("=");
      if (eq <= 0) {
        throw new SignCliError({
          code: "MISSING_FLAG",
          message: `--value must be of the form KEY=VALUE, got "${raw}".`,
        });
      }
      valuesFromFlags[raw.slice(0, eq).trim()] = raw.slice(eq + 1);
    }
    const values = { ...valuesFromFile, ...valuesFromFlags };
    if (Object.keys(values).length === 0) {
      throw new SignCliError({
        code: "MISSING_FLAG",
        message: "sign workflow nda requires --values <path.json> and/or --value KEY=VALUE flags.",
      });
    }
    const partyAEmail = flagValue(parsed, "party-a-email", true)!;
    const partyBEmail = flagValue(parsed, "party-b-email", true)!;
    validateEmail(partyAEmail, "Party A email");
    validateEmail(partyBEmail, "Party B email");
    const outPath = flagValue(parsed, "out", true)!;
    const templatePath = flagValue(parsed, "template");
    const title = flagValue(parsed, "title");
    const autoApprove = (flagValue(parsed, "auto-approve") ?? "false") === "true";
    const tokenTtlMinutes = Number(flagValue(parsed, "token-ttl-minutes") ?? "60");
    printProviderBanner(resolvedProvider);
    const { runNdaWorkflow } = await import("./lib/workflow-nda.js");
    const result = await runNdaWorkflow(db, {
      values,
      partyAEmail,
      partyBEmail,
      outPath,
      ...(templatePath ? { templatePath } : {}),
      ...(title ? { title } : {}),
      autoApprove,
      provider: selectedProvider,
      tokenTtlMinutes,
    });
    emitJsonWithProvider(result, resolvedProvider);
    return;
  }

  if (root === "signer" && sub === "list") {
    const inbox = listSignerInbox(db, { signerEmail: flagValue(parsed, "signer-email") });
    console.log(JSON.stringify(inbox, null, 2));
    return;
  }

  if (root === "signer" && sub === "fetch-document") {
    const requestId = flagValue(parsed, "request-id", true)!;
    const token = flagValue(parsed, "token", true)!;
    const out = flagValue(parsed, "out");
    const result = await fetchUnsignedDocumentForSigner(db, {
      requestId,
      token,
      signerEmail: flagValue(parsed, "signer-email"),
      outPath: out,
    });
    console.log(JSON.stringify(result, null, 2));
    return;
  }

  if (root === "signer" && sub === "decline") {
    const requestId = flagValue(parsed, "request-id", true)!;
    const token = flagValue(parsed, "token", true)!;
    const result = declineSigningRequestAsSigner(db, {
      requestId,
      token,
      signerEmail: flagValue(parsed, "signer-email"),
      reason: flagValue(parsed, "reason"),
    });
    console.log(JSON.stringify(result, null, 2));
    return;
  }

  if (root === "signer" && sub === "watch") {
    const signerEmail = flagValue(parsed, "signer-email");
    const exitOnFirst = (flagValue(parsed, "exit-on-first") ?? "false") === "true";
    const timeoutMs = parseDurationMs(parsed, { msFlag: "timeout-ms", secondsFlag: "timeout-seconds" });
    const pollIntervalMs = parseDurationMs(parsed, { msFlag: "interval-ms", secondsFlag: "interval-seconds", defaultMs: 1000, minMs: 50 })!;
    process.stderr.write(`[signer watch] tailing inbox${signerEmail ? ` for ${signerEmail}` : ""} (Ctrl+C to stop)\n`);
    const outcome = await runSignerWatch(db, {
      signerEmail,
      exitOnFirst,
      timeoutMs,
      pollIntervalMs,
      onEntry: (entry) => {
        const tag = entry.firstSeen ? "+ NEW" : "  initial";
        process.stderr.write(`${tag} ${entry.requestId} title=${JSON.stringify(entry.title)} signers=${entry.signers.length}\n`);
      },
    });
    console.log(JSON.stringify(outcome, null, 2));
    process.exitCode = outcome.exitReason === "timeout" ? 4 : 0;
    return;
  }

  if (root === "signer" && sub === "send-verification") {
    const requestId = flagValue(parsed, "request-id", true)!;
    const signerEmail = flagValue(parsed, "email", true)!;
    const ttl = flagValue(parsed, "ttl-minutes");
    const result = await issueSignerEmailVerification(db, {
      requestId,
      signerEmail,
      ttlMinutes: ttl ? Number(ttl) : undefined,
    });
    if (result.deliveredVia === "manual") {
      process.stderr.write(
        "[send-verification] No verification webhook delivered this code — pass it to the signer's " +
        "email mailbox yourself. The attribution value of the verification depends on that delivery.\n",
      );
    }
    if (result.deliveryError) {
      process.stderr.write(`[send-verification] ${result.deliveryError}\n`);
    }
    console.log(JSON.stringify(result, null, 2));
    return;
  }

  if (root === "signer" && sub === "verify-email") {
    const requestId = flagValue(parsed, "request-id", true)!;
    const signerEmail = flagValue(parsed, "email", true)!;
    const code = flagValue(parsed, "code", true)!;
    const result = verifySignerEmailCode(db, { requestId, signerEmail, code });
    console.log(JSON.stringify(result, null, 2));
    return;
  }

  if (root === "signer" && sub === "record-identity") {
    const requestId = flagValue(parsed, "request-id", true)!;
    const signerEmail = flagValue(parsed, "email", true)!;
    const spec = flagValue(parsed, "identity-assurance", true)!;
    const result = recordIdentityAssurance(db, {
      requestId,
      signerEmail,
      assurance: parseIdentityAssuranceSpec(spec),
    });
    console.log(JSON.stringify(result, null, 2));
    return;
  }

  if (root === "signer" && sub === "reissue-token") {
    const requestId = flagValue(parsed, "request-id", true)!;
    const signerEmail = flagValue(parsed, "signer-email", true)!;
    const ttl = flagValue(parsed, "token-ttl-minutes");
    const result = reissueSignerToken(db, {
      requestId,
      signerEmail,
      tokenTtlMinutes: ttl ? Number(ttl) : undefined,
    });
    console.log(JSON.stringify(result, null, 2));
    return;
  }

  if (root === "signer" && sub === "policy" && action === "run") {
    const requestId = flagValue(parsed, "request-id", true)!;
    const token = flagValue(parsed, "token", true)!;
    const specPath = flagValue(parsed, "spec", true)!;
    const dryRun = (flagValue(parsed, "dry-run") ?? "false") === "true";
    const spec = loadPolicySpec(specPath);
    const outcome = runSignerPolicy(db, { requestId, token, spec, dryRun });
    console.log(JSON.stringify(outcome, null, 2));
    return;
  }

  if (root === "signer" && sub === "policy" && action === "try") {
    const specPath = flagValue(parsed, "spec", true)!;
    const { evaluatePolicy, loadPolicySpec } = await import("./lib/policy-engine.js");
    const spec = loadPolicySpec(specPath);

    const batchPath = flagValue(parsed, "batch");
    if (batchPath) {
      // Batch mode: load a JSON array of { title, documentSha256, signerEmail, label? }
      // contexts and emit { contexts[], decisions[] }. Each decision row carries
      // the same shape evaluatePolicy returns. Errors per-row are caught and
      // surfaced as { decision: null, error: { code, message } } so one bad row
      // can't poison the batch.
      const fs = await import("node:fs");
      let raw: unknown;
      try {
        raw = JSON.parse(fs.readFileSync(batchPath, "utf8"));
      } catch (error) {
        throw new SignCliError({
          code: "INVALID_SPEC",
          message: `Failed to load --batch ${batchPath}: ${(error as Error).message}`,
        });
      }
      if (!Array.isArray(raw)) {
        throw new SignCliError({
          code: "INVALID_SPEC",
          message: `--batch file must be a JSON array of context objects.`,
        });
      }
      const decisions: Array<{
        index: number;
        label: string | null;
        ctx: { title: string; documentSha256: string; signerEmail: string };
        decision: ReturnType<typeof evaluatePolicy> | null;
        error: { code: string; message: string } | null;
      }> = [];
      for (let i = 0; i < raw.length; i += 1) {
        const entry = raw[i] as Record<string, unknown>;
        const ctx = {
          title: typeof entry?.title === "string" ? entry.title : "",
          documentSha256: typeof entry?.documentSha256 === "string" ? entry.documentSha256 : "",
          signerEmail: typeof entry?.signerEmail === "string" ? entry.signerEmail : "",
        };
        const label = typeof entry?.label === "string" ? entry.label : null;
        try {
          decisions.push({ index: i, label, ctx, decision: evaluatePolicy(spec, ctx), error: null });
        } catch (error) {
          const code = error instanceof SignCliError ? error.code : "INTERNAL";
          const message = error instanceof Error ? error.message : String(error);
          decisions.push({ index: i, label, ctx, decision: null, error: { code, message } });
        }
      }
      const summary = {
        total: decisions.length,
        sign: decisions.filter((d) => d.decision?.action === "sign").length,
        decline: decisions.filter((d) => d.decision?.action === "decline").length,
        report: decisions.filter((d) => d.decision?.action === "report").length,
        errored: decisions.filter((d) => d.error !== null).length,
      };
      console.log(JSON.stringify({ spec: specPath, ...summary, decisions }, null, 2));
      return;
    }

    const snapshotPath = flagValue(parsed, "snapshot");
    let title: string;
    let documentSha256: string;
    let signerEmail: string;
    if (snapshotPath) {
      const fs = await import("node:fs");
      const snap = JSON.parse(fs.readFileSync(snapshotPath, "utf8"));
      title = snap?.request?.title ?? "";
      documentSha256 = snap?.request?.document_hash ?? "";
      const fromSignersJson = (() => {
        if (typeof snap?.request?.signers_json !== "string") return undefined;
        try {
          const parsed = JSON.parse(snap.request.signers_json);
          return Array.isArray(parsed) ? parsed[0]?.email : undefined;
        } catch {
          return undefined;
        }
      })();
      signerEmail = flagValue(parsed, "signer-email")
        ?? snap?.signedBy?.[0]?.email
        ?? fromSignersJson
        ?? "";
    } else {
      title = flagValue(parsed, "title", true)!;
      documentSha256 = flagValue(parsed, "document-sha256", true)!;
      signerEmail = flagValue(parsed, "signer-email", true)!;
    }

    const decision = evaluatePolicy(spec, { title, documentSha256, signerEmail });
    console.log(JSON.stringify({
      ctx: { title, documentSha256, signerEmail },
      decision,
    }, null, 2));
    return;
  }

  if (root === "signer" && sub === "policy" && action === "diff") {
    const beforePath = flagValue(parsed, "before", true)!;
    const afterPath = flagValue(parsed, "after", true)!;
    const snapshotPath = flagValue(parsed, "snapshot");
    const useInbox = (flagValue(parsed, "inbox") ?? "false") === "true";
    if (!snapshotPath && !useInbox) {
      throw new SignCliError({
        code: "MISSING_FLAG",
        message: "signer policy diff requires either --snapshot <path> or --inbox true.",
      });
    }
    const { loadPolicySpec } = await import("./lib/policy-engine.js");
    const { diffPolicies } = await import("./lib/policy-diff.js");
    const before = loadPolicySpec(beforePath);
    const after = loadPolicySpec(afterPath);
    const contexts: Array<{ requestId: string | null; title: string; documentSha256: string; signerEmail: string }> = [];
    if (snapshotPath) {
      const fs = await import("node:fs");
      const snap = JSON.parse(fs.readFileSync(snapshotPath, "utf8"));
      const fromSignersJson = (() => {
        if (typeof snap?.request?.signers_json !== "string") return undefined;
        try {
          const arr = JSON.parse(snap.request.signers_json);
          return Array.isArray(arr) ? arr[0]?.email : undefined;
        } catch { return undefined; }
      })();
      const signerEmail = flagValue(parsed, "signer-email")
        ?? snap?.signedBy?.[0]?.email
        ?? fromSignersJson
        ?? "";
      contexts.push({
        requestId: snap?.request?.id ?? null,
        title: snap?.request?.title ?? "",
        documentSha256: snap?.request?.document_hash ?? "",
        signerEmail,
      });
    }
    if (useInbox) {
      const inbox = listSignerInbox(db, { signerEmail: flagValue(parsed, "signer-email") });
      for (const entry of inbox) {
        if (!entry.requestId) continue;
        const row = db.prepare("SELECT document_hash FROM requests WHERE id = ?")
          .get(entry.requestId) as { document_hash: string | null } | undefined;
        const signerEmail = flagValue(parsed, "signer-email")
          ?? entry.signers?.[0]?.email
          ?? "";
        contexts.push({
          requestId: entry.requestId,
          title: entry.title,
          documentSha256: row?.document_hash ?? "",
          signerEmail,
        });
      }
    }
    const summary = diffPolicies(before, after, contexts);
    const format = (flagValue(parsed, "format") ?? "json").toLowerCase();
    if (format === "markdown") {
      const { renderPolicyDiffAsMarkdown } = await import("./lib/policy-diff.js");
      process.stdout.write(renderPolicyDiffAsMarkdown(summary, { before: beforePath, after: afterPath }));
      process.stdout.write("\n");
      return;
    }
    if (format !== "json") {
      throw new SignCliError({
        code: "INVALID_ARGS",
        message: `--format must be json or markdown; got ${JSON.stringify(format)}.`,
      });
    }
    console.log(JSON.stringify({ before: beforePath, after: afterPath, ...summary }, null, 2));
    return;
  }

  if (root === "signer" && sub === "policy" && action === "lint") {
    const specPath = flagValue(parsed, "spec", true)!;
    const { loadPolicySpec } = await import("./lib/policy-engine.js");
    const { lintPolicySpec } = await import("./lib/policy-lint.js");
    const spec = loadPolicySpec(specPath);
    const report = lintPolicySpec(spec);
    console.log(JSON.stringify({ spec: specPath, ...report }, null, 2));
    if (!report.ok) process.exitCode = 3;
    return;
  }

  if (root === "signer" && sub === "policy" && action === "run-all") {
    const specPath = flagValue(parsed, "spec", true)!;
    const tokensPath = flagValue(parsed, "tokens-file", true)!;
    const dryRun = (flagValue(parsed, "dry-run") ?? "false") === "true";
    const fs = await import("node:fs");
    let tokens: Record<string, string>;
    try {
      const raw = JSON.parse(fs.readFileSync(tokensPath, "utf8"));
      if (Array.isArray(raw)) {
        tokens = {};
        for (const entry of raw as Array<{ requestId?: string; token?: string }>) {
          if (typeof entry?.requestId === "string" && typeof entry?.token === "string") {
            tokens[entry.requestId] = entry.token;
          }
        }
      } else if (raw && typeof raw === "object") {
        tokens = Object.fromEntries(
          Object.entries(raw as Record<string, unknown>)
            .filter(([, v]) => typeof v === "string") as Array<[string, string]>,
        );
      } else {
        throw new Error("expected an object or an array of {requestId, token} entries");
      }
    } catch (error) {
      throw new SignCliError({
        code: "INVALID_SPEC",
        message: `Failed to load --tokens-file ${tokensPath}: ${(error as Error).message}`,
      });
    }
    const spec = loadPolicySpec(specPath);
    const outcome = runSignerPolicyAll(db, {
      signerEmail: flagValue(parsed, "signer-email"),
      tokens,
      spec,
      dryRun,
    });
    console.log(JSON.stringify(outcome, null, 2));
    if (outcome.failed > 0) process.exitCode = 3;
    return;
  }

  if (root === "signer" && sub === "policy" && action === "run-watch") {
    const specPath = flagValue(parsed, "spec", true)!;
    const tokensPath = flagValue(parsed, "tokens-file", true)!;
    const signerEmail = flagValue(parsed, "signer-email");
    const exitOnFirst = (flagValue(parsed, "exit-on-first") ?? "false") === "true";
    const dryRun = (flagValue(parsed, "dry-run") ?? "false") === "true";
    const timeoutMs = parseDurationMs(parsed, { msFlag: "timeout-ms", secondsFlag: "timeout-seconds" });
    const pollIntervalMs = parseDurationMs(parsed, { msFlag: "interval-ms", secondsFlag: "interval-seconds", defaultMs: 1000, minMs: 50 })!;
    const fs = await import("node:fs");
    let tokens: Record<string, string>;
    try {
      const raw = JSON.parse(fs.readFileSync(tokensPath, "utf8"));
      if (Array.isArray(raw)) {
        tokens = {};
        for (const entry of raw as Array<{ requestId?: string; token?: string }>) {
          if (typeof entry?.requestId === "string" && typeof entry?.token === "string") {
            tokens[entry.requestId] = entry.token;
          }
        }
      } else if (raw && typeof raw === "object") {
        tokens = Object.fromEntries(
          Object.entries(raw as Record<string, unknown>)
            .filter(([, v]) => typeof v === "string") as Array<[string, string]>,
        );
      } else {
        throw new Error("expected an object or an array of {requestId, token} entries");
      }
    } catch (error) {
      throw new SignCliError({
        code: "INVALID_SPEC",
        message: `Failed to load --tokens-file ${tokensPath}: ${(error as Error).message}`,
      });
    }
    const spec = loadPolicySpec(specPath);
    const reportPath = flagValue(parsed, "report");
    const { runSignerPolicyWatch } = await import("./lib/policy-run-watch.js");
    let reportStream: import("node:fs").WriteStream | null = null;
    if (reportPath) {
      const fs = await import("node:fs");
      const pathMod = await import("node:path");
      const resolved = pathMod.resolve(reportPath);
      fs.mkdirSync(pathMod.dirname(resolved), { recursive: true });
      reportStream = fs.createWriteStream(resolved, { flags: "a" });
    }
    const onDecisionCmd = flagValue(parsed, "on-decision");
    const sinceAnchorRaw = flagValue(parsed, "since-anchor");
    let sinceCreatedAt: string | undefined;
    if (sinceAnchorRaw) {
      const { listStoredAnchors } = await import("./lib/audit-anchor.js");
      const anchors = listStoredAnchors(db, { limit: 1000 });
      let chosen: { artifactId: string; createdAt: string } | undefined;
      if (sinceAnchorRaw === "latest") {
        chosen = anchors[0];
      } else {
        chosen = anchors.find((a) => a.artifactId === sinceAnchorRaw);
      }
      if (!chosen) {
        throw new SignCliError({
          code: "INVALID_ARGS",
          message: sinceAnchorRaw === "latest"
            ? "--since-anchor latest: no audit_anchor artifacts have been issued yet."
            : `--since-anchor: anchor artifactId not found: ${JSON.stringify(sinceAnchorRaw)}.`,
        });
      }
      sinceCreatedAt = chosen.createdAt;
    }
    process.stderr.write(`[signer policy run-watch] tailing inbox${signerEmail ? ` for ${signerEmail}` : ""}${reportPath ? ` → ${reportPath}` : ""}${onDecisionCmd ? ` | hook: ${onDecisionCmd}` : ""}${sinceCreatedAt ? ` since ${sinceCreatedAt}` : ""} (Ctrl+C to stop)\n`);
    const { spawn } = await import("node:child_process");
    const outcome = await runSignerPolicyWatch(db, {
      tokens, spec, signerEmail, exitOnFirst, timeoutMs, pollIntervalMs, dryRun, sinceCreatedAt,
      onEntry: (entry) => {
        const tag = entry.skipped ? "  SKIP" : entry.ok ? `+ ${entry.decision?.action?.toUpperCase()}` : "× ERROR";
        process.stderr.write(`${tag} ${entry.requestId}${entry.error ? ` ${entry.error.code}: ${entry.error.message}` : ""}\n`);
        if (reportStream) {
          reportStream.write(JSON.stringify({ ...entry, observedAt: new Date().toISOString() }) + "\n");
        }
        if (onDecisionCmd) {
          // Spawn the hook as a child process; pipe the entry as JSON on
          // stdin. Don't wait on the child — fire-and-forget keeps the
          // watcher loop responsive. Errors land on stderr but don't
          // affect the watcher's exit code.
          try {
            const child = spawn(onDecisionCmd, [], {
              stdio: ["pipe", "inherit", "inherit"],
              shell: true,
              env: {
                ...process.env,
                SIGN_HOOK_REQUEST_ID: entry.requestId,
                SIGN_HOOK_SIGNER_EMAIL: entry.signerEmail ?? "",
                SIGN_HOOK_OK: String(entry.ok),
                SIGN_HOOK_ACTION: entry.decision?.action ?? "",
                SIGN_HOOK_SKIPPED: String(entry.skipped),
              },
            });
            child.on("error", (err) => {
              process.stderr.write(`[signer policy run-watch] hook spawn error: ${(err as Error).message}\n`);
            });
            child.stdin.end(JSON.stringify(entry) + "\n");
          } catch (err) {
            process.stderr.write(`[signer policy run-watch] hook spawn failed: ${(err as Error).message}\n`);
          }
        }
      },
    });
    if (reportStream) {
      reportStream.write(JSON.stringify({
        summary: true,
        succeeded: outcome.succeeded,
        failed: outcome.failed,
        skipped: outcome.skipped,
        exitReason: outcome.watch.exitReason,
        observedAt: new Date().toISOString(),
      }) + "\n");
      await new Promise<void>((resolve) => reportStream!.end(resolve));
    }
    console.log(JSON.stringify(outcome, null, 2));
    if (outcome.watch.exitReason === "timeout") process.exitCode = 4;
    else if (outcome.failed > 0) process.exitCode = 3;
    return;
  }

  if (root === "request" && sub === "send") {
    const requestId = flagValue(parsed, "request-id", true)!;
    const force = (flagValue(parsed, "force") ?? "false") === "true";
    // Print the banner FIRST so it remains visible even when downstream
    // resolution (API key, strict check, etc.) throws.
    printProviderBanner(resolvedProvider);
    // Strict-provider preflight: fail BEFORE we resolve API keys (which would
    // throw a misleading "API key not set" error for a provider the user
    // never intended to use against this request).
    if (flagValue(parsed, "provider") && strictProvider) {
      const persisted = getPersistedProviderForRequest(db, requestId);
      if (persisted !== selectedProvider) {
        throw new SignCliError({
          code: "STRICT_PROVIDER_MISMATCH",
          message: `Strict provider check failed: --provider ${selectedProvider} but request ${requestId} was created against ${persisted}.`,
          hint: `Either rerun with --provider ${persisted}, or unset --strict-provider/SIGN_STRICT_PROVIDER to bypass.`,
        });
      }
    }
    const result = await sendSigningRequest(db, {
      requestId,
      provider: selectedProvider,
      apiKey: resolveProviderApiKey(selectedProvider),
      testMode: resolveProviderTestMode(selectedProvider, flagValue(parsed, "test-mode")),
      applySigningOrder: resolveOrderedFlag(flagValue(parsed, "ordered")),
      force,
      ...(flagValue(parsed, "provider") ? { strictProvider } : {}),
    });
    emitJsonWithProvider(result, resolvedProvider);
    return;
  }


  if (root === "request" && sub === "send-embedded") {
    const requestId = flagValue(parsed, "request-id", true)!;
    const result = await sendEmbeddedSigningRequest(db, {
      requestId,
      provider: selectedProvider,
      apiKey: resolveProviderApiKey(selectedProvider),
      clientId: selectedProvider === "dropbox" ? requireDropboxClientId(flagValue(parsed, "client-id")) : undefined,
      testMode: resolveProviderTestMode(selectedProvider, flagValue(parsed, "test-mode")),
      applySigningOrder: resolveOrderedFlag(flagValue(parsed, "ordered")),
    });
    if (selectedProvider === "signwell") {
      const document = (result.responseBody as any) ?? {};
      const recipients = Array.isArray(document?.recipients)
        ? document.recipients.map((recipient: any) => ({
          id: recipient?.id,
          email: recipient?.email,
          embeddedSigningUrl: recipient?.embedded_signing_url ?? null,
        }))
        : [];
      console.log(JSON.stringify({ ...result, signwell: { documentId: result.signatureRequestId, recipients } }, null, 2));
      return;
    }
    console.log(JSON.stringify(result, null, 2));
    return;
  }

  if (root === "request" && sub === "sign-url") {
    const requestId = flagValue(parsed, "request-id", true)!;
    const signatureId = flagValue(parsed, "signature-id", true)!;
    const returnUrl = flagValue(parsed, "return-url");
    if (returnUrl) validateReturnUrl(returnUrl);
    const result = await getEmbeddedSignUrl(db, {
      requestId,
      provider: selectedProvider,
      signatureId,
      apiKey: resolveProviderApiKey(selectedProvider),
      returnUrl,
    });
    console.log(JSON.stringify(result, null, 2));
    return;
  }


  if (root === "request" && sub === "launch-embedded") {
    const requestId = flagValue(parsed, "request-id", true)!;
    const signatureId = flagValue(parsed, "signature-id", true)!;
    const returnUrl = flagValue(parsed, "return-url");
    if (returnUrl) validateReturnUrl(returnUrl);
    const result = await getEmbeddedSignUrl(db, {
      requestId,
      provider: selectedProvider,
      signatureId,
      apiKey: resolveProviderApiKey(selectedProvider),
      returnUrl,
    });
    const file = flagValue(parsed, "out") ?? `./embedded-launch-${signatureId}.html`;
    const fs = await import("node:fs/promises");
    if (selectedProvider === "signwell" || selectedProvider === "docusign") {
      const title = selectedProvider === "docusign" ? "DocuSign Embedded Sign" : "SignWell Embedded Sign";
      const html = `<!doctype html><html><head><meta charset="utf-8"><title>${title}</title><style>html,body,iframe{margin:0;padding:0;border:0;width:100%;height:100%;}</style></head><body><iframe src=${JSON.stringify(result.signUrl)} allow="camera *; microphone *" allowfullscreen></iframe></body></html>`;
      await fs.writeFile(file, html, "utf8");
      console.log(JSON.stringify({ ...result, launcherFile: file, mode: "iframe" }, null, 2));
      return;
    }
    const clientId = requireDropboxClientId(flagValue(parsed, "client-id"));
    const html = `<!doctype html><html><head><meta charset="utf-8"><title>Embedded Sign</title></head><body><h3>Launching signer...</h3><script src="https://cdn.hellosign.com/public/js/embedded/v2.11.1/embedded.development.js"></script><script>const client=new window.HelloSign();client.open(${JSON.stringify(result.signUrl)},{clientId:${JSON.stringify(clientId)},skipDomainVerification:true});</script></body></html>`;
    await fs.writeFile(file, html, "utf8");
    console.log(JSON.stringify({ ...result, launcherFile: file, mode: "hellosign-embedded-js" }, null, 2));
    return;
  }

  if (root === "request" && sub === "fetch-final") {
    const requestId = flagValue(parsed, "request-id", true)!;
    const outPath = flagValue(parsed, "out");
    const result = await fetchFinalSignedPdf(db, {
      requestId,
      provider: selectedProvider,
      apiKey: resolveProviderApiKey(selectedProvider),
      outPath,
    });
    console.log(JSON.stringify(result, null, 2));
    return;
  }

  if (root === "request" && sub === "status" && (flagValue(parsed, "watch") ?? "false") !== "true") {
    const requestId = flagValue(parsed, "request-id", true)!;
    const result = await getSigningRequestStatus(db, {
      requestId,
      provider: selectedProvider,
      apiKey: resolveProviderApiKey(selectedProvider),
    });
    console.log(JSON.stringify(result, null, 2));
    return;
  }

  // `request status --watch true` is a shorthand for `request watch` — same
  // flags, same exit codes. The single-shot status path is handled above.
  if (root === "request" && (sub === "watch" || sub === "status")) {
    const requestId = flagValue(parsed, "request-id", true)!;
    const intervalMs = parseDurationMs(parsed, { msFlag: "interval-ms", secondsFlag: "interval-seconds", defaultMs: 5000, minMs: 50 })!;
    const timeoutMs = parseDurationMs(parsed, { msFlag: "timeout-ms", secondsFlag: "timeout-seconds" });
    const fetchFinalPdf = (flagValue(parsed, "fetch-final") ?? "false") === "true";
    const outPath = flagValue(parsed, "out");
    const logger = createLogger({ mode: resolveLogMode(flagValue(parsed, "log")) });
    let lastPrintedStatus: string | null = null;
    const result = await watchSigningRequestStatus(db, {
      requestId,
      provider: selectedProvider,
      apiKey: resolveProviderApiKey(selectedProvider),
      intervalMs,
      timeoutMs,
      fetchFinalPdf,
      outPath,
      onPoll: (update) => {
        const shouldPrint = update.attempt === 1 || update.status !== lastPrintedStatus || update.terminal !== null;
        if (!shouldPrint) {
          return;
        }
        lastPrintedStatus = update.status;
        logger.info("watch poll", {
          provider: update.provider,
          attempt: update.attempt,
          status: update.status,
          terminal: update.terminal,
          elapsedSeconds: Number((update.elapsedMs / 1000).toFixed(1)),
        });
      },
    });
    console.log(JSON.stringify(result, null, 2));
    process.exitCode = result.exitCode;
    return;
  }

  if (root === "audit" && sub === "show") {
    const requestId = flagValue(parsed, "request-id", true)!;
    const format = (flagValue(parsed, "format") ?? "json").toLowerCase();
    if (format !== "json" && format !== "csv" && format !== "pretty") {
      throw new SignCliError({
        code: "INVALID_ARGS",
        message: `--format must be json, csv, or pretty; got ${JSON.stringify(format)}.`,
      });
    }
    const eventTypes = flagValues(parsed, "event-type");
    const since = flagValue(parsed, "since");
    const until = flagValue(parsed, "until");
    for (const [name, value] of [["since", since], ["until", until]] as const) {
      if (value !== undefined && Number.isNaN(Date.parse(value))) {
        throw new SignCliError({
          code: "INVALID_ARGS",
          message: `--${name} must be an ISO 8601 timestamp; got ${JSON.stringify(value)}.`,
        });
      }
    }
    let events = listAuditEvents(db, requestId);
    if (eventTypes.length > 0) {
      const allow = new Set(eventTypes);
      events = events.filter((e) => allow.has(e.event_type));
    }
    if (since) {
      const cutoff = Date.parse(since);
      events = events.filter((e) => Date.parse(e.created_at) >= cutoff);
    }
    if (until) {
      const cutoff = Date.parse(until);
      events = events.filter((e) => Date.parse(e.created_at) <= cutoff);
    }
    if (format === "csv") {
      const { renderAuditChainAsCsv } = await import("./lib/audit-csv.js");
      process.stdout.write(renderAuditChainAsCsv(events));
    } else if (format === "pretty") {
      const { renderAuditChainAsPretty } = await import("./lib/audit-pretty.js");
      process.stdout.write(renderAuditChainAsPretty(events) + "\n");
    } else {
      console.log(JSON.stringify(events, null, 2));
    }
    return;
  }

  if (root === "audit" && sub === "search") {
    const { searchAuditEvents } = await import("./lib/audit.js");
    const result = searchAuditEvents(db, {
      requestId: flagValue(parsed, "request-id"),
      eventType: flagValue(parsed, "event-type"),
      since: flagValue(parsed, "since"),
      until: flagValue(parsed, "until"),
      payloadContains: flagValue(parsed, "payload-contains"),
      limit: flagValue(parsed, "limit") ? Number(flagValue(parsed, "limit")) : undefined,
    });
    console.log(JSON.stringify(result, null, 2));
    return;
  }

  if (root === "audit" && sub === "verify") {
    const requestId = flagValue(parsed, "request-id", true)!;
    const result = verifyRequestAuditChain(db, requestId);
    console.log(JSON.stringify({ requestId, ...result }, null, 2));
    process.exitCode = result.valid ? 0 : 3;
    return;
  }

  if (root === "audit" && sub === "scan") {
    const provider = flagValue(parsed, "provider") ? selectedProvider : undefined;
    const status = flagValue(parsed, "status");
    const limitFlag = flagValue(parsed, "limit");
    const result = scanAllAuditChains(db, {
      provider,
      status,
      limit: limitFlag ? Number(limitFlag) : undefined,
    });
    console.log(JSON.stringify(result, null, 2));
    process.exitCode = result.invalid === 0 ? 0 : 3;
    return;
  }

  if (root === "audit" && sub === "watch") {
    const requestId = flagValue(parsed, "request-id");
    const pollIntervalMs = parseDurationMs(parsed, { msFlag: "interval-ms", secondsFlag: "interval-seconds", defaultMs: 5000, minMs: 50 })!;
    const timeoutMs = parseDurationMs(parsed, { msFlag: "timeout-ms", secondsFlag: "timeout-seconds" });
    process.stderr.write(`[audit watch] re-verifying audit chain${requestId ? ` for ${requestId}` : ""} every ${pollIntervalMs}ms (Ctrl+C to stop)\n`);
    const outcome = await runAuditWatch(db, {
      requestId,
      pollIntervalMs,
      timeoutMs,
      onScan: (report, trigger) => {
        process.stderr.write(`[audit watch] ${trigger}: total=${report.total} valid=${report.valid} invalid=${report.invalid}\n`);
      },
    });
    console.log(JSON.stringify(outcome, null, 2));
    process.exitCode = outcome.exitReason === "break_detected" ? 3 : outcome.exitReason === "timeout" ? 4 : 0;
    return;
  }

  if (root === "audit" && sub === "anchor") {
    const tsaUrl = flagValue(parsed, "tsa-url");
    const outDir = flagValue(parsed, "out");
    const sinceRaw = flagValue(parsed, "since");
    const sinceAnchorRaw = flagValue(parsed, "since-anchor");
    let since = sinceRaw;
    if (sinceAnchorRaw) {
      const { listStoredAnchors } = await import("./lib/audit-anchor.js");
      const anchors = listStoredAnchors(db, { limit: 1000 });
      const chosen = sinceAnchorRaw === "latest"
        ? anchors[0]
        : anchors.find((a) => a.artifactId === sinceAnchorRaw);
      if (!chosen) {
        throw new SignCliError({
          code: "INVALID_ARGS",
          message: sinceAnchorRaw === "latest"
            ? "--since-anchor latest: no audit_anchor artifacts have been issued yet."
            : `--since-anchor: anchor artifactId not found: ${JSON.stringify(sinceAnchorRaw)}.`,
        });
      }
      since = chosen.createdAt;
    }
    const dryRun = (flagValue(parsed, "dry-run") ?? "false") === "true";
    if (dryRun) {
      const { previewAnchorAllAuditChainHeads } = await import("./lib/audit-anchor.js");
      const preview = previewAnchorAllAuditChainHeads(db, { since });
      console.log(JSON.stringify({ dryRun: true, ...preview }, null, 2));
      return;
    }
    const { anchorAllAuditChainHeads } = await import("./lib/audit-anchor.js");
    const result = await anchorAllAuditChainHeads(db, { tsaUrl, outDir, since });
    console.log(JSON.stringify(result, null, 2));
    return;
  }

  if (root === "audit" && sub === "verify-chain-bundle") {
    const bundleDir = flagValue(parsed, "bundle");
    const tarballPath = flagValue(parsed, "tarball");
    const reportPath = flagValue(parsed, "report");
    if (!bundleDir && !tarballPath) {
      throw new SignCliError({
        code: "MISSING_FLAG",
        message: "audit verify-chain-bundle requires either --bundle <dir> or --tarball <path>.",
      });
    }
    const { verifyAuditChainBundle, verifyAuditChainBundleFromTarball } = await import("./lib/audit-chain-bundle.js");
    const report = tarballPath
      ? await verifyAuditChainBundleFromTarball(tarballPath)
      : await verifyAuditChainBundle(bundleDir!);
    if (reportPath) {
      const fs = await import("node:fs");
      const pathMod = await import("node:path");
      const resolved = pathMod.resolve(reportPath);
      fs.mkdirSync(pathMod.dirname(resolved), { recursive: true });
      const stream = fs.createWriteStream(resolved, { flags: "a" });
      for (const row of report.results) {
        stream.write(JSON.stringify({ ...row, observedAt: new Date().toISOString() }) + "\n");
      }
      stream.write(JSON.stringify({
        summary: true,
        ok: report.ok,
        bundleDir: report.bundleDir,
        passed: report.passed,
        failed: report.failed,
        anchor: report.anchor,
        errors: report.errors,
        observedAt: new Date().toISOString(),
      }) + "\n");
      await new Promise<void>((resolve) => stream.end(resolve));
    }
    console.log(JSON.stringify(report, null, 2));
    if (!report.ok) process.exitCode = 3;
    return;
  }

  if (root === "audit" && sub === "chain-bundle") {
    const out = flagValue(parsed, "out", true)!;
    const requestIds = flagValues(parsed, "request-id");
    const tarballPath = flagValue(parsed, "tarball");
    const includeSourcePdf = (flagValue(parsed, "include-source-pdf") ?? "false") === "true";
    const { exportAuditChainBundle } = await import("./lib/audit-chain-bundle.js");
    const result = await exportAuditChainBundle(db, {
      outDir: out,
      requestIds: requestIds.length > 0 ? requestIds : undefined,
      tarballPath,
      includeSourcePdf,
    });
    console.log(JSON.stringify(result, null, 2));
    return;
  }

  if (root === "audit" && sub === "anchors-list") {
    const limitFlag = flagValue(parsed, "limit");
    const { listStoredAnchors } = await import("./lib/audit-anchor.js");
    const limit = limitFlag ? Number(limitFlag) : undefined;
    console.log(JSON.stringify({ anchors: listStoredAnchors(db, { limit }) }, null, 2));
    return;
  }

  if (root === "audit" && sub === "verify-anchor") {
    const manifestPath = flagValue(parsed, "manifest", true)!;
    const fs = await import("node:fs");
    let manifest: Array<{ requestId: string; hashSelf: string }>;
    try {
      manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
      if (!Array.isArray(manifest)) throw new Error("manifest must be a JSON array");
    } catch (error) {
      throw new SignCliError({
        code: "INVALID_SPEC",
        message: `Failed to load anchor manifest at ${manifestPath}: ${(error as Error).message}`,
      });
    }
    const { verifyAnchorManifest } = await import("./lib/audit-anchor.js");
    const report = verifyAnchorManifest(db, manifest);
    console.log(JSON.stringify(report, null, 2));
    if (report.tampered > 0 || report.missing > 0) process.exitCode = 3;
    return;
  }

  if (root === "audit" && sub === "timestamp") {
    const requestId = flagValue(parsed, "request-id", true)!;
    const result = await timestampRequestAuditChain(db, {
      requestId,
      tsaUrl: flagValue(parsed, "tsa-url"),
      outPath: flagValue(parsed, "out"),
    });
    console.log(JSON.stringify(result, null, 2));
    return;
  }

  if (root === "audit" && sub === "export") {
    const requestId = flagValue(parsed, "request-id", true)!;
    const out = flagValue(parsed, "out", true)!;
    const result = await exportAuditBundle(db, { requestId, outDir: out });
    console.log(JSON.stringify(result, null, 2));
    return;
  }

  if (root === "audit" && sub === "export-jsonld") {
    const requestId = flagValue(parsed, "request-id", true)!;
    const out = flagValue(parsed, "out", true)!;
    const result = await exportAuditChainAsJsonLd(db, { requestId, outPath: out });
    console.log(JSON.stringify(result, null, 2));
    return;
  }

  if (root === "audit" && sub === "sign-head") {
    const requestId = flagValue(parsed, "request-id", true)!;
    const out = flagValue(parsed, "out");
    const result = await signAuditHead(db, { requestId, outPath: out });
    console.log(JSON.stringify(result, null, 2));
    return;
  }

  if (root === "audit" && sub === "issue-receipts") {
    const out = flagValue(parsed, "out", true)!;
    const provider = flagValue(parsed, "provider") ? selectedProvider : undefined;
    const status = flagValue(parsed, "status");
    const limitFlag = flagValue(parsed, "limit");
    const ndjson = (flagValue(parsed, "ndjson") ?? "false") === "true";
    const logger = createLogger({ mode: resolveLogMode(flagValue(parsed, "log")) });
    const result = await issueAuditReceiptsBulk(db, {
      outDir: out,
      provider,
      status,
      limit: limitFlag ? Number(limitFlag) : undefined,
      onProgress: (event) => logger.info("audit issue-receipts", event),
    });
    if (ndjson) {
      const { renderBulkResultAsNdjson } = await import("./lib/ndjson.js");
      process.stdout.write(renderBulkResultAsNdjson(result));
    } else {
      console.log(JSON.stringify(result, null, 2));
    }
    if (result.failed > 0) process.exitCode = 3;
    return;
  }

  if (root === "audit" && sub === "verify-head") {
    const proofPath = flagValue(parsed, "proof", true)!;
    const fs = await import("node:fs");
    let proof: Awaited<Parameters<typeof verifyAuditHeadProof>[0]>;
    try {
      proof = JSON.parse(fs.readFileSync(proofPath, "utf8"));
    } catch (error) {
      throw new SignCliError({
        code: "INVALID_SPEC",
        message: `Failed to load head proof at ${proofPath}: ${(error as Error).message}`,
      });
    }
    const expectFingerprintSha256 = flagValue(parsed, "expect-fingerprint");
    const result = await verifyAuditHeadProof(proof, { expectFingerprintSha256 });
    console.log(JSON.stringify(result, null, 2));
    process.exitCode = result.ok ? 0 : 3;
    return;
  }

  if (root === "request" && sub === "receipt") {
    const requestId = flagValue(parsed, "request-id", true)!;
    const out = flagValue(parsed, "out", true)!;
    const result = await exportRequestReceipt(db, { requestId, outDir: out });
    console.log(JSON.stringify(result, null, 2));
    return;
  }

  if (root === "request" && sub === "verify-receipt") {
    const bundleDir = flagValue(parsed, "bundle", true)!;
    const htmlOut = flagValue(parsed, "html");
    const expectFingerprintSha256 = flagValue(parsed, "expect-fingerprint");
    const result = verifyRequestReceiptBundle(bundleDir, { expectFingerprintSha256 });
    if (htmlOut) {
      const fs = await import("node:fs");
      const pathMod = await import("node:path");
      const resolved = pathMod.resolve(htmlOut);
      fs.mkdirSync(pathMod.dirname(resolved), { recursive: true });
      fs.writeFileSync(resolved, renderReceiptVerificationHtml(result));
      console.log(JSON.stringify({ ...result, htmlReport: resolved }, null, 2));
    } else {
      console.log(JSON.stringify(result, null, 2));
    }
    process.exitCode = result.ok ? 0 : 3;
    return;
  }

  if (root === "request" && sub === "verify-signed-pdf") {
    const requestId = flagValue(parsed, "request-id", true)!;
    const result = await inspectRequestSignedPdf(db, {
      requestId,
      path: flagValue(parsed, "path"),
      ...(flagValue(parsed, "recipient") ? { recipient: flagValue(parsed, "recipient") } : {}),
    });
    // One-line verdict on stderr so callers see the answer without parsing JSON.
    // The same fields are in result.summary on stdout for programmatic use.
    process.stderr.write(
      `[sign] verify: ${result.summary.verdict} ` +
      `(signatures=${result.report.signatureCount}, ` +
      `trust=${result.summary.trust}, ` +
      `digest_ok=${result.summary.digest_ok}, ` +
      `signer_match=${result.summary.signer_match}, ` +
      `warnings=${result.summary.warnings_count})\n`,
    );
    console.log(JSON.stringify(result, null, 2));
    process.exitCode = verifyVerdictExitCode(result.summary.verdict);
    return;
  }

  if (root === "request" && sub === "list") {
    const provider = flagValue(parsed, "provider") ? selectedProvider : undefined;
    const status = flagValue(parsed, "status");
    const limit = flagValue(parsed, "limit") ? Number(flagValue(parsed, "limit")) : undefined;
    const since = flagValue(parsed, "since");
    const format = (flagValue(parsed, "format") ?? "json").toLowerCase();
    if (format !== "json" && format !== "table") {
      throw new SignCliError({
        code: "INVALID_ARGS",
        message: `--format must be json or table; got ${JSON.stringify(format)}.`,
      });
    }
    const rows = listSigningRequests(db, { provider, status, limit, since });
    if (format === "table") {
      const { renderRequestsTable } = await import("./lib/request-table.js");
      console.log(renderRequestsTable(rows));
    } else {
      console.log(JSON.stringify(rows, null, 2));
    }
    return;
  }

  if (root === "request" && sub === "remind") {
    const requestId = flagValue(parsed, "request-id", true)!;
    const email = flagValue(parsed, "email");
    const result = await remindSigningRequest(db, {
      requestId,
      provider: selectedProvider,
      apiKey: resolveProviderApiKey(selectedProvider),
      email,
    });
    console.log(JSON.stringify(result, null, 2));
    return;
  }

  if (root === "request" && sub === "bulk") {
    const csvPath = flagValue(parsed, "csv", true)!;
    const documentPaths = flagValues(parsed, "document");
    if (documentPaths.length === 0) {
      throw new Error("Missing required flag: --document");
    }
    documentPaths.forEach((p) => validateDocumentPath(p));
    const titleTemplate = flagValue(parsed, "title") ?? "Bulk send for {{email}}";
    const tokenTtlMinutes = flagValue(parsed, "token-ttl-minutes") ? Number(flagValue(parsed, "token-ttl-minutes")) : undefined;
    const rows = await loadCsvFile(csvPath);
    validateBulkRowCount(rows.length);
    const logger = createLogger({ mode: resolveLogMode(flagValue(parsed, "log")) });
    const result = await bulkSendFromCsv(db, {
      rows,
      titleTemplate,
      documentPaths,
      provider: selectedProvider,
      apiKey: resolveProviderApiKey(selectedProvider),
      testMode: resolveProviderTestMode(selectedProvider, flagValue(parsed, "test-mode")),
      tokenTtlMinutes,
      onProgress: (event) => {
        logger.info("bulk", event);
      },
    });
    const emitTokensPath = flagValue(parsed, "emit-tokens");
    if (emitTokensPath) {
      const fs = await import("node:fs");
      const pathMod = await import("node:path");
      const roster = result.results
        .filter((r) => r.ok && r.token)
        .map((r) => ({
          row: r.row,
          requestId: r.requestId,
          signerEmail: r.signerEmail,
          token: r.token,
          tokenExpiresAt: r.tokenExpiresAt,
        }));
      const resolved = pathMod.resolve(emitTokensPath);
      fs.mkdirSync(pathMod.dirname(resolved), { recursive: true });
      fs.writeFileSync(resolved, JSON.stringify(roster, null, 2));
      // Strip raw tokens from the public stdout output — the file is the canonical artifact.
      result.results = result.results.map((r) => ({ ...r, token: r.token ? "<written-to-file>" : null }));
    }
    if ((flagValue(parsed, "ndjson") ?? "false") === "true") {
      const { renderBulkResultAsNdjson } = await import("./lib/ndjson.js");
      process.stdout.write(renderBulkResultAsNdjson(result));
    } else {
      console.log(JSON.stringify(result, null, 2));
    }
    if (result.failed > 0) process.exitCode = 3;
    return;
  }

  if (root === "request" && sub === "bulk-resend") {
    const csvPath = flagValue(parsed, "csv", true)!;
    const tokenTtlMinutes = flagValue(parsed, "token-ttl-minutes") ? Number(flagValue(parsed, "token-ttl-minutes")) : undefined;
    const csvRows = await loadCsvFile(csvPath);
    validateBulkRowCount(csvRows.length);
    const logger = createLogger({ mode: resolveLogMode(flagValue(parsed, "log")) });
    const rows = csvRows.map((row) => ({
      requestId: (row.request_id ?? row.requestId ?? "").trim(),
      signerEmail: (row.signer_email ?? row.signerEmail ?? row.email ?? "").trim(),
      tokenTtlMinutes: row.token_ttl_minutes || row.tokenTtlMinutes
        ? Number(row.token_ttl_minutes ?? row.tokenTtlMinutes)
        : undefined,
    }));
    const result = bulkReissueSignerTokens(db, {
      rows,
      tokenTtlMinutes,
      onProgress: (event) => logger.info("bulk-resend", event),
    });
    const emitTokensPath = flagValue(parsed, "emit-tokens");
    if (emitTokensPath) {
      const fs = await import("node:fs");
      const pathMod = await import("node:path");
      const roster = result.results
        .filter((r) => r.ok && r.token)
        .map((r) => ({
          row: r.row,
          requestId: r.requestId,
          signerEmail: r.signerEmail,
          token: r.token,
          tokenExpiresAt: r.expiresAt,
        }));
      const resolved = pathMod.resolve(emitTokensPath);
      fs.mkdirSync(pathMod.dirname(resolved), { recursive: true });
      fs.writeFileSync(resolved, JSON.stringify(roster, null, 2));
      result.results = result.results.map((r) => ({ ...r, token: r.token ? "<written-to-file>" : null }));
    }
    if ((flagValue(parsed, "ndjson") ?? "false") === "true") {
      const { renderBulkResultAsNdjson } = await import("./lib/ndjson.js");
      process.stdout.write(renderBulkResultAsNdjson(result));
    } else {
      console.log(JSON.stringify(result, null, 2));
    }
    if (result.failed > 0) process.exitCode = 3;
    return;
  }

  if (root === "request" && sub === "cancel") {
    const requestId = flagValue(parsed, "request-id", true)!;
    const reason = flagValue(parsed, "reason");
    const confirmed = (flagValue(parsed, "yes") ?? "false") === "true";
    if (!confirmed) {
      throw new Error("request cancel is destructive at the provider. Re-run with --yes true to confirm.");
    }
    const result = await cancelSigningRequest(db, {
      requestId,
      provider: selectedProvider,
      apiKey: resolveProviderApiKey(selectedProvider),
      reason,
    });
    console.log(JSON.stringify(result, null, 2));
    return;
  }

  if (root === "webhook" && sub === "verify") {
    const webhookProvider = resolveWebhookProvider(selectedProvider);
    const payloadFile = flagValue(parsed, "payload-file", true)!;
    if (webhookProvider === "signwell") {
      const secret = requireSignWellWebhookSecret();
      const payload = await loadSignWellWebhookPayloadFile(payloadFile);
      const verified = verifySignWellCallback(secret, payload, null);
      console.log(JSON.stringify({ provider: "signwell", verified, event: payload.event ?? null }, null, 2));
      return;
    }
    if (webhookProvider === "docusign") {
      const secret = requireDocuSignWebhookSecret();
      const fs = await import("node:fs/promises");
      const rawBody = await fs.readFile(payloadFile, "utf8");
      const payload = await loadDocuSignWebhookPayloadFile(payloadFile);
      const signatureHeader = flagValue(parsed, "signature-header") ?? null;
      const verified = verifyDocuSignCallback(secret, rawBody, signatureHeader);
      console.log(JSON.stringify({ provider: "docusign", verified, event: payload.event ?? null }, null, 2));
      return;
    }
    const apiKey = requireDropboxApiKey();
    const payload = await loadWebhookPayloadFile(payloadFile);
    const verified = verifyDropboxCallback(apiKey, payload);
    console.log(JSON.stringify({ provider: "dropbox", verified, event: payload.event ?? null }, null, 2));
    return;
  }

  if (root === "webhook" && sub === "ingest") {
    const webhookProvider = resolveWebhookProvider(selectedProvider);
    const payloadFile = flagValue(parsed, "payload-file", true)!;
    if (webhookProvider === "signwell") {
      const secret = requireSignWellWebhookSecret();
      const payload = await loadSignWellWebhookPayloadFile(payloadFile);
      const result = ingestSignWellWebhookPayload(db, {
        payload,
        secret,
        requestId: flagValue(parsed, "request-id"),
      });
      console.log(JSON.stringify({ provider: "signwell", ...result }, null, 2));
      return;
    }
    if (webhookProvider === "docusign") {
      const secret = requireDocuSignWebhookSecret();
      const fs = await import("node:fs/promises");
      const rawBody = await fs.readFile(payloadFile, "utf8");
      const payload = await loadDocuSignWebhookPayloadFile(payloadFile);
      const signatureHeader = flagValue(parsed, "signature-header") ?? null;
      const result = ingestDocuSignWebhookPayload(db, {
        payload,
        secret,
        rawBody,
        signatureHeader,
        requestId: flagValue(parsed, "request-id"),
      });
      console.log(JSON.stringify({ provider: "docusign", ...result }, null, 2));
      return;
    }
    const apiKey = requireDropboxApiKey();
    const payload = await loadWebhookPayloadFile(payloadFile);
    const result = ingestWebhookPayload(db, {
      payload,
      apiKey,
      requestId: flagValue(parsed, "request-id"),
    });
    console.log(JSON.stringify({ provider: "dropbox", ...result }, null, 2));
    return;
  }

  if (root === "webhook" && sub === "listen") {
    const webhookProvider = resolveWebhookProvider(selectedProvider);
    const apiKey = webhookProvider === "signwell"
      ? requireSignWellWebhookSecret()
      : webhookProvider === "docusign"
        ? requireDocuSignWebhookSecret()
        : requireDropboxApiKey();
    const port = Number(flagValue(parsed, "port") ?? "3000");
    const defaultPath = webhookProvider === "signwell"
      ? "/signwell/callback"
      : webhookProvider === "docusign"
        ? "/docusign/callback"
        : "/dropbox/callback";
    const webhookPath = flagValue(parsed, "path") ?? defaultPath;
    const requestId = flagValue(parsed, "request-id");
    const pretty = (flagValue(parsed, "pretty") ?? "false") === "true";
    const server = startWebhookServer({
      dbPath,
      apiKey,
      port,
      path: webhookPath,
      requestId,
      provider: webhookProvider,
    });
    let detachPretty: (() => void) | null = null;
    if (pretty) {
      console.error(`[webhook listen --pretty] tailing audit events to stderr; one line per event…`);
      detachPretty = attachPrettyAuditPrinter(db, process.stderr);
    }
    const shutdown = () => {
      if (detachPretty) detachPretty();
      server.close(() => process.exit(0));
    };
    process.on("SIGINT", shutdown);
    process.on("SIGTERM", shutdown);
    console.log(JSON.stringify({
      listening: true,
      provider: webhookProvider,
      port,
      path: webhookPath,
      requestId: requestId ?? null,
      callbackUrl: `http://127.0.0.1:${port}${webhookPath}`,
      signatureVerification: webhookProvider === "signwell"
        ? "event.hash via SIGNWELL_WEBHOOK_SECRET HMAC (or X-SignWell-Webhook-Signature header)"
        : webhookProvider === "docusign"
          ? "X-DocuSign-Signature-1/-2/-3 HMAC (base64 or hex) using DOCUSIGN_WEBHOOK_SECRET"
          : "event_hash via API key HMAC",
      expectedSuccessExitCode: REQUEST_WATCH_EXIT_CODES.completed,
    }, null, 2));
    return;
  }

  if (root === "serve") {
    const port = Number(flagValue(parsed, "port") ?? "4000");
    const bind = flagValue(parsed, "bind") ?? "127.0.0.1";
    const authToken = flagValue(parsed, "auth-token") ?? process.env.SIGN_HTTP_AUTH_TOKEN ?? undefined;
    const certPath = flagValue(parsed, "tls-cert");
    const keyPath = flagValue(parsed, "tls-key");
    const caPath = flagValue(parsed, "tls-ca");
    const tls = certPath && keyPath ? { certPath, keyPath, ...(caPath ? { caPath } : {}) } : undefined;
    const webDemoFlag = flagValue(parsed, "web-demo");
    const webDemoDir = webDemoFlag === "true"
      ? (await import("node:path")).resolve("fixtures/web-demo")
      : (webDemoFlag && webDemoFlag !== "false" ? (await import("node:path")).resolve(webDemoFlag) : undefined);
    const rateLimitRps = flagValue(parsed, "rate-limit");
    const rateLimitCapacity = flagValue(parsed, "rate-limit-burst");
    const rateLimit = rateLimitRps
      ? {
          refillPerSec: Math.max(0.1, Number(rateLimitRps)),
          capacity: rateLimitCapacity ? Math.max(1, Number(rateLimitCapacity)) : Math.max(1, Number(rateLimitRps) * 2),
        }
      : undefined;
    const readOnly = (flagValue(parsed, "read-only") ?? "false") === "true";
    const trustProxy = (flagValue(parsed, "trust-proxy") ?? "false") === "true";
    const server = startHttpApiServer({ db, port, bind, authToken, tls, webDemoDir, rateLimit, readOnly, trustProxy });
    const shutdown = () => server.close(() => process.exit(0));
    process.on("SIGINT", shutdown);
    process.on("SIGTERM", shutdown);
    console.log(JSON.stringify({
      listening: true,
      url: `${tls ? "https" : "http"}://${bind}:${port}`,
      tls: Boolean(tls),
      authRequired: Boolean(authToken),
      readOnly,
      rateLimit: rateLimit ? { refillPerSec: rateLimit.refillPerSec, capacity: rateLimit.capacity } : null,
      webDemo: webDemoDir ? `${tls ? "https" : "http"}://${bind}:${port}/web-demo/index.html` : null,
      // Pull from listMockHttpRoutes() so this banner can't drift from the
      // actual route registry. /v1/metrics is handled inline (not in ROUTES)
      // so include it explicitly.
      routes: ["GET /v1/metrics", ...listMockHttpRoutes()].sort(),
    }, null, 2));
    return;
  }

  if (root === "metrics" && sub === "show") {
    const { renderPrometheusMetrics } = await import("./lib/prom-metrics.js");
    process.stdout.write(renderPrometheusMetrics(db));
    return;
  }

  if (root === "metrics" && sub === "ship") {
    const url = flagValue(parsed, "url", true)!;
    const bearer = flagValue(parsed, "bearer");
    const headerEntries = flagValues(parsed, "header");
    const headers: Record<string, string> = {};
    for (const entry of headerEntries) {
      const eq = entry.indexOf("=");
      if (eq <= 0) {
        throw new SignCliError({
          code: "INVALID_ARGS",
          message: `--header expects KEY=VALUE; got ${JSON.stringify(entry)}.`,
        });
      }
      headers[entry.slice(0, eq).trim()] = entry.slice(eq + 1);
    }
    const intervalSecondsRaw = flagValue(parsed, "interval-seconds");
    const intervalMs = intervalSecondsRaw ? Math.max(1, Number(intervalSecondsRaw)) * 1000 : undefined;
    const maxPushesRaw = flagValue(parsed, "max-pushes");
    const maxPushes = maxPushesRaw ? Math.max(1, Number(maxPushesRaw)) : undefined;
    const batchSizeRaw = flagValue(parsed, "batch-size");
    const batchSize = batchSizeRaw ? Math.max(1, Number(batchSizeRaw)) : undefined;
    const { shipMetricsLoop } = await import("./lib/metrics-ship.js");
    const controller = new AbortController();
    const stop = () => controller.abort();
    process.on("SIGINT", stop);
    process.on("SIGTERM", stop);
    process.stderr.write(`[metrics ship] POST ${url} every ${(intervalMs ?? 30000) / 1000}s${batchSize && batchSize > 1 ? ` (batched ${batchSize}×)` : ""} (Ctrl+C to stop)\n`);
    const report = await shipMetricsLoop(db, {
      url,
      bearer,
      headers,
      intervalMs,
      maxPushes,
      batchSize,
      signal: controller.signal,
      onProgress: (event) => {
        if (event.phase === "render") {
          if (batchSize && batchSize > 1) {
            process.stderr.write(`[metrics ship] render #${event.pushNumber} buffered=${event.bufferedSnapshots}/${batchSize} (${event.bytes}B)\n`);
          }
        } else if (event.phase === "push") {
          process.stderr.write(`[metrics ship] push #${event.pushNumber} → HTTP ${event.status} (${event.bytes}B${event.snapshotsInBody > 1 ? `, ${event.snapshotsInBody} snapshots` : ""})\n`);
        } else if (event.phase === "error") {
          process.stderr.write(`[metrics ship] push #${event.pushNumber} ERROR: ${event.error}\n`);
        } else {
          process.stderr.write(`[metrics ship] stopped (${event.reason})\n`);
        }
      },
    });
    console.log(JSON.stringify(report, null, 2));
    return;
  }

  if (root === "completion") {
    const shell = (sub ?? "").toLowerCase();
    if (shell !== "bash" && shell !== "zsh" && shell !== "fish") {
      throw new SignCliError({
        code: "INVALID_ARGS",
        message: `Unsupported shell "${sub ?? ""}". Use bash, zsh, or fish.`,
      });
    }
    process.stdout.write(generateCompletionScript(shell as CompletionShell));
    return;
  }

  if (root === "mcp" && sub === "serve") {
    const readOnly = (flagValue(parsed, "read-only") ?? "false") === "true";
    const allowedToolNames = flagValues(parsed, "tool");
    const allowedTools = allowedToolNames.length > 0 ? new Set(allowedToolNames) : undefined;
    const capabilityNames = flagValues(parsed, "capability");
    for (const cap of capabilityNames) {
      if (cap !== "tools" && cap !== "resources" && cap !== "prompts") {
        throw new SignCliError({
          code: "INVALID_ARGS",
          message: `--capability must be one of tools, resources, prompts; got ${JSON.stringify(cap)}.`,
        });
      }
    }
    const capabilities = capabilityNames.length > 0
      ? new Set(capabilityNames as Array<"tools" | "resources" | "prompts">)
      : undefined;
    const emitEventsPath = flagValue(parsed, "emit-events");
    const emitEventsRedact = (flagValue(parsed, "emit-events-redact") ?? "false") === "true";

    // HTTP transport — Streamable HTTP MCP for Smithery / remote agent
    // clients. `--http true` switches the transport from stdio.
    const useHttp = (flagValue(parsed, "http") ?? "false") === "true";
    if (useHttp) {
      const port = Number(flagValue(parsed, "http-port") ?? process.env.PORT ?? "8080");
      if (!Number.isFinite(port) || port <= 0 || port > 65535) {
        throw new SignCliError({
          code: "INVALID_ARGS",
          message: `--http-port must be a port in 1..65535; got ${JSON.stringify(flagValue(parsed, "http-port"))}.`,
        });
      }
      // Default to loopback. Exposing the MCP control surface on all
      // interfaces (0.0.0.0) without auth is a remote attack surface; require
      // an explicit --http-bind to broaden it.
      const bind = flagValue(parsed, "http-bind") ?? "127.0.0.1";
      const endpointPath = flagValue(parsed, "http-path") ?? "/mcp";
      const authToken = flagValue(parsed, "http-auth-token") ?? process.env.SIGN_MCP_HTTP_AUTH_TOKEN;
      const server = startMcpHttpServer({
        port, bind, endpointPath, authToken,
        db, readOnly, allowedTools, capabilities, emitEventsPath, emitEventsRedact,
      });
      await new Promise<void>((resolve) => {
        const shutdown = () => server.close(() => resolve());
        process.on("SIGINT", shutdown);
        process.on("SIGTERM", shutdown);
      });
      return;
    }

    await serveMcpStdio({ input: process.stdin, output: process.stdout, db, readOnly, allowedTools, capabilities, emitEventsPath, emitEventsRedact });
    return;
  }

  if (root === "mcp" && sub === "tools") {
    const format = (flagValue(parsed, "format") ?? "json").toLowerCase();
    if (format !== "json" && format !== "markdown") {
      throw new SignCliError({
        code: "INVALID_ARGS",
        message: `--format must be json or markdown; got ${JSON.stringify(format)}.`,
      });
    }
    if (format === "markdown") {
      process.stdout.write(renderMcpToolsAsMarkdown());
      return;
    }
    console.log(JSON.stringify({ tools: listMcpTools() }, null, 2));
    return;
  }

  if (root === "request" && sub === "show") {
    const requestId = flagValue(parsed, "request-id", true)!;
    const hashOnly = (flagValue(parsed, "hash-only") ?? "false") === "true";
    if (hashOnly) {
      // Pure-hash projection — no signers, status, or PII. Stable across
      // builds for diff-style scripted comparisons (jq, watch, sha256sum).
      const requestRow = db.prepare(
        "SELECT id, document_hash FROM requests WHERE id = ?",
      ).get(requestId) as { id: string; document_hash: string | null } | undefined;
      if (!requestRow) {
        throw new SignCliError({
          code: "REQUEST_NOT_FOUND",
          message: `Request not found: ${requestId}`,
        });
      }
      const headRow = db.prepare(
        "SELECT hash_self FROM audit_events WHERE request_id = ? ORDER BY id DESC LIMIT 1",
      ).get(requestId) as { hash_self: string } | undefined;
      console.log(JSON.stringify({
        requestId: requestRow.id,
        documentSha256: requestRow.document_hash,
        chainHead: headRow?.hash_self ?? null,
      }, null, 2));
      return;
    }
    const includeMetrics = (flagValue(parsed, "metrics") ?? "false") === "true";
    const snapshot = getRequestSnapshot(db, requestId, { includeMetrics });
    const recipientFilter = flagValue(parsed, "recipient");
    if (recipientFilter) {
      const norm = recipientFilter.trim().toLowerCase();
      // Confirm the recipient is actually on this request — refuse otherwise.
      const requestSigners = (() => {
        try { return JSON.parse(snapshot.request.signers_json) as Array<{ email?: string; name?: string; order?: number }>; }
        catch { return []; }
      })();
      const matchedSigner = requestSigners.find((s) => (s.email ?? "").trim().toLowerCase() === norm);
      if (!matchedSigner) {
        throw new SignCliError({
          code: "SIGNER_NOT_RECIPIENT",
          message: `${recipientFilter} is not a recipient on request ${requestId}.`,
        });
      }
      // Build a redacted view: drop other signers from request.signers_json,
      // approvals, signedBy. Hide declinedBy/declineReason unless this
      // recipient is the one who declined.
      const redactedSnapshot = {
        ...snapshot,
        request: {
          ...snapshot.request,
          signers_json: JSON.stringify([matchedSigner]),
        },
        approvals: snapshot.approvals.filter((a) => a.signer_email.trim().toLowerCase() === norm),
        signedBy: snapshot.signedBy
          ? snapshot.signedBy.filter((s) => s.email.trim().toLowerCase() === norm)
          : null,
        declinedBy: snapshot.declinedBy && snapshot.declinedBy.trim().toLowerCase() === norm ? snapshot.declinedBy : null,
        declineReason: snapshot.declinedBy && snapshot.declinedBy.trim().toLowerCase() === norm ? snapshot.declineReason : null,
      };
      console.log(JSON.stringify({ ...redactedSnapshot, recipientView: recipientFilter }, null, 2));
      return;
    }
    console.log(JSON.stringify(snapshot, null, 2));
    return;
  }

  if (root === "request" && sub === "diff") {
    const before = flagValue(parsed, "before", true)!;
    const after = flagValue(parsed, "after", true)!;
    const result = diffRequests(db, before, after);
    console.log(JSON.stringify(result, null, 2));
    process.exitCode = result.identical ? 0 : 1;
    return;
  }

  if (root === "request" && sub === "rerun-policy") {
    const requestId = flagValue(parsed, "request-id", true)!;
    const specPath = flagValue(parsed, "spec", true)!;
    const signerEmail = flagValue(parsed, "signer-email");
    const { loadPolicySpec } = await import("./lib/policy-engine.js");
    const spec = loadPolicySpec(specPath);
    const result = rerunPolicyForRequest(db, { requestId, spec, signerEmail });
    console.log(JSON.stringify(result, null, 2));
    return;
  }

  printUsage();
  throw new SignCliError({
    code: "UNKNOWN_COMMAND",
    message: `Unknown command: ${parsed.positionals.join(" ")}`,
    details: { positionals: parsed.positionals },
  });
}

main().catch((error) => {
  const envelope = formatCliError(error);
  if (process.env.SIGN_ERROR_FORMAT === "text") {
    console.error(redactErrorMessage(error));
  } else {
    console.error(JSON.stringify(envelope, null, 2));
  }
  process.exitCode = 1;
});
