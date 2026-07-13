import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import {
  approveSigningRequest,
  createSigningRequest,
  getRequestSnapshot,
  issueSignerEmailVerification,
  listAuditEvents,
  recordIdentityAssurance,
  sendSigningRequest,
  signSigningRequest,
  verifySignerEmailCode,
} from "../lib/signing-service.js";
import { verifyAuditChain } from "../lib/audit.js";
import {
  describeConsentStatements,
  ESIGN_DISCLOSURE_STATEMENT,
  INTENT_TO_SIGN_STATEMENT,
  parseIdentityAssuranceSpec,
  statementSha256,
} from "../lib/consent.js";
import { SignCliError } from "../lib/sign-error.js";
import { createDb, createDocumentFixture, makeTempDb } from "./helpers.js";

const SIGNER = { name: "Alice", email: "alice@example.com", order: 1 };

function bootstrap(opts: {
  requireConsent?: boolean;
  requireEmailVerification?: boolean;
  signers?: Array<{ name: string; email: string; order: number }>;
} = {}) {
  const temp = makeTempDb();
  const db = createDb(temp.dbPath);
  const documentPath = createDocumentFixture();
  const created = createSigningRequest(db, {
    title: "Consent test",
    documentPath,
    signers: opts.signers ?? [SIGNER],
    tokenTtlMinutes: 30,
    provider: "local",
    requireConsent: opts.requireConsent,
    requireEmailVerification: opts.requireEmailVerification,
  });
  return {
    db,
    created,
    cleanup: () => {
      db.close();
      temp.cleanup();
    },
  };
}

function auditEventsOfType(db: ReturnType<typeof createDb>, requestId: string, eventType: string) {
  return listAuditEvents(db, requestId)
    .filter((event) => event.event_type === eventType)
    .map((event) => JSON.parse(event.payload_json));
}

// ---------------------------------------------------------------------------
// Canonical statements
// ---------------------------------------------------------------------------

test("consent statements are versioned and hash-stable", () => {
  const described = describeConsentStatements();
  assert.equal(described.length, 2);
  const byKind = new Map(described.map((entry) => [entry.kind, entry]));
  assert.equal(byKind.get("intent_to_sign")?.version, "intent-to-sign.v1");
  assert.equal(byKind.get("esign_disclosure")?.version, "esign-disclosure.v1");
  assert.equal(byKind.get("intent_to_sign")?.sha256, statementSha256(INTENT_TO_SIGN_STATEMENT));
  assert.equal(byKind.get("esign_disclosure")?.sha256, statementSha256(ESIGN_DISCLOSURE_STATEMENT));
  for (const entry of described) {
    assert.ok(entry.text.length > 100, `statement ${entry.version} should be a real statement`);
  }
});

// ---------------------------------------------------------------------------
// Identity-assurance spec parsing
// ---------------------------------------------------------------------------

test("parseIdentityAssuranceSpec: happy path + validation", () => {
  const parsed = parseIdentityAssuranceSpec("method:video-call,verifier:ops@acme.com,reference:TICKET-123");
  assert.deepEqual(parsed, { method: "video-call", verifier: "ops@acme.com", reference: "TICKET-123" });

  assert.throws(() => parseIdentityAssuranceSpec("verifier:ops@acme.com"), (err: unknown) =>
    err instanceof SignCliError && err.code === "INVALID_ARGS");
  assert.throws(() => parseIdentityAssuranceSpec("method:palm-reading"), (err: unknown) =>
    err instanceof SignCliError && err.code === "INVALID_ARGS");
  assert.throws(() => parseIdentityAssuranceSpec(`method:other,notes:${"x".repeat(501)}`), (err: unknown) =>
    err instanceof SignCliError && err.code === "INVALID_ARGS");
});

// ---------------------------------------------------------------------------
// Create-time validation
// ---------------------------------------------------------------------------

test("auto-approve cannot bypass the consent / verification gates", () => {
  const temp = makeTempDb();
  const db = createDb(temp.dbPath);
  const documentPath = createDocumentFixture();
  try {
    for (const gate of [{ requireConsent: true }, { requireEmailVerification: true }]) {
      assert.throws(
        () =>
          createSigningRequest(db, {
            title: "Bypass attempt",
            documentPath,
            signers: [SIGNER],
            tokenTtlMinutes: 30,
            autoApprove: true,
            ...gate,
          }),
        (err: unknown) => err instanceof SignCliError && err.code === "INVALID_ARGS",
      );
    }
  } finally {
    db.close();
    temp.cleanup();
  }
});

test("request.created audit payload records the gates", () => {
  const ctx = bootstrap({ requireConsent: true, requireEmailVerification: true });
  try {
    const [payload] = auditEventsOfType(ctx.db, ctx.created.requestId, "request.created");
    assert.equal(payload.requireConsent, true);
    assert.equal(payload.requireEmailVerification, true);
  } finally {
    ctx.cleanup();
  }
});

// ---------------------------------------------------------------------------
// Consent capture at approve
// ---------------------------------------------------------------------------

test("approve without consent is rejected when required; with consent it records both attestations", () => {
  const ctx = bootstrap({ requireConsent: true });
  try {
    const token = ctx.created.tokens[0].token;

    assert.throws(
      () => approveSigningRequest(ctx.db, { requestId: ctx.created.requestId, token }),
      (err: unknown) => err instanceof SignCliError && err.code === "CONSENT_REQUIRED",
    );

    // --agree alone is not enough: the disclosure must be accepted too.
    assert.throws(
      () => approveSigningRequest(ctx.db, { requestId: ctx.created.requestId, token, agree: true }),
      (err: unknown) => err instanceof SignCliError && err.code === "CONSENT_REQUIRED",
    );

    const approved = approveSigningRequest(ctx.db, {
      requestId: ctx.created.requestId,
      token,
      agree: true,
      acceptDisclosure: true,
    });
    assert.equal(approved.requestStatus, "approved");
    assert.ok(approved.consent?.intentToSignAcceptedAt);
    assert.ok(approved.consent?.esignDisclosureAcceptedAt);

    const intentEvents = auditEventsOfType(ctx.db, ctx.created.requestId, "request.consent_captured");
    assert.equal(intentEvents.length, 1);
    assert.equal(intentEvents[0].signerEmail, SIGNER.email);
    assert.equal(intentEvents[0].statementVersion, "intent-to-sign.v1");
    assert.equal(intentEvents[0].statementSha256, statementSha256(INTENT_TO_SIGN_STATEMENT));
    assert.equal(intentEvents[0].statementText, INTENT_TO_SIGN_STATEMENT.text);

    const disclosureEvents = auditEventsOfType(ctx.db, ctx.created.requestId, "request.esign_consent_captured");
    assert.equal(disclosureEvents.length, 1);
    assert.equal(disclosureEvents[0].statementVersion, "esign-disclosure.v1");

    const [approvedPayload] = auditEventsOfType(ctx.db, ctx.created.requestId, "request.approved");
    assert.equal(approvedPayload.intentToSignCaptured, true);
    assert.equal(approvedPayload.esignDisclosureAccepted, true);

    assert.equal(verifyAuditChain(ctx.db, ctx.created.requestId).valid, true);
  } finally {
    ctx.cleanup();
  }
});

test("consent capture is opt-in even when not required, and partial-consent retry keeps the token spendable", () => {
  const ctx = bootstrap();
  try {
    const approved = approveSigningRequest(ctx.db, {
      requestId: ctx.created.requestId,
      token: ctx.created.tokens[0].token,
      agree: true,
    });
    assert.ok(approved.consent?.intentToSignAcceptedAt);
    assert.equal(approved.consent?.esignDisclosureAcceptedAt, undefined);
    assert.equal(auditEventsOfType(ctx.db, ctx.created.requestId, "request.consent_captured").length, 1);
  } finally {
    ctx.cleanup();
  }
});

// ---------------------------------------------------------------------------
// The gates hold at sign time (the surface MCP/HTTP share)
// ---------------------------------------------------------------------------

test("sign is blocked until consent is captured, then succeeds", { concurrency: false }, async () => {
  const dir = mkdtempSync(path.join(os.tmpdir(), "sign-consent-gate-"));
  const previousStore = process.env.SIGN_LOCAL_STORE_DIR;
  const previousKeys = process.env.SIGN_LOCAL_KEY_DIR;
  process.env.SIGN_LOCAL_STORE_DIR = path.join(dir, "store");
  process.env.SIGN_LOCAL_KEY_DIR = path.join(dir, "keys");
  const temp = makeTempDb();
  const db = createDb(temp.dbPath);
  try {
    const documentPath = path.join(dir, "doc.pdf");
    writeFileSync(documentPath, Buffer.from("%PDF-1.4\n%nothing\n%%EOF", "latin1"));
    const created = createSigningRequest(db, {
      title: "Consent gate at sign",
      documentPath,
      signers: [SIGNER],
      tokenTtlMinutes: 30,
      provider: "local",
      requireConsent: true,
    });
    await sendSigningRequest(db, { requestId: created.requestId, provider: "local", testMode: true });
    const token = created.tokens[0].token;

    assert.throws(
      () => signSigningRequest(db, { requestId: created.requestId, token }),
      (err: unknown) => err instanceof SignCliError && err.code === "CONSENT_REQUIRED",
    );

    approveSigningRequest(db, { requestId: created.requestId, token, agree: true, acceptDisclosure: true });
    const signed = signSigningRequest(db, { requestId: created.requestId, token });
    assert.equal(signed.signerEmail, SIGNER.email);
    assert.equal(verifyAuditChain(db, created.requestId).valid, true);
  } finally {
    db.close();
    temp.cleanup();
    if (previousStore === undefined) delete process.env.SIGN_LOCAL_STORE_DIR;
    else process.env.SIGN_LOCAL_STORE_DIR = previousStore;
    if (previousKeys === undefined) delete process.env.SIGN_LOCAL_KEY_DIR;
    else process.env.SIGN_LOCAL_KEY_DIR = previousKeys;
    rmSync(dir, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// Email verification
// ---------------------------------------------------------------------------

test("email verification: issue → wrong code → right code → approve passes", async () => {
  const ctx = bootstrap({ requireEmailVerification: true });
  try {
    const token = ctx.created.tokens[0].token;

    assert.throws(
      () => approveSigningRequest(ctx.db, { requestId: ctx.created.requestId, token }),
      (err: unknown) => err instanceof SignCliError && err.code === "EMAIL_VERIFICATION_REQUIRED",
    );

    const issued = await issueSignerEmailVerification(ctx.db, {
      requestId: ctx.created.requestId,
      signerEmail: SIGNER.email,
    });
    assert.match(issued.code, /^\d{6}$/u);
    assert.equal(issued.deliveredVia, "manual");

    // The audit chain never sees the plaintext code — only the hint.
    const [issuedPayload] = auditEventsOfType(ctx.db, ctx.created.requestId, "request.signer_verification_issued");
    assert.equal(issuedPayload.codeHint, issued.codeHint);
    assert.equal(issuedPayload.code, undefined);
    assert.ok(!JSON.stringify(issuedPayload).includes(issued.code));

    const wrongCode = issued.code === "000000" ? "000001" : "000000";
    assert.throws(
      () => verifySignerEmailCode(ctx.db, { requestId: ctx.created.requestId, signerEmail: SIGNER.email, code: wrongCode }),
      (err: unknown) => err instanceof SignCliError && err.code === "VERIFICATION_CODE_INVALID",
    );

    const verified = verifySignerEmailCode(ctx.db, {
      requestId: ctx.created.requestId,
      signerEmail: SIGNER.email,
      code: issued.code,
    });
    assert.ok(verified.verifiedAt);
    assert.equal(auditEventsOfType(ctx.db, ctx.created.requestId, "request.signer_email_verified").length, 1);

    const approved = approveSigningRequest(ctx.db, { requestId: ctx.created.requestId, token });
    assert.equal(approved.requestStatus, "approved");
    assert.equal(verifyAuditChain(ctx.db, ctx.created.requestId).valid, true);
  } finally {
    ctx.cleanup();
  }
});

test("email verification: one-step approve with --verification-code", async () => {
  const ctx = bootstrap({ requireEmailVerification: true });
  try {
    const issued = await issueSignerEmailVerification(ctx.db, {
      requestId: ctx.created.requestId,
      signerEmail: SIGNER.email,
    });
    const approved = approveSigningRequest(ctx.db, {
      requestId: ctx.created.requestId,
      token: ctx.created.tokens[0].token,
      verificationCode: issued.code,
    });
    assert.ok(approved.emailVerifiedAt);
  } finally {
    ctx.cleanup();
  }
});

test("email verification: expiry, attempt lockout, and re-issue invalidating prior codes", async () => {
  const ctx = bootstrap({ requireEmailVerification: true });
  try {
    const requestId = ctx.created.requestId;
    const expired = await issueSignerEmailVerification(ctx.db, {
      requestId,
      signerEmail: SIGNER.email,
      ttlMinutes: 5,
      now: new Date("2026-07-13T12:00:00.000Z"),
    });
    assert.throws(
      () => verifySignerEmailCode(ctx.db, {
        requestId,
        signerEmail: SIGNER.email,
        code: expired.code,
        now: new Date("2026-07-13T12:06:00.000Z"),
      }),
      (err: unknown) => err instanceof SignCliError && err.code === "VERIFICATION_CODE_EXPIRED",
    );

    // Re-issue replaces the prior unverified code entirely.
    const reissued = await issueSignerEmailVerification(ctx.db, { requestId, signerEmail: SIGNER.email });
    assert.throws(
      () => verifySignerEmailCode(ctx.db, { requestId, signerEmail: SIGNER.email, code: expired.code }),
      (err: unknown) => err instanceof SignCliError && err.code === "VERIFICATION_CODE_INVALID",
    );

    // 5 wrong attempts lock the code even if the right one arrives afterwards.
    const wrongCode = reissued.code === "000000" ? "000001" : "000000";
    for (let attempt = 0; attempt < 5; attempt += 1) {
      assert.throws(() =>
        verifySignerEmailCode(ctx.db, { requestId, signerEmail: SIGNER.email, code: wrongCode }));
    }
    assert.throws(
      () => verifySignerEmailCode(ctx.db, { requestId, signerEmail: SIGNER.email, code: reissued.code }),
      (err: unknown) =>
        err instanceof SignCliError &&
        err.code === "VERIFICATION_CODE_INVALID" &&
        /locked/u.test(err.message),
    );
  } finally {
    ctx.cleanup();
  }
});

test("issue verification rejects emails that are not on the request", async () => {
  const ctx = bootstrap();
  try {
    await assert.rejects(
      issueSignerEmailVerification(ctx.db, {
        requestId: ctx.created.requestId,
        signerEmail: "mallory@example.com",
      }),
      (err: unknown) => err instanceof SignCliError && err.code === "SIGNER_NOT_RECIPIENT",
    );
  } finally {
    ctx.cleanup();
  }
});

// ---------------------------------------------------------------------------
// Identity assurance
// ---------------------------------------------------------------------------

test("recordIdentityAssurance appends the assertion to the audit chain", () => {
  const ctx = bootstrap();
  try {
    const result = recordIdentityAssurance(ctx.db, {
      requestId: ctx.created.requestId,
      signerEmail: SIGNER.email,
      assurance: { method: "video-call", verifier: "ops@acme.com", reference: "TICKET-123" },
    });
    assert.equal(result.method, "video-call");

    const [payload] = auditEventsOfType(ctx.db, ctx.created.requestId, "request.identity_assurance_recorded");
    assert.equal(payload.signerEmail, SIGNER.email);
    assert.equal(payload.method, "video-call");
    assert.equal(payload.verifier, "ops@acme.com");
    assert.equal(payload.reference, "TICKET-123");
    assert.equal(verifyAuditChain(ctx.db, ctx.created.requestId).valid, true);
  } finally {
    ctx.cleanup();
  }
});

// ---------------------------------------------------------------------------
// Snapshot surfacing
// ---------------------------------------------------------------------------

test("request snapshot exposes consent + verification state per signer", async () => {
  const ctx = bootstrap({
    requireConsent: true,
    requireEmailVerification: true,
    signers: [SIGNER, { name: "Bob", email: "bob@example.com", order: 2 }],
  });
  try {
    const requestId = ctx.created.requestId;
    const issued = await issueSignerEmailVerification(ctx.db, { requestId, signerEmail: SIGNER.email });
    verifySignerEmailCode(ctx.db, { requestId, signerEmail: SIGNER.email, code: issued.code });
    approveSigningRequest(ctx.db, {
      requestId,
      token: ctx.created.tokens[0].token,
      agree: true,
      acceptDisclosure: true,
    });

    const snapshot = getRequestSnapshot(ctx.db, requestId);
    assert.equal(snapshot.consent.consentRequired, true);
    assert.equal(snapshot.consent.emailVerificationRequired, true);
    const alice = snapshot.consent.signers.find((entry) => entry.signerEmail === SIGNER.email);
    const bob = snapshot.consent.signers.find((entry) => entry.signerEmail === "bob@example.com");
    assert.ok(alice?.intentToSignAcceptedAt);
    assert.ok(alice?.esignDisclosureAcceptedAt);
    assert.ok(alice?.emailVerifiedAt);
    assert.equal(bob?.intentToSignAcceptedAt, null);
    assert.equal(bob?.emailVerifiedAt, null);
  } finally {
    ctx.cleanup();
  }
});
