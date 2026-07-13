import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import {
  buildProviderMatrix,
  createSigningRequest,
  exportAuditBundle,
  inspectRequestSignedPdf,
  runLocalDemo,
  runProviderAccountCheck,
  sendSigningRequest,
  verifyRequestAuditChain,
  watchSigningRequestStatus,
} from "../lib/signing-service.js";
import { createDb, makeTempDb } from "./helpers.js";

function withScopedLocalStorage<T>(fn: () => Promise<T> | T): Promise<T> | T {
  const dir = mkdtempSync(path.join(os.tmpdir(), "sign-local-"));
  const previousStore = process.env.SIGN_LOCAL_STORE_DIR;
  const previousKeys = process.env.SIGN_LOCAL_KEY_DIR;
  process.env.SIGN_LOCAL_STORE_DIR = path.join(dir, "store");
  process.env.SIGN_LOCAL_KEY_DIR = path.join(dir, "keys");
  const restore = () => {
    if (previousStore === undefined) delete process.env.SIGN_LOCAL_STORE_DIR;
    else process.env.SIGN_LOCAL_STORE_DIR = previousStore;
    if (previousKeys === undefined) delete process.env.SIGN_LOCAL_KEY_DIR;
    else process.env.SIGN_LOCAL_KEY_DIR = previousKeys;
    rmSync(dir, { recursive: true, force: true });
  };
  try {
    const result = fn();
    if (result instanceof Promise) {
      return result.finally(restore);
    }
    restore();
    return result;
  } catch (error) {
    restore();
    throw error;
  }
}

test("buildProviderMatrix lists local provider as configured", () => {
  const local = buildProviderMatrix().find((entry) => entry.provider === "local");
  assert.ok(local, "local provider must appear in the matrix");
  assert.equal(local.config.configured, true);
  assert.equal(local.capabilities.emailSend, true);
  assert.equal(local.capabilities.embeddedSigning, true);
});

test("runProviderAccountCheck for local needs no API key", async () => {
  const result = await runProviderAccountCheck({ provider: "local" });
  assert.equal(result.provider, "local");
  assert.match(JSON.stringify(result), /local simulator/i);
});

test("local provider runs the full create -> send -> watch -> verify-signed-pdf flow", { concurrency: false }, async () => {
  await withScopedLocalStorage(async () => {
    const { dbPath, cleanup } = makeTempDb();
    const db = createDb(dbPath);
    const dir = mkdtempSync(path.join(os.tmpdir(), "sign-local-flow-"));
    const documentPath = path.join(dir, "doc.pdf");
    writeFileSync(documentPath, Buffer.from("%PDF-1.4\n%nothing\n%%EOF", "latin1"));
    try {
      const created = createSigningRequest(db, {
        title: "Local flow",
        documentPath,
        signers: [{ name: "Demo", email: "demo@example.com", order: 1 }],
        tokenTtlMinutes: 30,
        provider: "local",
        autoApprove: true,
      });
      const sent = await sendSigningRequest(db, {
        requestId: created.requestId,
        provider: "local",
        testMode: true,
      });
      assert.match(sent.signatureRequestId, /^local_/);

      const watch = await watchSigningRequestStatus(db, {
        requestId: created.requestId,
        provider: "local",
        intervalMs: 5,
        timeoutMs: 1000,
        fetchFinalPdf: true,
        outPath: path.join(dir, "signed.pdf"),
      });
      assert.equal(watch.terminal, "completed");
      assert.ok(watch.finalPdf);

      const inspection = await inspectRequestSignedPdf(db, { requestId: created.requestId });
      assert.equal(inspection.report.hasSignature, true);
      assert.equal(inspection.report.signatures[0].messageDigestMatches, true);
      assert.match(inspection.report.signatures[0].signers[0].subject ?? "", /Sign CLI Local Signer/);

      assert.equal(verifyRequestAuditChain(db, created.requestId).valid, true);
    } finally {
      rmSync(dir, { recursive: true, force: true });
      db.close();
      cleanup();
    }
  });
});

test("runLocalDemo produces a bundle with a verifiable signed PDF and a valid audit chain", { concurrency: false }, async () => {
  await withScopedLocalStorage(async () => {
    const { dbPath, cleanup } = makeTempDb();
    const db = createDb(dbPath);
    const dir = mkdtempSync(path.join(os.tmpdir(), "sign-demo-out-"));
    try {
      const result = await runLocalDemo(db, { outDir: dir });
      assert.equal(result.auditChainValid, true);
      assert.equal(result.messageDigestVerified, true);
      assert.equal(result.signatureCount, 1);
      assert.match(result.signedPdfPath, /signed\.pdf$/);
      // The demo drives the consent flow end-to-end: both gates must have
      // actually blocked a sign attempt before the attestations satisfied them.
      assert.deepEqual(result.consent.gatesEnforced, ["EMAIL_VERIFICATION_REQUIRED", "CONSENT_REQUIRED"]);
      assert.ok(result.consent.emailVerifiedAt);
      assert.ok(result.consent.intentToSignAcceptedAt);
      assert.ok(result.consent.esignDisclosureAcceptedAt);
      assert.equal(result.consent.identityAssuranceMethod, "known-contact");

      const fs = await import("node:fs");
      assert.ok(fs.existsSync(path.join(dir, "manifest.json")));
      assert.ok(fs.existsSync(path.join(dir, "signed.pdf")));
      assert.ok(fs.existsSync(path.join(dir, "audit.json")));
    } finally {
      rmSync(dir, { recursive: true, force: true });
      db.close();
      cleanup();
    }
  });
});

test("local provider supports embedded signing with a per-recipient sign URL", { concurrency: false }, async () => {
  await withScopedLocalStorage(async () => {
    const { dbPath, cleanup } = makeTempDb();
    const db = createDb(dbPath);
    const dir = mkdtempSync(path.join(os.tmpdir(), "sign-local-embed-"));
    const documentPath = path.join(dir, "doc.pdf");
    writeFileSync(documentPath, Buffer.from("%PDF-1.4\n%nothing\n%%EOF", "latin1"));
    try {
      const { sendEmbeddedSigningRequest, getEmbeddedSignUrl } = await import("../lib/signing-service.js");
      const created = createSigningRequest(db, {
        title: "Embedded local",
        documentPath,
        signers: [{ name: "Demo", email: "demo@example.com", order: 1 }],
        tokenTtlMinutes: 30,
        provider: "local",
        autoApprove: true,
      });
      const sent = await sendEmbeddedSigningRequest(db, {
        requestId: created.requestId,
        provider: "local",
        testMode: true,
      });
      assert.equal(sent.signatureIds[0], "local_recipient_1");
      const signUrl = await getEmbeddedSignUrl(db, {
        requestId: created.requestId,
        provider: "local",
        signatureId: "local_recipient_1",
      });
      assert.match(signUrl.signUrl, /^data:text\/html/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
      db.close();
      cleanup();
    }
  });
});
