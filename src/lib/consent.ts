// Canonical consent statements + identity-assurance parsing.
//
// The statements below are versioned and immutable: NEVER edit the text of a
// published version in place. If the wording needs to change, add a new
// `*.v2` constant and make it the default — audit events reference the
// version id + SHA-256 of the exact text the signer accepted, so rewording a
// published version would break re-verification of historical consents.
//
// Design boundary (see docs/reference/consent-and-identity.md): this module
// records *assertions* — what the signer agreed to, and how the operator says
// identity was checked. It deliberately stores no identity documents or
// government-ID data; that is a data-minimization choice, not an oversight.

import { SignCliError } from "./sign-error.js";
import { sha256 } from "./util.js";

export type ConsentStatement = {
  /** Stable id recorded in audit events, e.g. "intent-to-sign.v1". */
  version: string;
  /** Audit-event kind + signer_consents.kind value. */
  kind: "intent_to_sign" | "esign_disclosure";
  /** Exact text the signer accepts. */
  text: string;
};

export const INTENT_TO_SIGN_STATEMENT: ConsentStatement = {
  version: "intent-to-sign.v1",
  kind: "intent_to_sign",
  text:
    "I have reviewed the document identified by the SHA-256 hash recorded for this signing request, " +
    "and I intend to sign it electronically. I understand that my electronic signature is intended to " +
    "have the same effect as a handwritten signature to the extent permitted by applicable law, and " +
    "that this attestation is recorded in a tamper-evident audit log together with the date and time.",
};

export const ESIGN_DISCLOSURE_STATEMENT: ConsentStatement = {
  version: "esign-disclosure.v1",
  kind: "esign_disclosure",
  text:
    "I consent to conduct this transaction electronically and to receive, review, and sign the records " +
    "relating to this signing request in electronic form rather than on paper. I understand that I may " +
    "instead decline to sign electronically and ask the requester for a paper alternative, that I may " +
    "withdraw this consent for future transactions by notifying the requester, and that I should retain " +
    "a copy of the signed document for my records. Viewing the electronic records for this request " +
    "requires a device capable of displaying PDF files.",
};

export const CONSENT_STATEMENTS: ConsentStatement[] = [
  INTENT_TO_SIGN_STATEMENT,
  ESIGN_DISCLOSURE_STATEMENT,
];

export function statementSha256(statement: ConsentStatement): string {
  return sha256(statement.text);
}

export function describeConsentStatements(): Array<{
  kind: string;
  version: string;
  sha256: string;
  text: string;
}> {
  return CONSENT_STATEMENTS.map((statement) => ({
    kind: statement.kind,
    version: statement.version,
    sha256: statementSha256(statement),
    text: statement.text,
  }));
}

// ---------------------------------------------------------------------------
// Identity assurance
// ---------------------------------------------------------------------------

/** How the operator verified the signer's identity, out-of-band. */
export const IDENTITY_ASSURANCE_METHODS = [
  "in-person",
  "video-call",
  "document-check",
  "provider-idv",
  "known-contact",
  "other",
] as const;

export type IdentityAssuranceMethod = (typeof IDENTITY_ASSURANCE_METHODS)[number];

export type IdentityAssuranceInput = {
  method: IdentityAssuranceMethod;
  /** Who performed the check (a person or system name), e.g. "ops@acme.com". */
  verifier?: string;
  /** Pointer to where evidence lives (ticket id, provider envelope id) — NOT the evidence itself. */
  reference?: string;
  notes?: string;
};

const IDENTITY_ASSURANCE_MAX_FIELD_LENGTH = 500;

/**
 * Parse `method:video-call,verifier:ops@acme.com,reference:TICKET-123,notes:...`
 * (same spec shape as --signer). Values are capped at 500 chars; the intent is
 * a pointer to evidence, not the evidence — keep ID numbers and document scans
 * out of it.
 */
export function parseIdentityAssuranceSpec(raw: string): IdentityAssuranceInput {
  const record: Record<string, string> = {};
  for (const segment of raw.split(",").map((s) => s.trim()).filter(Boolean)) {
    const colon = segment.indexOf(":");
    if (colon === -1) {
      throw new SignCliError({
        code: "INVALID_ARGS",
        message: `Invalid --identity-assurance segment: "${segment}" (expected key:value).`,
        hint: "Example: --identity-assurance method:video-call,verifier:ops@acme.com,reference:TICKET-123",
      });
    }
    record[segment.slice(0, colon).trim()] = segment.slice(colon + 1).trim();
  }
  const method = record.method as IdentityAssuranceMethod | undefined;
  if (!method || !IDENTITY_ASSURANCE_METHODS.includes(method)) {
    throw new SignCliError({
      code: "INVALID_ARGS",
      message: `--identity-assurance needs method:<one of ${IDENTITY_ASSURANCE_METHODS.join(" | ")}>.`,
      hint: "Example: --identity-assurance method:in-person,verifier:\"Jane Ops\",reference:TICKET-123",
    });
  }
  for (const key of ["verifier", "reference", "notes"] as const) {
    const value = record[key];
    if (value !== undefined && value.length > IDENTITY_ASSURANCE_MAX_FIELD_LENGTH) {
      throw new SignCliError({
        code: "INVALID_ARGS",
        message: `--identity-assurance ${key} exceeds ${IDENTITY_ASSURANCE_MAX_FIELD_LENGTH} characters.`,
        hint: "Record a short pointer to where the evidence lives (ticket id, envelope id) — not the evidence itself.",
      });
    }
  }
  return {
    method,
    ...(record.verifier ? { verifier: record.verifier } : {}),
    ...(record.reference ? { reference: record.reference } : {}),
    ...(record.notes ? { notes: record.notes } : {}),
  };
}
