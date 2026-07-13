# Consent & identity assurance

What the consent layer records, why it exists, and what it deliberately
does **not** do. Companion to [`legal.md`](./legal.md) (the posture) and
[`audit-chain.md`](./audit-chain.md) (the mechanism).

## Why this layer exists

Under US ESIGN/UETA, the questions a court actually asks about an
electronic signature are procedural, not cryptographic: did the signer
**intend to sign**, did they **consent to transact electronically**, and
can you **attribute** the signature to them? The PAdES envelope and the
hash-chained audit log already prove *what* was signed and *when*; this
layer adds explicit, tamper-evident evidence of *intent*, *consent*, and
*email control* — plus a place to record how identity was checked
out-of-band.

What it does **not** do: verify anyone's legal identity. There is no ID
upload, no government-ID field, no KYC. That is deliberate
(data minimization — see [Design boundaries](#design-boundaries)); real
identity verification belongs to hosted-provider IDV or a QTSP.

## The four mechanisms

### 1. Intent-to-sign attestation

A canonical, versioned statement the signer affirmatively accepts at the
approval step:

```bash
sign consent show          # read the exact texts, version ids, SHA-256
sign approve --request-id req_abc --token <token> --agree true --accept-disclosure true
```

Accepting records `request.consent_captured` in the audit chain with the
statement's version id (`intent-to-sign.v1`), its SHA-256, the full text,
the signer email, and the timestamp. Statement texts are immutable per
version — a wording change becomes a new `.v2`, so historical events
always re-verify against the exact text that was accepted.

### 2. Electronic-records (ESIGN) disclosure

The second half of the same gesture: `--accept-disclosure true` records
`request.esign_consent_captured` — the signer's consent to conduct the
transaction electronically, with the same version/hash/text treatment
(`esign-disclosure.v1`). The disclosure covers the right to decline and
request paper, withdrawal for future transactions, record retention, and
hardware requirements — the elements 15 U.S.C. § 7001(c) cares about.

### 3. Signer email verification (opt-in)

Proves the signer controls the mailbox the request was addressed to —
attribution evidence the bare approval token cannot give you (the
requester knows the token; only the mailbox owner should know the code).

```bash
# Requester: issue a 6-digit code (invalidates prior unverified codes)
sign signer send-verification --request-id req_abc --email alice@acme.com

# Signer: redeem it
sign signer verify-email --request-id req_abc --email alice@acme.com --code 123456
# …or in one step at approval time:
sign approve --request-id req_abc --token <token> --verification-code 123456
```

Mechanics: only the code's SHA-256 is stored; the audit chain sees a
masked hint (`1****6`), never the plaintext. Codes default to a 15-minute
TTL and lock after 5 wrong attempts (re-issue to retry). Delivery: if
`SIGN_VERIFICATION_WEBHOOK_URL` is set, the code is POSTed there
(`{requestId, signerEmail, signerName, code, expiresAt}`) for your mailer
to send; otherwise the CLI returns it once and the operator must deliver
it to the signer's mailbox out-of-band. **The attribution value of the
verification is only as good as that delivery** — a code handed to the
signer over the same channel as the token proves nothing extra.

Successful redemption appends `request.signer_email_verified`.

### 4. Identity-assurance record

When the operator *has* verified identity out-of-band (a video call, an
in-person meeting, a provider IDV flow), record **that it happened and
how** — not the evidence itself:

```bash
sign signer record-identity --request-id req_abc --email alice@acme.com \
  --identity-assurance method:video-call,verifier:ops@acme.com,reference:TICKET-123
```

Methods: `in-person | video-call | document-check | provider-idv |
known-contact | other`, plus optional `verifier`, `reference`, `notes`
(each ≤ 500 chars). Appends `request.identity_assurance_recorded`.

**Store pointers, not evidence.** `reference` should be a ticket id or an
envelope id — never an ID-document number, scan, or date of birth. The
audit chain is exportable and long-lived; keep personal data out of it.

## Enforcement: the gates

Both gates are opt-in per request, set at creation:

```bash
sign request create ... --require-consent true --require-email-verification true
```

- `--require-consent true` — every signer must have accepted **both**
  statements before they can sign.
- `--require-email-verification true` — every signer must have a redeemed
  verification code before they can sign.
- `--auto-approve true` is rejected in combination with either gate
  (`INVALID_ARGS`) — the gates exist precisely so approval can't be
  skipped.

Enforcement lives in the shared signing service, so it holds on **every
surface**: the CLI `sign` command, the MCP `sign` tool, and
`POST /v1/sign` all refuse with `CONSENT_REQUIRED` /
`EMAIL_VERIFICATION_REQUIRED` until the gates are satisfied. Capture
itself (approve, verify-email, record-identity) is CLI-only, consistent
with the tool's core asymmetry: the agent drives the workflow, the human
performs the signing gesture.

`request show` exposes per-signer state under `consent`:

```json
"consent": {
  "consentRequired": true,
  "emailVerificationRequired": true,
  "signers": [
    { "signerEmail": "alice@acme.com",
      "intentToSignAcceptedAt": "2026-07-13T09:12:00.000Z",
      "esignDisclosureAcceptedAt": "2026-07-13T09:12:00.000Z",
      "emailVerifiedAt": "2026-07-13T09:11:31.000Z" }
  ]
}
```

## Audit events added by this layer

| Event | Payload highlights |
|---|---|
| `request.consent_captured` | statement version, SHA-256, full text, signer, timestamp |
| `request.esign_consent_captured` | same, for the electronic-records disclosure |
| `request.signer_verification_issued` | masked code hint, TTL, delivery channel — never the code |
| `request.signer_email_verified` | signer, hint, verification timestamp |
| `request.identity_assurance_recorded` | method, verifier, reference, notes |

`request.created` additionally records `requireConsent` /
`requireEmailVerification`, and `request.approved` records
`intentToSignCaptured` / `esignDisclosureAccepted` / `emailVerified`.

## What this changes legally — and what it doesn't

**Strengthens (US ESIGN/UETA):** explicit intent-to-sign and
consent-to-electronic-records evidence, in a tamper-evident log, plus
email-control attribution. These are exactly the elements disputes turn
on.

**Does not change (eIDAS):** the local provider still produces a Simple
Electronic Signature. Consent capture does not make the signature
"uniquely linked" to the signatory in the AdES sense — that requires
verified identity via a QTSP or a hosted provider's IDV. See
[`legal.md`](./legal.md).

## Design boundaries

- **No KYC data.** The tool never asks for or stores identity documents,
  ID numbers, or dates of birth. Unverifiable self-asserted identity data
  adds privacy liability (GDPR data-minimization, breach surface) without
  adding evidentiary weight. The identity-assurance record stores the
  *assertion* of an out-of-band check; the evidence stays in the system
  the `reference` points to.
- **Versioned statements are immutable.** Never rewrite a published
  statement version — add a `.v2`.
- **Plaintext verification codes exist only in the issue response.**
  Hash at rest, hint in the audit chain.
