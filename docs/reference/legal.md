# Legal posture

When is a `sign-cli` signature actually enforceable? This doc lays out the
honest answer — by jurisdiction, by use case, and with the evidentiary
gaps called out so you don't discover them in a deposition.

> **Not legal advice.** This is engineering documentation written by the
> people who built the tool. For anything material, talk to a lawyer in
> the relevant jurisdiction. "Will it hold up in court" depends on the
> dispute, the judge, what the counterparty argues, and a hundred other
> things this document can't predict.

## What `sign-cli` actually produces

Independent of legal framework, here's the cryptographic and procedural
reality you can point to:

- **PAdES-style envelope** (ETSI EN 319 142 structure) — every PDF
  reader's signature panel recognises it as a digital signature.
- **Self-issued X.509 certificates**, generated locally per signer. No
  Certificate Authority. No third-party identity verification.
- **Hash-chained audit log** — `audit_events.hash_self = sha256(...)`,
  enforced by SQLite `BEFORE UPDATE/DELETE` triggers. See
  [`compliance-posture.md`](./compliance-posture.md) for the threat
  model.
- **Per-signer approval tokens** — TTL-bounded, single-use, scoped to
  one signer's email. Designed for a human to gate each signature.
- **Recorded intent-to-sign + electronic-records consent** (optional,
  `--require-consent`) — versioned canonical statements the signer
  accepts at approval, captured in the audit chain with the statement's
  SHA-256 and timestamp. See
  [`consent-and-identity.md`](./consent-and-identity.md).
- **Signer email verification** (optional,
  `--require-email-verification`) — a hashed, TTL-bounded, single-use
  code proves the signer controls the mailbox before signing is allowed.
- **Identity-assurance records** — `sign signer record-identity` logs
  *how* identity was checked out-of-band (method + pointer to evidence),
  in the audit chain.
- **Optional RFC 3161 timestamping** via `sign audit timestamp` /
  `sign audit anchor`. Anchors the chain head against a public TSA.
- **Re-verifiable receipt bundles** — `sign audit export` writes a
  self-contained `audit.json + signed.pdf + audit.tsr + manifest.json`
  that an auditor can verify offline a year later.

What's missing, deliberately, from the local provider:

- **No identity verification.** Anyone can run `sign request create
  --signer name:Alice,email:alice@example.com`. Email verification
  proves control of the mailbox, and the identity-assurance record
  captures your out-of-band checks — but neither verifies that the
  person is legally Alice. That requires a hosted provider's IDV or a
  QTSP, and the CLI deliberately collects no identity documents itself
  (see [`consent-and-identity.md`](./consent-and-identity.md)).
- **No qualified certificate** from a Qualified Trust Service Provider
  (QTSP). The cert is self-signed by `Sign CLI Local Provider`.
- **No long-term validation (LTV)** with CRL/OCSP staples.

If you need any of those, route signing through one of the integrated
providers (Dropbox Sign, DocuSign, SignWell) — see
[Provider-integrated mode](#provider-integrated-mode) below.

## United States: ESIGN Act and UETA

The bar is low and the tool clears it for most uses.

> *"An electronic signature [is] an electronic sound, symbol, or process
> attached to or logically associated with a record and executed or
> adopted by a person with the intent to sign the record."* — ESIGN Act,
> 15 U.S.C. § 7001

`sign-cli` produces signatures that meet this definition. The audit
chain + per-signer token + PAdES envelope gives you stronger evidence
than most click-to-sign products.

### Use it for

- Internal acknowledgments — code of conduct, security policy, training
- B2B commercial agreements at low-to-mid value (SaaS, freelance,
  reseller, referral, contractor SOWs)
- Mutual NDAs between US companies
- Receipts and attestations ("I read this," "I approve this expense")
- Anything where both parties agreed in advance on the signing method

### Don't use it for

US federal and state law carve out documents that require notarization,
wet signatures, or specific approved e-signing standards:

- Wills, codicils, trust amendments
- Real estate deeds and mortgages (most states require RON or notarized
  e-sign)
- Family law — divorce, custody, adoption
- Court filings — every court has its own e-filing portal
- Securities filings and equity issuance for public companies
- Tax filings, regulated insurance, government submissions

For high-value commercial agreements (~$100K+) with sophisticated
counterparties, use [provider-integrated mode](#provider-integrated-mode)
even though the local mode is technically valid. Their lawyers will ask
"who issued the cert?" and "self-CA" isn't the answer that closes the
deal.

## European Union: eIDAS Regulation

eIDAS recognises three tiers of electronic signature. Knowing which
tier you're producing matters because the evidentiary weight in court
is very different.

| Tier | Acronym | What it needs | `sign-cli` produces this? |
|---|---|---|---|
| Simple Electronic Signature | SES | "Data in electronic form attached to other data … which the signatory uses to sign." Almost anything counts. | ✅ Yes |
| Advanced Electronic Signature | AdES | Uniquely linked to signer; capable of identifying signer; created under signer's sole control; linked to the document such that tamper is detectable. | ❌ No — format matches, but "uniquely linked" requires identity verification a self-issued cert can't provide |
| Qualified Electronic Signature | QES | AdES + qualified certificate from a Qualified Trust Service Provider + qualified signature creation device. Legal equivalent of a handwritten signature. | ❌ No — and won't, by design |

### The lever that helps you: Article 25(1)

> *"An electronic signature shall not be denied legal effect and
> admissibility as evidence in legal proceedings solely on the grounds
> that it is in electronic form or that it does not meet the
> requirements for qualified electronic signatures."*

Translation: an SES is **admissible**. A court can't reject it just for
being electronic. They can challenge the *evidentiary weight*, not the
*form*. That's the lever the audit chain leans on.

### Where you sit, practically

A `sign-cli` signature in the EU is an SES. It is:

- ✅ Admissible as evidence in every EU member state.
- ✅ Sufficient for most B2B contracts where both parties agreed on
  the method.
- ❌ Not equivalent to a wet signature (only QES is).
- ❌ Not presumed valid — the burden of proving the signer signed is
  on the party asserting the signature. The audit chain is how you
  meet that burden.

### Member-state nuances

Member states layer their own contract-law conservatism on top:

| Country | Disposition toward SES for B2B contracts |
|---|---|
| Germany | Permissive. *Textform* (BGB §126b) accepts basic e-sig for most contracts including NDAs. |
| Netherlands, Sweden, Denmark | Pragmatic — basic e-sig accepted broadly. |
| France | More formalist. Some courts have demanded AdES for evidentiary weight in commercial disputes. |
| Italy | Conservative. *Firma Elettronica Avanzata* (AdES) is the de facto minimum for serious B2B agreements. |
| Spain, Portugal | Mixed — admissible, but evidentiary weight varies by court. |

Public-sector contracts, regulated finance, healthcare, and any document
the law requires to be in "qualified form" need AdES or QES regardless
of jurisdiction. Don't roll your own there.

## Practical traffic light

Two questions to ask before each use:

1. **"If the counterparty denied signing, would my audit chain alone
   convince a judge?"**
   - Token sent to verified business email ✓
   - Counterparty opened it and approved it ✓
   - Human at signer's org executed the sign gesture ✓
   - PDF byte-range digest matches the embedded signature ✓
   - For US ESIGN disputes that's usually enough; for EU it depends.

2. **"How much do I lose if this contract is voided?"**

| Scenario | Verdict |
|---|---|
| Internal sign-offs, employee acknowledgments | 🟢 Use `sign-cli` |
| Mutual B2B NDA, US-to-US, low-to-mid value | 🟢 Use `sign-cli` |
| Mutual B2B NDA, intra-EU, with method-consent clause | 🟢 Use `sign-cli` (see [EU NDA guide](#eu-ndas-deep-dive) below) |
| B2B contract <$10K, US counterparty | 🟢 Use `sign-cli` |
| B2B contract $10K–$100K | 🟡 Use [provider-integrated mode](#provider-integrated-mode) |
| B2B contract $100K+, sophisticated counterparty | 🟡 Use provider-integrated mode; their lawyers will ask |
| Anything cross-border into France, Italy, Belgium with serious money | 🟡 Provider-integrated, or step up to AdES via a qualified provider |
| Wills, real estate, family law, court filings | 🔴 Don't use `sign-cli`; jurisdiction-specific formalities apply |
| Public-sector EU, regulated finance, healthcare | 🔴 Needs AdES or QES; use a qualified provider |
| Documents you'd be embarrassed about in court | 🔴 Whatever you'd use if you couldn't use this CLI |

## EU NDAs deep-dive

NDAs are the use case most teams ask about. They're worth a focused
section because the legal terrain is unusually friendly:

- Most EU member states have **no form requirements** for NDAs.
- B2B contracts have wide freedom-of-form.
- Article 25(1) gives you admissibility.
- The dispute usually isn't *"did they sign?"* — it's *"did they
  breach?"* and *"what damages?"* The signature itself is rarely the
  contested point.

### What makes an NDA signed via `sign-cli` enforceable

| Evidence the court considers | What the CLI provides | Weight |
|---|---|---|
| Token sent to verified business email | ✅ per-signer, TTL-bounded | Strong |
| Single-use approval gesture | ✅ approval token + sign event | Strong |
| Tamper-evident document | ✅ PAdES byte-range + audit chain | Strong |
| Timestamped event log | ✅ hash-chained, optional RFC 3161 | Strong |
| Third-party identity verification | ❌ self-issued certs | **Missing — this is the weakness** |

### The method-consent clause

If both parties contractually agree on the signing method, challenging
the signature later means challenging their own consent — a much harder
argument. Bake this clause into the NDA itself:

> *"The Parties agree that this Agreement may be executed by electronic
> signature, and that signatures recorded electronically through
> `sign-cli` (or substantially equivalent system) — together with the
> associated audit chain — constitute valid and binding signatures
> equivalent to wet-ink signatures for the purposes of this Agreement."*

Combined with the audit chain, this gives you a defensible EU NDA for
typical B2B use without escalating to AdES.

### EU NDA traffic light

| Scenario | Verdict |
|---|---|
| Mutual NDA between two known B2B counterparties + method-consent clause | 🟢 Use `sign-cli` |
| NDA for pre-acquisition due diligence under €100K transaction | 🟢 Use `sign-cli` with method-consent clause |
| NDA with a new counterparty you've never corresponded with | 🟡 Add an out-of-band identity check (video call, business-registry lookup) and keep the evidence alongside the audit bundle |
| NDA forming the basis of a serious M&A or licensing deal (€1M+) | 🟡 Use [provider-integrated mode](#provider-integrated-mode); DocuSign and Dropbox Sign have QTSP partnerships in some EU jurisdictions |
| NDA with a French government entity or anything public-sector EU | 🔴 Needs AdES or QES |
| NDA where the disclosed info is genuinely catastrophic if leaked (pre-filing patents, irreplaceable trade secrets) | 🔴 Get a lawyer to advise on QES + jurisdiction-specific formalities |

## Provider-integrated mode

For anything where the local-provider posture isn't enough, route the
signing through one of the existing provider integrations. The audit
chain, per-signer tokens, and receipt bundles still apply on top — you
only swap out *who issues the cert*:

```bash
sign request create --provider docusign --signer name:Alice,email:alice@example.com,order:1 ...
sign request create --provider dropbox  --signer name:Alice,email:alice@example.com,order:1 ...
sign request create --provider signwell --signer name:Alice,email:alice@example.com,order:1 ...
```

This produces a signature that — depending on the provider's plan and
jurisdiction — can reach AdES or QES. Pair it with `sign audit
timestamp` and `sign audit export` and you still get the verifiable
receipt bundle property the local provider gives you.

See [`docs/architecture.md`](./architecture.md) for how requests flow
through the provider layer and [`docs/comparison.md`](./comparison.md)
for which provider fits which use case.

## The thing that actually makes signatures weak in court

It isn't the self-issued cert — most judges don't care about the
underlying cryptography. It's whether you can prove **the right human
authorized the signature**.

Strong evidentiary posture:

- Approval tokens emailed to verified business addresses
- One human gesture per signer (don't auto-approve and auto-sign with
  no review)
- `--require-consent true` on the request, so every signer's
  intent-to-sign + electronic-records consent is captured in the audit
  chain (see [`consent-and-identity.md`](./consent-and-identity.md))
- `--require-email-verification true`, so signing is gated on proof of
  mailbox control — with the code delivered to the signer's email, not
  alongside the token
- `sign signer record-identity` whenever you actually checked who you
  were dealing with
- `sign audit timestamp` after every meaningful event
- Receipt bundles exported and retained per `docs/recipes/`

Weak posture:

- Auto-approve every request and have a script sign without human
  review (the counterparty's "I never authorized this" argument has
  legs)
- Shared signing credentials
- No timestamping
- No retention of the audit chain

The CLI's architecture is designed to make the strong posture the easy
one (`approve` requires a separate human action; tokens are emitted to
the human, not the agent). Use it.

## What we'll never claim

To keep the README honest, we'll never describe `sign-cli` as:

- "Legally binding" without a jurisdiction qualifier
- "eIDAS-compliant" or "AdES-compliant" — the format is, the identity
  layer isn't
- "Court-ready" without "*for jurisdictions that recognize Simple
  Electronic Signatures and where the counterparty has agreed to the
  method*"
- A replacement for wet signatures in regulated contexts

What we will claim, and you can claim downstream:

- Produces a real PAdES-style signed PDF that any PDF inspector validates
- Tamper-evident audit chain with optional RFC 3161 timestamping
- Legally valid under US ESIGN/UETA for most business agreements
- Admissible as a Simple Electronic Signature under eIDAS Article 25(1)
- A defensible signing record for typical B2B NDAs in EU when paired
  with a method-consent clause

That's the boundary. If you find yourself reaching past it in
documentation or marketing, escalate to provider-integrated mode and
update the wording instead.
