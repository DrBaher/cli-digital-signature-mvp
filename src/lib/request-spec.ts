import { readFileSync } from "node:fs";
import path from "node:path";
import type { SignProvider } from "./providers.js";
import { resolveSignProvider } from "./providers.js";
import { SignCliError } from "./sign-error.js";
import type { PrefillInput, SignerInput } from "./util.js";
import type { SignatureField } from "./field-placement.js";

export type RequestSpec = {
  title: string;
  documentPath?: string;
  documentPaths?: string[];
  templateId?: string;
  signers: SignerInput[];
  fields?: SignatureField[];
  prefills?: PrefillInput[];
  tokenTtlMinutes?: number;
  provider?: SignProvider;
  autoApprove?: boolean;
  requireConsent?: boolean;
  requireEmailVerification?: boolean;
};

function specError(message: string, details?: Record<string, unknown>): SignCliError {
  return new SignCliError({
    code: "INVALID_SPEC",
    message,
    hint: "See the JSON schema at fixtures/request-spec.example.json.",
    details,
  });
}

function isObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function ensureString(value: unknown, fieldName: string): string {
  if (typeof value !== "string" || value.length === 0) {
    throw specError(`spec.${fieldName} must be a non-empty string.`);
  }
  return value;
}

function parseSignersSpec(input: unknown): SignerInput[] {
  if (!Array.isArray(input) || input.length === 0) {
    throw specError("spec.signers must be a non-empty array.");
  }
  return input.map((entry, idx) => {
    if (!isObject(entry)) throw specError(`spec.signers[${idx}] must be an object.`);
    const name = ensureString(entry.name, `signers[${idx}].name`);
    const email = ensureString(entry.email, `signers[${idx}].email`);
    const order = entry.order;
    if (!Number.isInteger(order) || (order as number) < 1) {
      throw specError(`spec.signers[${idx}].order must be a positive integer.`);
    }
    const role = entry.role === undefined ? undefined : ensureString(entry.role, `signers[${idx}].role`);
    return { name, email, order: order as number, ...(role ? { role } : {}) };
  });
}

function parsePrefillsSpec(input: unknown): PrefillInput[] {
  if (input === undefined) return [];
  if (!Array.isArray(input)) throw specError("spec.prefills must be an array.");
  return input.map((entry, idx) => {
    if (!isObject(entry)) throw specError(`spec.prefills[${idx}] must be an object.`);
    const name = ensureString(entry.name, `prefills[${idx}].name`);
    if (entry.value === undefined) {
      throw specError(`spec.prefills[${idx}].value is required.`);
    }
    const value = String(entry.value);
    const signerOrder = entry.signerOrder ?? entry.signer;
    const order = signerOrder === undefined
      ? undefined
      : (Number.isInteger(signerOrder) && (signerOrder as number) >= 1
        ? (signerOrder as number)
        : (() => { throw specError(`spec.prefills[${idx}].signerOrder must be a positive integer.`); })());
    return { name, value, ...(order !== undefined ? { signerOrder: order } : {}) };
  });
}

function parseFieldsSpec(input: unknown): SignatureField[] {
  if (input === undefined) return [];
  if (!Array.isArray(input)) throw specError("spec.fields must be an array.");
  return input.map((entry, idx) => {
    if (!isObject(entry)) throw specError(`spec.fields[${idx}] must be an object.`);
    const signerOrder = entry.signerOrder ?? entry.signer;
    const documentIndex = entry.documentIndex ?? entry.doc ?? 0;
    if (!Number.isInteger(signerOrder) || (signerOrder as number) < 1) {
      throw specError(`spec.fields[${idx}].signerOrder must be a positive integer.`);
    }
    if (!Number.isInteger(documentIndex) || (documentIndex as number) < 0) {
      throw specError(`spec.fields[${idx}].documentIndex must be a non-negative integer.`);
    }
    const type = ensureString(entry.type ?? "signature", `fields[${idx}].type`);
    const anchor = entry.anchor === undefined ? undefined : ensureString(entry.anchor, `fields[${idx}].anchor`);
    const page = entry.page;
    const x = entry.x;
    const y = entry.y;
    const out: SignatureField = {
      signerOrder: signerOrder as number,
      documentIndex: documentIndex as number,
      type: type as SignatureField["type"],
      required: entry.required === undefined ? true : Boolean(entry.required),
    };
    if (anchor !== undefined) out.anchor = anchor;
    if (typeof page === "number") out.page = page;
    if (typeof x === "number") out.x = x;
    if (typeof y === "number") out.y = y;
    return out;
  });
}

export function parseRequestSpec(raw: unknown): RequestSpec {
  if (!isObject(raw)) throw specError("Request spec must be a JSON object at the top level.");
  const title = ensureString(raw.title, "title");
  const documentPath = raw.documentPath === undefined ? undefined : ensureString(raw.documentPath, "documentPath");
  let documentPaths: string[] | undefined;
  if (raw.documentPaths !== undefined) {
    if (!Array.isArray(raw.documentPaths) || raw.documentPaths.some((p) => typeof p !== "string")) {
      throw specError("spec.documentPaths must be an array of strings.");
    }
    documentPaths = raw.documentPaths as string[];
  }
  const templateId = raw.templateId === undefined ? undefined : ensureString(raw.templateId, "templateId");
  if (!templateId && !documentPath && !(documentPaths && documentPaths.length > 0)) {
    throw specError("spec must include documentPath, documentPaths[], or templateId.");
  }
  if (templateId && (documentPath || (documentPaths && documentPaths.length > 0))) {
    throw specError("spec.templateId cannot be combined with documentPath/documentPaths.");
  }
  const signers = parseSignersSpec(raw.signers);
  const fields = parseFieldsSpec(raw.fields);
  const prefills = parsePrefillsSpec(raw.prefills);
  const tokenTtlMinutesRaw = raw.tokenTtlMinutes;
  let tokenTtlMinutes: number | undefined;
  if (tokenTtlMinutesRaw !== undefined) {
    if (typeof tokenTtlMinutesRaw !== "number" || !Number.isFinite(tokenTtlMinutesRaw) || tokenTtlMinutesRaw <= 0) {
      throw specError("spec.tokenTtlMinutes must be a positive number.");
    }
    tokenTtlMinutes = tokenTtlMinutesRaw;
  }
  const provider = raw.provider === undefined ? undefined : resolveSignProvider(ensureString(raw.provider, "provider"));
  const autoApprove = raw.autoApprove === undefined ? undefined : Boolean(raw.autoApprove);
  const requireConsent = raw.requireConsent === undefined ? undefined : Boolean(raw.requireConsent);
  const requireEmailVerification =
    raw.requireEmailVerification === undefined ? undefined : Boolean(raw.requireEmailVerification);

  return {
    title,
    ...(documentPath ? { documentPath } : {}),
    ...(documentPaths ? { documentPaths } : {}),
    ...(templateId ? { templateId } : {}),
    signers,
    ...(fields.length > 0 ? { fields } : {}),
    ...(prefills.length > 0 ? { prefills } : {}),
    ...(tokenTtlMinutes !== undefined ? { tokenTtlMinutes } : {}),
    ...(provider !== undefined ? { provider } : {}),
    ...(autoApprove !== undefined ? { autoApprove } : {}),
    ...(requireConsent !== undefined ? { requireConsent } : {}),
    ...(requireEmailVerification !== undefined ? { requireEmailVerification } : {}),
  };
}

export function applyRequestSpecTemplate(
  text: string,
  params: Record<string, string>,
): string {
  return text.replace(/\{\{\s*([a-zA-Z0-9_.-]+)\s*\}\}/gu, (_match, key: string) => {
    const trimmed = key.trim();
    if (!(trimmed in params)) {
      throw new SignCliError({
        code: "INVALID_SPEC",
        message: `Spec template references unknown param "${trimmed}". Pass --param ${trimmed}=<value>.`,
        details: { missingParam: trimmed, providedParams: Object.keys(params) },
      });
    }
    return params[trimmed];
  });
}

export function loadRequestSpec(filePath: string, params: Record<string, string> = {}): RequestSpec {
  let text: string;
  try {
    text = readFileSync(filePath, "utf8");
  } catch (error) {
    throw new SignCliError({
      code: "INVALID_SPEC",
      message: `Failed to load request spec from ${filePath}: ${(error as Error).message}`,
      details: { filePath: path.resolve(filePath) },
    });
  }
  const substituted = Object.keys(params).length > 0 ? applyRequestSpecTemplate(text, params) : text;
  let raw: unknown;
  try {
    raw = JSON.parse(substituted);
  } catch (error) {
    throw new SignCliError({
      code: "INVALID_SPEC",
      message: `Failed to parse request spec from ${filePath}: ${(error as Error).message}`,
      details: { filePath: path.resolve(filePath) },
    });
  }
  return parseRequestSpec(raw);
}
