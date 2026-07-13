import crypto from "node:crypto";

export type SignerInput = {
  name: string;
  email: string;
  order: number;
  role?: string;
};

export type PrefillInput = {
  name: string;
  value: string;
  signerOrder?: number;
};

export function nowIso(date = new Date()): string {
  return date.toISOString();
}

export function sha256(input: string | Buffer): string {
  return crypto.createHash("sha256").update(input).digest("hex");
}

export function hmacSha256(secret: string, input: string): string {
  return crypto.createHmac("sha256", secret).update(input).digest("hex");
}

export function createId(prefix: string): string {
  return `${prefix}_${crypto.randomUUID().replaceAll("-", "")}`;
}

export function createToken(): string {
  return crypto.randomBytes(24).toString("hex");
}

export function tokenHint(token: string): string {
  return `${token.slice(0, 6)}...${token.slice(-4)}`;
}

/** 6-digit numeric code for signer email verification — short enough to type
 *  from a phone, brute-force-bounded by the attempts counter on the row. */
export function createVerificationCode(): string {
  return String(crypto.randomInt(0, 1_000_000)).padStart(6, "0");
}

export function verificationCodeHint(code: string): string {
  return `${code.slice(0, 1)}****${code.slice(-1)}`;
}

export function stableStringify(value: unknown): string {
  if (Array.isArray(value)) {
    return `[${value.map((item) => stableStringify(item)).join(",")}]`;
  }
  if (value && typeof value === "object") {
    const entries = Object.entries(value as Record<string, unknown>)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([key, nested]) => `${JSON.stringify(key)}:${stableStringify(nested)}`);
    return `{${entries.join(",")}}`;
  }
  return JSON.stringify(value);
}

export function parseSignerSpec(raw: string): SignerInput {
  const pairs = raw.split(",").map((segment) => segment.trim()).filter(Boolean);
  const record: Record<string, string> = {};

  for (const pair of pairs) {
    const [key, ...rest] = pair.split(":");
    if (!key || rest.length === 0) {
      throw new Error(`Invalid signer segment: "${pair}"`);
    }
    record[key.trim()] = rest.join(":").trim();
  }

  if (!record.name || !record.email || !record.order) {
    throw new Error(`Signer must include name, email, and order: "${raw}"`);
  }

  const order = Number(record.order);
  if (!Number.isInteger(order) || order < 1) {
    throw new Error(`Signer order must be a positive integer: "${raw}"`);
  }

  return {
    name: record.name,
    email: record.email,
    order,
    ...(record.role ? { role: record.role } : {}),
  };
}

export function parsePrefillSpec(raw: string): PrefillInput {
  const segments: string[] = [];
  let current = "";
  let inQuotes = false;
  for (let i = 0; i < raw.length; i += 1) {
    const ch = raw[i];
    if (ch === '"') {
      inQuotes = !inQuotes;
      continue;
    }
    if (ch === "," && !inQuotes) {
      segments.push(current);
      current = "";
      continue;
    }
    current += ch;
  }
  if (current.length > 0) segments.push(current);

  const record: Record<string, string> = {};
  for (const segment of segments.map((s) => s.trim()).filter(Boolean)) {
    const colon = segment.indexOf(":");
    if (colon === -1) throw new Error(`Invalid prefill segment: "${segment}"`);
    record[segment.slice(0, colon).trim()] = segment.slice(colon + 1).trim();
  }
  if (!record.name) {
    throw new Error(`Prefill must include name:<key>: "${raw}"`);
  }
  if (record.value === undefined) {
    throw new Error(`Prefill must include value:<v>: "${raw}"`);
  }
  const signerOrder = record.signer ? Number(record.signer) : undefined;
  if (signerOrder !== undefined && (!Number.isInteger(signerOrder) || signerOrder < 1)) {
    throw new Error(`Prefill signer must be a positive integer matching --signer order: "${raw}"`);
  }
  return {
    name: record.name,
    value: record.value,
    ...(signerOrder !== undefined ? { signerOrder } : {}),
  };
}

export function parseBooleanFlag(value: string | undefined, fallback: boolean): boolean {
  if (value === undefined) {
    return fallback;
  }
  return ["1", "true", "yes", "on"].includes(value.toLowerCase());
}
