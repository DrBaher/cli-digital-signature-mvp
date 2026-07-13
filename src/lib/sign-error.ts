import { redactString, collectKnownSecrets } from "./secret.js";

export type SignErrorCode =
  | "TOKEN_REQUIRED"
  | "TOKEN_INVALID"
  | "TOKEN_EXPIRED"
  | "TOKEN_SIGNER_MISMATCH"
  | "SIGNER_ALREADY_SIGNED"
  | "SIGNER_NOT_RECIPIENT"
  | "PRE_SIGN_HASH_MISMATCH"
  | "PRE_SIGN_TITLE_MISMATCH"
  | "PRE_SIGN_SIGNER_MISMATCH"
  | "PRE_SIGN_TITLE_BAD_REGEX"
  | "NON_LOCAL_PROVIDER"
  | "REQUEST_NOT_SENT"
  | "REQUEST_NOT_FOUND"
  | "MISSING_FLAG"
  | "UNKNOWN_COMMAND"
  | "INVALID_SPEC"
  | "POLICY_VIOLATION"
  | "UNKNOWN_TOOL"
  | "INVALID_ARGS"
  | "UNKNOWN_RESOURCE"
  | "RATE_LIMITED"
  | "SIGN_IMAGE_INCOMPLETE_POSITION"
  | "SIGN_VISIBLE_SIG_BOTH"
  | "NAME_SIGNATURE_MISSING_TEXT"
  | "AUTO_PLACE_REQUIRES_VISIBLE_SIG"
  | "AUTO_PLACE_NO_HIGH_CONFIDENCE"
  | "AUTO_PLACE_AMBIGUOUS"
  | "AUTO_PLACE_PAGE_NOT_FOUND"
  | "AUTO_PLACE_PAGE_AMBIGUOUS"
  | "AUTO_PLACE_INDEX_OUT_OF_RANGE"
  | "INVALID_AUTO_PLACE_VALUE"
  | "DOCX_CONVERSION_FAILED"
  | "INVALID_PROFILE"
  | "INVALID_PROFILE_NAME"
  | "PROFILE_NOT_FOUND"
  | "PROFILE_ALREADY_EXISTS"
  | "PROFILE_ENV_VAR_UNSET"
  | "STORAGE_UNWRITABLE"
  | "STRICT_PROVIDER_MISMATCH"
  | "CONSENT_REQUIRED"
  | "EMAIL_VERIFICATION_REQUIRED"
  | "VERIFICATION_CODE_INVALID"
  | "VERIFICATION_CODE_EXPIRED"
  | "FORBIDDEN"
  | "INTERNAL";

export type SignErrorEnvelope = {
  ok: false;
  error: {
    code: SignErrorCode;
    message: string;
    hint?: string;
    details?: Record<string, unknown>;
  };
};

export class SignCliError extends Error {
  readonly code: SignErrorCode;
  readonly hint?: string;
  readonly details?: Record<string, unknown>;
  constructor(input: {
    code: SignErrorCode;
    message: string;
    hint?: string;
    details?: Record<string, unknown>;
  }) {
    super(input.message);
    this.name = "SignCliError";
    this.code = input.code;
    this.hint = input.hint;
    this.details = input.details;
  }
}

export function formatCliError(error: unknown): SignErrorEnvelope {
  const secrets = collectKnownSecrets();
  if (error instanceof SignCliError) {
    return {
      ok: false,
      error: {
        code: error.code,
        message: redactString(error.message, secrets),
        ...(error.hint ? { hint: error.hint } : {}),
        ...(error.details ? { details: error.details } : {}),
      },
    };
  }
  const message = error instanceof Error ? error.message : String(error);
  return {
    ok: false,
    error: {
      code: "INTERNAL",
      message: redactString(message, secrets),
    },
  };
}
