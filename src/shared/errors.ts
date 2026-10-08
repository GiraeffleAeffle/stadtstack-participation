/** An error with a stable machine-readable code and the HTTP status it maps to. */
export class CodedError extends Error {
  readonly code: string;
  readonly status: number;

  constructor(code: string, status = 400) {
    super(code);
    this.name = "CodedError";
    this.code = code;
    this.status = status;
  }
}

export function fail(code: string, status = 400): never {
  throw new CodedError(code, status);
}

export function isCodedError(value: unknown): value is CodedError {
  return value instanceof CodedError;
}
