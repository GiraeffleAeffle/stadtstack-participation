import { createHash, createHmac, createPublicKey, randomBytes } from "node:crypto";
import type { DatabaseSync } from "node:sqlite";
import { canonical, exact, isSafeNonNegativeInteger, object, snapshot } from "../shared/canonical.ts";
import { fail, isCodedError } from "../shared/errors.ts";
import { isHex64, isHttpsOrigin } from "../shared/ids.ts";
import type { EligibilityAdapter, EligibilityBasis, EligibilityCheckInput, EligibilityDecision, EligibilityRecheckInput } from "../shared/seams.ts";

export type EudiPidConfig = Readonly<{
  kind: "eudi_pid_v1"; verifierBaseUrl: string; acceptedVcts: readonly string[];
  acceptedAddresses: readonly Readonly<{ postalCode: string; locality: string }>[];
  transactionTtlSeconds: number; validitySeconds: number;
}>;
export type EudiPidRuntime = Readonly<{
  db: DatabaseSync; municipalityId: string; policyVersion: string; basis: EligibilityBasis;
  uniquenessKey: Uint8Array; fetch?: typeof fetch; intendedUseId?: string; timeoutMs?: number;
}>;
export type EudiRequest = Readonly<{ transactionId: string; walletUrl: string; expiresAt: number }>;
export type EudiRequestState = Readonly<{ state: "pending" | "ready" | "expired" }> | Readonly<{ state: "failed"; reason: string }>;
type TransactionRow = { subject_pubkey: string; nonce: string | null; client_id: string | null; started_at: number; expires_at: number; state: string; reason: string | null; evidence_ref: string | null; effective_at: number | null; valid_until: number | null; consumed: number };
type DecisionRow = { evidence_ref: string; effective_at: number; valid_until: number };

function normalized(value: string): string {
  return value.normalize("NFC").trim().toLocaleLowerCase("de-DE");
}

export function validateEudiPidConfig(value: unknown, basis: EligibilityBasis): EudiPidConfig {
  const config = exact(snapshot(value), ["kind", "verifierBaseUrl", "acceptedVcts", "acceptedAddresses", "transactionTtlSeconds", "validitySeconds"], "adapter_config_invalid");
  if (config.kind !== "eudi_pid_v1" || !isHttpsOrigin(config.verifierBaseUrl) ||
      !Array.isArray(config.acceptedVcts) || !config.acceptedVcts.length || config.acceptedVcts.length > 16 ||
      config.acceptedVcts.some((v) => typeof v !== "string" || !v.trim() || v !== v.trim() || v.length > 2048) ||
      new Set(config.acceptedVcts).size !== config.acceptedVcts.length ||
      !Array.isArray(config.acceptedAddresses) || !config.acceptedAddresses.length || config.acceptedAddresses.length > 1000 ||
      !isSafeNonNegativeInteger(config.transactionTtlSeconds) || config.transactionTtlSeconds < 30 || config.transactionTtlSeconds > 900 ||
      !isSafeNonNegativeInteger(config.validitySeconds) || config.validitySeconds < 1 || config.validitySeconds > 31_536_000) fail("adapter_config_invalid");
  const pairs = new Set<string>();
  for (const entry of config.acceptedAddresses) {
    const address = exact(entry, ["postalCode", "locality"], "adapter_config_invalid");
    if (typeof address.postalCode !== "string" || typeof address.locality !== "string" ||
        !normalized(address.postalCode) || !normalized(address.locality) || address.postalCode.length > 32 || address.locality.length > 200) fail("adapter_config_invalid");
    const pair = canonical([normalized(address.postalCode), normalized(address.locality)]);
    if (pairs.has(pair)) fail("adapter_config_invalid");
    pairs.add(pair);
  }
  // A PID does not prove secondary residence, citizenship restrictions or registry locality IDs.
  if (basis.residence !== "main_residence" || basis.nationality !== "any" || basis.localityScope !== null) fail("eudi_basis_unsupported");
  return config as EudiPidConfig;
}

/** Only decisions and transaction bindings are persisted, never credentials or disclosures. */
export function migrate(db: DatabaseSync): void {
  db.exec(`CREATE TABLE IF NOT EXISTS eudi_transactions (
    municipality_id TEXT NOT NULL, policy_version TEXT NOT NULL, transaction_id TEXT NOT NULL,
    subject_pubkey TEXT NOT NULL, nonce TEXT, client_id TEXT, started_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
    state TEXT NOT NULL, reason TEXT, evidence_ref TEXT, effective_at INTEGER, valid_until INTEGER,
    consumed INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (municipality_id, policy_version, transaction_id)
  );
  CREATE TABLE IF NOT EXISTS eudi_decisions (
    municipality_id TEXT NOT NULL, policy_version TEXT NOT NULL, subject_pubkey TEXT NOT NULL,
    evidence_ref TEXT NOT NULL, effective_at INTEGER NOT NULL, valid_until INTEGER NOT NULL,
    PRIMARY KEY (municipality_id, policy_version, subject_pubkey, evidence_ref)
  );`);
}

function decodeJson(part: string): unknown {
  if (!/^[A-Za-z0-9_-]+$/u.test(part)) fail("presentation_invalid");
  try { return snapshot(JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(Buffer.from(part, "base64url"))), "presentation_invalid"); }
  catch { fail("presentation_invalid"); }
}


function ageOn(birthdate: string, now: number): number {
  if (!/^\d{4}-\d{2}-\d{2}$/u.test(birthdate)) fail("age_claim_invalid");
  const birth = new Date(`${birthdate}T00:00:00Z`);
  const today = new Date(now * 1000);
  if (!Number.isFinite(birth.getTime()) || birth.toISOString().slice(0, 10) !== birthdate || birth > today) fail("age_claim_invalid");
  const before = today.getUTCMonth() < birth.getUTCMonth() || (today.getUTCMonth() === birth.getUTCMonth() && today.getUTCDate() < birth.getUTCDate());
  return today.getUTCFullYear() - birth.getUTCFullYear() - Number(before);
}

/** Resolve only disclosures actually referenced by the issuer-signed SD digests. */
function disclosedClaims(parts: readonly string[], payload: Record<string, unknown>): Record<string, unknown> {
  if (payload._sd_alg !== undefined && payload._sd_alg !== "sha-256") fail("presentation_invalid");
  const disclosures = new Map<string, readonly unknown[]>();
  for (const part of parts) {
    const disclosure = decodeJson(part);
    if (!Array.isArray(disclosure) || disclosure.length !== 3 || typeof disclosure[0] !== "string" || typeof disclosure[1] !== "string") fail("presentation_invalid");
    const hash = createHash("sha256").update(part).digest("base64url");
    if (disclosures.has(hash)) fail("presentation_invalid");
    disclosures.set(hash, disclosure);
  }
  const used = new Set<string>();
  function resolve(value: unknown, depth: number): unknown {
    if (depth > 16) fail("presentation_invalid");
    if (Array.isArray(value)) return value.map((entry) => resolve(entry, depth + 1));
    if (value === null || typeof value !== "object") return value;
    const source = object(value, "presentation_invalid");
    const result: Record<string, unknown> = Object.create(null) as Record<string, unknown>;
    for (const [key, entry] of Object.entries(source)) if (key !== "_sd" && key !== "_sd_alg") result[key] = resolve(entry, depth + 1);
    if (source._sd !== undefined) {
      if (!Array.isArray(source._sd) || source._sd.some((hash) => typeof hash !== "string")) fail("presentation_invalid");
      for (const hash of source._sd as string[]) {
        const disclosure = disclosures.get(hash);
        if (!disclosure) continue;
        const name = disclosure[1] as string;
        if (used.has(hash) || name === "_sd" || name === "_sd_alg" || Object.hasOwn(result, name)) fail("presentation_invalid");
        used.add(hash);
        result[name] = resolve(disclosure[2], depth + 1);
      }
    }
    return result;
  }
  return object(resolve(payload, 0), "presentation_invalid");
}

export class EudiPidAdapter implements EligibilityAdapter {
  readonly kind = "eudi_pid_v1";
  readonly config: EudiPidConfig;
  private readonly runtime: EudiPidRuntime;
  private readonly fetcher: typeof fetch;
  private readonly timeoutMs: number;

  constructor(config: EudiPidConfig, runtime: EudiPidRuntime) {
    this.config = validateEudiPidConfig(config, runtime.basis);
    if (runtime.uniquenessKey.byteLength < 32) fail("eudi_uniqueness_key_invalid", 500);
    this.runtime = { ...runtime, uniquenessKey: Uint8Array.from(runtime.uniquenessKey) };
    this.fetcher = runtime.fetch ?? fetch;
    this.timeoutMs = runtime.timeoutMs ?? 15_000;
    if (!Number.isSafeInteger(this.timeoutMs) || this.timeoutMs < 1 || !(runtime.intendedUseId ?? "TEST-01").trim()) fail("eudi_runtime_invalid", 500);
    migrate(runtime.db);
  }

  async start(subjectPubkey: string, now: number, signal: AbortSignal): Promise<EudiRequest> {
    if (!isHex64(subjectPubkey) || !isSafeNonNegativeInteger(now)) fail("eudi_request_invalid");
    const nonce = randomBytes(32).toString("base64url");
    const claims = [{ path: ["family_name"] }, { path: ["given_name"] }, { path: ["birthdate"] },
      { path: ["address", "postal_code"] }, { path: ["address", "locality"] }];
    const { response, body } = await this.call("/ui/presentations", signal, {
      method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({
        dcql_query: { credentials: [{ id: "pid", format: "dc+sd-jwt", meta: { vct_values: this.config.acceptedVcts }, claims }] },
        nonce, jar_mode: "by_reference", request_uri_method: "get", profile: "openid4vp", intended_use_id: this.runtime.intendedUseId ?? "TEST-01",
      }),
    });
    if (!response.ok || typeof body.transaction_id !== "string" || !/^[A-Za-z0-9_-]{1,256}$/u.test(body.transaction_id) ||
        typeof body.client_id !== "string" || !body.client_id || body.client_id.length > 2048 || typeof body.request_uri !== "string") fail("verifier_unavailable", 502);
    let uri: URL;
    try { uri = new URL(body.request_uri); } catch { fail("verifier_response_invalid", 502); }
    if (uri.protocol !== "https:" || uri.username || uri.password) fail("verifier_response_invalid", 502);
    const expiresAt = now + this.config.transactionTtlSeconds;
    const params = new URLSearchParams({ client_id: body.client_id, request_uri: body.request_uri, request_uri_method: "get" });
    this.runtime.db.prepare("INSERT INTO eudi_transactions (municipality_id,policy_version,transaction_id,subject_pubkey,nonce,client_id,started_at,expires_at,state) VALUES (?,?,?,?,?,?,?,?, 'pending')")
      .run(this.runtime.municipalityId, this.runtime.policyVersion, body.transaction_id, subjectPubkey, nonce, body.client_id, now, expiresAt);
    return { transactionId: body.transaction_id, walletUrl: `eudi-openid4vp://?${params}`, expiresAt };
  }

  async poll(transactionId: string, subjectPubkey: string, now: number, signal: AbortSignal): Promise<EudiRequestState> {
    if (!isSafeNonNegativeInteger(now)) fail("eudi_request_invalid");
    const row = this.transaction(transactionId, subjectPubkey);
    if (row.state === "expired" || now >= row.expires_at || now < row.started_at) return this.expire(transactionId);
    if (row.state === "ready") return { state: "ready" };
    if (row.state === "failed") return { state: "failed", reason: row.reason! };
    const started = performance.now();
    try {
      const { response, body } = await this.call(`/ui/presentations/${encodeURIComponent(transactionId)}`, signal);
      const evaluatedAt = now + Math.floor((performance.now() - started) / 1000);
      if (evaluatedAt >= row.expires_at) return this.expire(transactionId);
      if (response.status === 400 && (body.error === undefined || body.error === "PresentationNotSubmitted")) return { state: "pending" };
      if (response.status === 404) return this.reject(transactionId, "verifier_transaction_expired");
      if (!response.ok) return this.reject(transactionId, response.status === 400 ? "verifier_rejected" : "verifier_unavailable");
      if (body.transaction_id !== undefined && body.transaction_id !== transactionId) fail("transaction_mismatch");
      if (body.error !== undefined) fail("verifier_rejected");
      const tokens = object(body.vp_token, "presentation_missing");
      if (Object.keys(tokens).length !== 1 || !Object.hasOwn(tokens, "pid")) fail("presentation_invalid");
      const token = tokens.pid;
      const presentation = Array.isArray(token) && token.length === 1 ? token[0] : token;
      if (typeof presentation !== "string") fail("presentation_missing");
      const decision = this.evaluate(presentation, row, evaluatedAt);
      this.runtime.db.prepare("UPDATE eudi_transactions SET state='ready',nonce=NULL,client_id=NULL,evidence_ref=?,effective_at=?,valid_until=? WHERE municipality_id=? AND policy_version=? AND transaction_id=? AND state='pending'")
        .run(decision.evidenceRef, decision.effectiveAt, decision.validUntil, this.runtime.municipalityId, this.runtime.policyVersion, transactionId);
      // A concurrent terminal response wins; never overwrite it with a late presentation.
      const stored = this.transaction(transactionId, subjectPubkey);
      return stored.state === "ready" ? { state: "ready" } : stored.state === "expired" ? { state: "expired" } : { state: "failed", reason: stored.reason! };
    } catch (error) {
      return this.reject(transactionId, isCodedError(error) ? error.code : "verifier_unavailable");
    }
  }

  async check(input: EligibilityCheckInput): Promise<EligibilityDecision> {
    if (!isSafeNonNegativeInteger(input.now)) return { state: "inactive", reason: "eudi_evidence_invalid" };
    if (input.municipalityId !== this.runtime.municipalityId || input.policyVersion !== this.runtime.policyVersion) return { state: "inactive", reason: "policy_mismatch" };
    let transactionId: unknown;
    try { transactionId = exact(snapshot(input.evidence), ["transactionId"], "eudi_evidence_invalid").transactionId; }
    catch { return { state: "inactive", reason: "eudi_evidence_invalid" }; }
    if (typeof transactionId !== "string") return { state: "inactive", reason: "eudi_evidence_invalid" };
    let row: TransactionRow;
    try { row = this.transaction(transactionId, input.subjectPubkey); }
    catch { return { state: "inactive", reason: "eudi_transaction_not_found" }; }
    if (row.state === "expired" || input.now >= row.expires_at || input.now < row.started_at) {
      this.expire(transactionId);
      return { state: "inactive", reason: "transaction_expired" };
    }
    if (row.consumed) return { state: "inactive", reason: "transaction_used" };
    if (row.state !== "ready") return { state: "inactive", reason: row.reason ?? "presentation_pending" };
    if (row.valid_until! <= input.now || row.effective_at! > input.now) return { state: "inactive", reason: "evidence_expired" };
    const db = this.runtime.db;
    db.exec("BEGIN IMMEDIATE");
    try {
      const consumed = db.prepare("UPDATE eudi_transactions SET consumed=1 WHERE municipality_id=? AND policy_version=? AND transaction_id=? AND consumed=0").run(input.municipalityId, input.policyVersion, transactionId);
      if (consumed.changes !== 1) { db.exec("ROLLBACK"); return { state: "inactive", reason: "transaction_used" }; }
      db.prepare("INSERT INTO eudi_decisions VALUES (?,?,?,?,?,?) ON CONFLICT (municipality_id,policy_version,subject_pubkey,evidence_ref) DO UPDATE SET effective_at=excluded.effective_at, valid_until=excluded.valid_until WHERE excluded.effective_at >= eudi_decisions.effective_at")
        .run(input.municipalityId, input.policyVersion, input.subjectPubkey, row.evidence_ref, row.effective_at, row.valid_until);
      db.exec("COMMIT");
    } catch (error) { db.exec("ROLLBACK"); throw error; }
    return { state: "active", evidenceRef: row.evidence_ref!, effectiveAt: row.effective_at!, validUntil: row.valid_until! };
  }

  recheck(input: EligibilityRecheckInput): Promise<EligibilityDecision> {
    if (input.municipalityId !== this.runtime.municipalityId || input.policyVersion !== this.runtime.policyVersion) return Promise.resolve({ state: "inactive", reason: "policy_mismatch" });
    if (!isSafeNonNegativeInteger(input.now)) return Promise.resolve({ state: "inactive", reason: "evidence_expired" });
    const row = this.runtime.db.prepare("SELECT evidence_ref,effective_at,valid_until FROM eudi_decisions WHERE municipality_id=? AND policy_version=? AND subject_pubkey=? AND evidence_ref=?")
      .get(input.municipalityId, input.policyVersion, input.subjectPubkey, input.evidenceRef) as DecisionRow | undefined;
    return Promise.resolve(!row ? { state: "inactive", reason: "evidence_not_found" } : input.now >= row.valid_until || input.now < row.effective_at ?
      { state: "inactive", reason: "evidence_expired" } : { state: "active", evidenceRef: row.evidence_ref, effectiveAt: row.effective_at, validUntil: row.valid_until });
  }

  private transaction(transactionId: string, subject: string): TransactionRow {
    if (!/^[A-Za-z0-9_-]{1,256}$/u.test(transactionId)) fail("eudi_transaction_not_found", 404);
    const row = this.runtime.db.prepare("SELECT * FROM eudi_transactions WHERE municipality_id=? AND policy_version=? AND transaction_id=? AND subject_pubkey=?")
      .get(this.runtime.municipalityId, this.runtime.policyVersion, transactionId, subject) as TransactionRow | undefined;
    if (!row) fail("eudi_transaction_not_found", 404);
    return row;
  }

  private expire(transactionId: string): EudiRequestState {
    this.runtime.db.prepare("UPDATE eudi_transactions SET state='expired',nonce=NULL,client_id=NULL WHERE municipality_id=? AND policy_version=? AND transaction_id=?")
      .run(this.runtime.municipalityId, this.runtime.policyVersion, transactionId);
    return { state: "expired" };
  }

  private reject(transactionId: string, reason: string): EudiRequestState {
    this.runtime.db.prepare("UPDATE eudi_transactions SET state='failed',reason=?,nonce=NULL,client_id=NULL WHERE municipality_id=? AND policy_version=? AND transaction_id=? AND state='pending'")
      .run(reason, this.runtime.municipalityId, this.runtime.policyVersion, transactionId);
    const row = this.runtime.db.prepare("SELECT state,reason FROM eudi_transactions WHERE municipality_id=? AND policy_version=? AND transaction_id=?")
      .get(this.runtime.municipalityId, this.runtime.policyVersion, transactionId) as { state: string; reason: string | null };
    return row.state === "ready" ? { state: "ready" } : row.state === "expired" ? { state: "expired" } : { state: "failed", reason: row.reason! };
  }

  private evaluate(presentation: string, row: TransactionRow, now: number): Extract<EligibilityDecision, { state: "active" }> {
    if (presentation.length > 200_000) fail("presentation_invalid");
    const parts = presentation.split("~");
    if (parts.length < 2 || parts.length > 256) fail("holder_binding_missing");
    const jwt = parts[0]!.split(".");
    const kb = parts.at(-1)!.split(".");
    if (jwt.length !== 3 || kb.length !== 3) fail("holder_binding_missing");
    const payload = object(decodeJson(jwt[1]!), "presentation_invalid");
    const binding = object(decodeJson(kb[1]!), "holder_binding_missing");
    if (binding.nonce !== row.nonce || binding.aud !== row.client_id) fail("presentation_binding_invalid");
    if (!isSafeNonNegativeInteger(binding.iat) || binding.iat < row.started_at || binding.iat > now) fail("presentation_binding_invalid");
    const sdJwt = parts.slice(0, -1).join("~") + "~";
    if (binding.sd_hash !== createHash("sha256").update(sdJwt).digest("base64url")) fail("presentation_binding_invalid");
    if (typeof payload.vct !== "string" || !this.config.acceptedVcts.includes(payload.vct)) fail("credential_type_invalid");
    if (payload.exp !== undefined && (!isSafeNonNegativeInteger(payload.exp) || payload.exp <= now)) fail("credential_expired");
    const claims = disclosedClaims(parts.slice(1, -1).filter(Boolean), payload);
    const address = object(claims.address, "address_claim_missing");
    if (typeof address.postal_code !== "string" || typeof address.locality !== "string") fail("address_claim_missing");
    const postalCode = normalized(address.postal_code);
    const locality = normalized(address.locality);
    if (!this.config.acceptedAddresses.some((accepted) => normalized(accepted.postalCode) === postalCode && normalized(accepted.locality) === locality)) fail("address_not_accepted");
    if (typeof claims.birthdate !== "string") fail("birthdate_claim_missing");
    const age = ageOn(claims.birthdate, now);
    if (this.runtime.basis.minimumAgeYears !== null && age < this.runtime.basis.minimumAgeYears) fail("under_minimum_age");
    if (typeof claims.family_name !== "string" || typeof claims.given_name !== "string") fail("name_claim_missing");
    const familyName = claims.family_name.normalize("NFC").trim().replace(/\s+/gu, " ").toLowerCase();
    const givenName = claims.given_name.normalize("NFC").trim().replace(/\s+/gu, " ").toLowerCase();
    if (!familyName || !givenName) fail("name_claim_missing");
    const cnf = object(payload.cnf, "holder_binding_missing");
    const jwk = object(cnf.jwk, "holder_binding_missing");
    if ("d" in jwk || !["EC", "OKP", "RSA"].includes(jwk.kty as string)) fail("holder_binding_invalid");
    try { createPublicKey({ key: jwk, format: "jwk" }); } catch { fail("holder_binding_invalid"); }
    const evidenceRef = createHmac("sha256", this.runtime.uniquenessKey)
      .update(`stadtstack-participation/eudi-person/v1/${this.runtime.municipalityId}:${canonical({ familyName, givenName, birthdate: claims.birthdate })}`).digest("hex");
    return { state: "active", effectiveAt: now, validUntil: Math.min(typeof payload.exp === "number" ? payload.exp : Infinity, now + this.config.validitySeconds), evidenceRef };
  }

  private async call(path: string, signal: AbortSignal, init: RequestInit = {}): Promise<{ response: Response; body: Record<string, unknown> }> {
    const bounded = AbortSignal.any([signal, AbortSignal.timeout(this.timeoutMs)]);
    try {
      bounded.throwIfAborted();
      const response = await this.fetcher(`${this.config.verifierBaseUrl}${path}`, { ...init, signal: bounded, redirect: "error", credentials: "omit", cache: "no-store" });
      const chunks: Uint8Array[] = [];
      let size = 0;
      const reader = response.body?.getReader();
      if (reader) {
        try {
          for (;;) {
            const chunk = await reader.read();
            if (chunk.done) break;
            size += chunk.value.length;
            if (size > 262144) fail("verifier_response_invalid", 502);
            chunks.push(chunk.value);
          }
        } finally { await reader.cancel().catch(() => {}); }
      }
      bounded.throwIfAborted();
      const text = Buffer.concat(chunks).toString("utf8");
      return { response, body: text ? object(snapshot(JSON.parse(text), "verifier_response_invalid"), "verifier_response_invalid") : {} };
    } catch (error) {
      if (isCodedError(error)) throw error;
      fail("verifier_unavailable", 502);
    }
  }
}
