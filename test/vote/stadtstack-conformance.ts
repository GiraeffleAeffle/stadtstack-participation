import assert from "node:assert/strict";
import { digest } from "../../src/shared/canonical.ts";
import type { ParticipationResult, ResultContext } from "../../src/vote/index.ts";

/** Mirrors coordinator.ts:835-870,950-954,1469-1565,1574-1587 (30a677f).
 * Kernel.ts:503-624,680-765 additionally forbids raw keys and nested values.
 * The coordinator currently admits only its synthetic fixture references/time.
 */
export function assertStadtstackConformance(result: ParticipationResult, binding: ResultContext["checksumBinding"]): void {
  assert.deepEqual(Object.keys(result).sort(), ["schemaVersion", "id", "contractId", "contractVersion", "methodKind", "methodVersion", "ruleId", "ruleVersion", "authorityBinding", "question", "options", "totalAccepted", "resultSummary", "unresolvedDissent", "representationAudit", "limitations", "openedAt", "closedAt", "reviewedAt", "resultArtifactRef", "minorityReportRef", "correctionState", "checksum"].sort());
  assert.equal(result.schemaVersion, "participation_result_v1");
  assert.equal(result.authorityBinding, "none");
  assert.equal(result.correctionState, "current");
  const text = (value: unknown, limit = 4000): void => {
    assert.equal(typeof value, "string");
    const string = value as string;
    assert.ok(string.trim().length > 0 && string.length <= limit);
    assert.doesNotMatch(string, /(?:\b(?:npub|nsec)1[a-z0-9-]{8,}\b|\b0x[a-f0-9]{40}\b|\b(?:ballot|eligibility|identity|wallet|credential)\b|\b(?:participant|account|user)(?:[_ -]?id)?\s*[:=]|\b(?:private[_ -]?key|prompt|reasoning|tool[_ -]?trace)\b)/iu);
  };
  const count = (value: number) => assert.ok(Number.isSafeInteger(value) && value >= 0);
  const strings = (values: readonly string[]) => {
    assert.ok(Array.isArray(values) && values.length <= 64);
    for (const value of values) text(value, 2048);
    assert.deepEqual(values, [...values].sort());
  };
  text(result.id, 512);
  text(result.contractId, 512);
  for (const value of [result.methodKind, result.methodVersion, result.ruleId, result.ruleVersion]) text(value, 256);
  text(result.question);
  text(result.resultSummary);
  count(result.contractVersion);
  assert.ok(result.contractVersion >= 1);
  count(result.totalAccepted);
  assert.ok(result.options.length <= 64);
  for (const option of result.options) {
    assert.deepEqual(Object.keys(option).sort(), ["optionId", "label", "aggregateCount"].sort());
    text(option.optionId, 256);
    text(option.label, 1000);
    count(option.aggregateCount);
  }
  assert.deepEqual(result.options.map((item) => item.optionId), [...result.options.map((item) => item.optionId)].sort());
  for (let i = 1; i < result.options.length; i++) assert.notEqual(result.options[i]!.optionId, result.options[i - 1]!.optionId);
  assert.equal(result.options.reduce((sum, item) => sum + item.aggregateCount, 0), result.totalAccepted);
  const audit = result.representationAudit;
  assert.deepEqual(Object.keys(audit).sort(), ["targetPopulationDescription", "recruitmentMethod", "samplingMethod", "totalInvited", "totalStarted", "totalCompleted", "limitations"].sort());
  text(audit.targetPopulationDescription);
  text(audit.recruitmentMethod);
  if (audit.samplingMethod !== null) text(audit.samplingMethod);
  count(audit.totalStarted);
  count(audit.totalCompleted);
  if (audit.totalInvited !== null) { count(audit.totalInvited); assert.ok(audit.totalInvited >= audit.totalStarted); }
  assert.ok(audit.totalCompleted <= audit.totalStarted && audit.totalCompleted >= result.totalAccepted);
  strings(audit.limitations);
  strings(result.limitations);
  strings(result.unresolvedDissent);
  for (const value of [result.openedAt, result.closedAt, result.reviewedAt]) {
    assert.match(value, /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u);
    assert.ok(Number.isFinite(Date.parse(value)));
  }
  assert.ok(Date.parse(result.openedAt) <= Date.parse(result.closedAt) && Date.parse(result.closedAt) <= Date.parse(result.reviewedAt));
  assert.equal(result.reviewedAt, "2026-08-08T00:00:05.000Z");
  text(result.resultArtifactRef, 2048);
  assert.match(result.resultArtifactRef, /^synthetic:\/\/[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]{1,2040}$/u);
  if (result.minorityReportRef !== null) { text(result.minorityReportRef, 2048); assert.match(result.minorityReportRef, /^synthetic:\/\/[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]{1,2040}$/u); }
  assert.match(result.checksum, /^sha256:[a-f0-9]{64}$/u);
  const { checksum, ...participation } = result;
  assert.equal(checksum, `sha256:${digest({ participation, ...binding, reviewedAt: result.reviewedAt })}`);
  const walk = (value: unknown): void => {
    if (typeof value === "string") {
      assert.doesNotMatch(value, /\b(?:npub|nsec)1[0-9a-z][0-9a-z-]{7,}\b|\b0x[a-f0-9]{40}\b|\b(?:participant(?:id|[_-]?id)|user(?:id|[_-]?id)|identity|ballot|wallet)\s*[:=]\s*(?:"[^"\r\n]*"|'[^'\r\n]*'|[^\s,;]+)/iu);
    } else if (Array.isArray(value)) for (const child of value) walk(child);
    else if (value && typeof value === "object") for (const [key, child] of Object.entries(value)) {
      assert.doesNotMatch(key, /(ballot|wallet|npub|participant[_-]?id|user[_-]?id|eligibility[_-]?proof|social[_-]?graph|identity)/iu);
      walk(child);
    }
  };
  walk(result);
}
