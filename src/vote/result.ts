import { digest, exact, isSafeNonNegativeInteger, snapshot } from "../shared/canonical.ts";
import { fail } from "../shared/errors.ts";
import type { ElectionMetadata } from "./election.ts";
import type { Tally } from "./tally.ts";

export type RepresentationAudit = Readonly<{ targetPopulationDescription: string; recruitmentMethod: string; samplingMethod: string | null; totalInvited: number | null; totalStarted: number; totalCompleted: number; limitations: readonly string[] }>;
export type ParticipationResult = Readonly<{
  schemaVersion: "participation_result_v1"; id: string; contractId: string; contractVersion: number;
  methodKind: string; methodVersion: string; ruleId: string; ruleVersion: string; authorityBinding: "none";
  question: string; options: readonly Readonly<{ optionId: string; label: string; aggregateCount: number }>[];
  totalAccepted: number; resultSummary: string; unresolvedDissent: readonly string[];
  representationAudit: RepresentationAudit; limitations: readonly string[];
  openedAt: string; closedAt: string; reviewedAt: string; resultArtifactRef: string; minorityReportRef: string | null;
  correctionState: "current"; checksum: string;
}>;
export type ResultContext = Readonly<{
  id: string; methodKind: string; methodVersion: string; ruleId: string; ruleVersion: string;
  resultSummary: string; unresolvedDissent: readonly string[]; representationAudit: RepresentationAudit;
  limitations: readonly string[]; reviewedAt: string; resultArtifactRef: string; minorityReportRef: string | null;
  checksumBinding: Readonly<{ sourceBrief: Readonly<{ id: string; briefChecksum: string; briefEventId: string }>; policyVersion: string; actorBinding: Readonly<{ actorId: string; actorClass: "participation_reviewer" }> }>;
}>;

// civic-case-coordinator.ts:950,1469-1473; stricter than civic-kernel.ts:226-230.
const RAW_VALUE = /(?:\b(?:npub|nsec)1[a-z0-9-]{8,}\b|\b0x[a-f0-9]{40}\b|\b(?:ballot|eligibility|identity|wallet|credential)\b|\b(?:participant|account|user)(?:[_ -]?id)?\s*[:=]|\b(?:private[_ -]?key|prompt|reasoning|tool[_ -]?trace)\b)/iu;

export function projectParticipationResult(tally: Tally, metadata: ElectionMetadata, context: ResultContext): ParticipationResult {
  if (tally.electionId !== metadata.electionId || tally.choices.length !== metadata.choices.length || tally.choices.some((choice) => !metadata.choices.some((item) => item.index === choice.index && item.label === choice.label)) || tally.choices.reduce((sum, item) => sum + item.count, 0) !== tally.totalAccepted) fail("result_tally_mismatch");
  const audit = exact(snapshot(context.representationAudit), ["targetPopulationDescription", "recruitmentMethod", "samplingMethod", "totalInvited", "totalStarted", "totalCompleted", "limitations"], "representation_invalid") as RepresentationAudit;
  if (!isSafeNonNegativeInteger(audit.totalStarted) || !isSafeNonNegativeInteger(audit.totalCompleted) || audit.totalCompleted > audit.totalStarted || audit.totalCompleted < tally.totalAccepted || (audit.totalInvited !== null && (!isSafeNonNegativeInteger(audit.totalInvited) || audit.totalInvited < audit.totalStarted))) fail("representation_count_inconsistent");
  if (typeof audit.targetPopulationDescription !== "string" || typeof audit.recruitmentMethod !== "string" || (audit.samplingMethod !== null && typeof audit.samplingMethod !== "string")) fail("representation_invalid");
  for (const [value, limit] of [[context.id, 512], [metadata.participationContract.id, 512], [context.methodKind, 256], [context.methodVersion, 256], [context.ruleId, 256], [context.ruleVersion, 256], [context.resultArtifactRef, 2048]] as const) {
    if (typeof value !== "string" || value.length > limit) fail("result_text_invalid");
  }
  if (context.minorityReportRef !== null && (typeof context.minorityReportRef !== "string" || context.minorityReportRef.length > 2048)) fail("result_text_invalid");
  if (!isSafeNonNegativeInteger(tally.totalAccepted) || tally.choices.length > 64 || tally.choices.some((choice) => !isSafeNonNegativeInteger(choice.count) || typeof choice.label !== "string" || choice.label.length > 1000)) fail("result_tally_mismatch");
  const list = (values: readonly string[]) => {
    if (!Array.isArray(values) || values.length > 64 || values.some((value) => typeof value !== "string" || value.length > 2048)) fail("result_text_invalid");
    return [...values].sort();
  };
  const result: Omit<ParticipationResult, "checksum"> = {
    schemaVersion: "participation_result_v1", id: context.id, contractId: metadata.participationContract.id, contractVersion: metadata.participationContract.version,
    methodKind: context.methodKind, methodVersion: context.methodVersion, ruleId: context.ruleId, ruleVersion: context.ruleVersion, authorityBinding: "none", question: metadata.question,
    options: tally.choices.map((choice) => ({ optionId: String(choice.index), label: choice.label, aggregateCount: choice.count })).sort((a, b) => a.optionId < b.optionId ? -1 : a.optionId > b.optionId ? 1 : 0),
    totalAccepted: tally.totalAccepted, resultSummary: context.resultSummary, unresolvedDissent: list(context.unresolvedDissent),
    representationAudit: { ...audit, limitations: list(audit.limitations) }, limitations: list(context.limitations),
    openedAt: new Date(tally.window.opensAt * 1000).toISOString(), closedAt: new Date(tally.window.closesAt * 1000).toISOString(), reviewedAt: context.reviewedAt,
    resultArtifactRef: context.resultArtifactRef, minorityReportRef: context.minorityReportRef, correctionState: "current",
  };
  const check = (value: unknown): void => {
    if (typeof value === "string" && (!value.trim() || value.length > 4000 || RAW_VALUE.test(value))) fail("result_text_invalid");
    if (Array.isArray(value)) for (const child of value) check(child);
    else if (value && typeof value === "object") for (const child of Object.values(value)) check(child);
  };
  check(result);
  const timestamps = [result.openedAt, result.closedAt, result.reviewedAt];
  if (timestamps.some((value) => !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u.test(value) || !Number.isFinite(Date.parse(value))) || Date.parse(result.closedAt) > Date.parse(result.reviewedAt)) fail("participation_timestamp_order_invalid");
  const binding = snapshot(context.checksumBinding);
  return { ...result, checksum: `sha256:${digest({ participation: result, ...(binding as ResultContext["checksumBinding"]), reviewedAt: result.reviewedAt })}` };
}
