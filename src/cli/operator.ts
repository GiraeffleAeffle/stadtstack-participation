import { generateKeyPairSync } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";
import { createPublicClient, encodeFunctionData, http, isAddress, type Address } from "viem";
import { createRuntimeAdapter } from "../server.ts";
import { parseIssuerPolicy, toStadtstackPolicy } from "../issuer/policy.ts";
import { IssuerService } from "../issuer/service.ts";
import { IssuerStore } from "../issuer/store.ts";
import { canonical, digest, exact, object } from "../shared/canonical.ts";
import { openDatabase } from "../shared/db.ts";
import { ed25519PublicKeyHex, loadEd25519PrivateKey } from "../shared/ed25519.ts";
import { fail } from "../shared/errors.ts";
import { isBytes32 } from "../shared/ids.ts";
import { buildAnchor } from "../vote/anchor.ts";
import { electionId, validateMetadata } from "../vote/election.ts";
import type { Hex } from "../vote/hash.ts";
import { ELECTION_REGISTRY_ABI, getElection, assertElectionMatchesChain, type ElectionMirror } from "../vote/registry-client.ts";
import { projectParticipationResult, type ResultContext } from "../vote/result.ts";
import { VoteStore } from "../vote/store.ts";
import { buildTally, tallyHash } from "../vote/tally.ts";

const flags = ["out", "registry", "municipality", "policy-version", "issuer", "issuer-key-id", "issuer-public-key", "public-base-url", "receipt-ttl-seconds", "status-max-age-seconds", "max-event-clock-skew-seconds", "allowed-agent-pubkeys", "basis", "adapter", "attestors", "metadata", "opens-at", "closes-at", "election-id", "review"];
type OperatorOptions = Readonly<Record<string, string | boolean | (string | boolean)[] | undefined>>;
const jsonFile = async (path: string): Promise<unknown> => JSON.parse(await readFile(path, "utf8"));
const outputFile = async (path: string, value: unknown) => writeFile(path, `${canonical(value)}\n`, { flag: "wx" });
const quote = (value: string) => `'${value.replaceAll("'", "'\\''")}'`;

export function transactionArtifacts(input: Readonly<{ chainId: number; address: Address; rpcUrl: string; election: ElectionMirror; tally?: Readonly<{ tallyHash: Hex; totalAccepted: number }> }>) {
  const e = input.election;
  const data = input.tally ? encodeFunctionData({ abi: ELECTION_REGISTRY_ABI, functionName: "closeElection", args: [e.electionId, input.tally.tallyHash, BigInt(input.tally.totalAccepted)] }) : encodeFunctionData({ abi: ELECTION_REGISTRY_ABI, functionName: "openElection", args: [e.electionId, e.metadata.municipalityId, e.anchorRoot, 16, e.metadataHash, BigInt(e.scope), BigInt(e.opensAt), BigInt(e.closesAt)] });
  const signature = input.tally ? "closeElection(bytes32,bytes32,uint256)" : "openElection(bytes32,string,bytes32,uint8,bytes32,uint256,uint64,uint64)";
  const args = input.tally ? [e.electionId, input.tally.tallyHash, String(input.tally.totalAccepted)] : [e.electionId, e.metadata.municipalityId, e.anchorRoot, "16", e.metadataHash, BigInt(e.scope).toString(), String(e.opensAt), String(e.closesAt)];
  // Raw-calldata BatchTransaction: https://github.com/safe-global/safe-wallet-monorepo/blob/dev/apps/tx-builder/src/typings/models.ts
  return { batch: { version: "1.0", chainId: String(input.chainId), createdAt: 0, meta: { name: input.tally ? "Close advisory poll" : "Open advisory poll", description: "Advisory non-binding participation" }, transactions: [{ to: input.address, value: "0", data }] }, castCommand: `cast send --account '<keystore-name>' --rpc-url "$RPC_URL" ${quote(input.address)} ${quote(signature)} ${args.map(quote).join(" ")}` };
}

export async function runOperator(argv: readonly string[], environment: NodeJS.ProcessEnv = process.env): Promise<unknown> {
  const command = argv[0];
  const { values: parsedValues, positionals } = parseArgs({ args: argv.slice(1), options: Object.fromEntries([...flags.map((name) => [name, { type: "string" as const }]), ["json", { type: "boolean" as const }]]), strict: true, allowPositionals: true });
  const values: OperatorOptions = parsedValues;
  const acceptsElectionId = ["poll-confirm-open", "poll-confirm-close", "poll-tally", "poll-result"].includes(command ?? "");
  if (positionals.length > (acceptsElectionId ? 1 : 0) || (positionals.length && values["election-id"] !== undefined)) fail("operator_arguments_invalid");
  const required = (name: string): string => { const value = values[name]; if (typeof value !== "string" || !value) fail(`operator_option_${name}_required`); return value; };
  const integer = (name: string): number => { const text = required(name); if (!/^(?:0|[1-9][0-9]*)$/u.test(text) || !Number.isSafeInteger(Number(text))) fail("operator_integer_invalid"); return Number(text); };
  if (command === "issuer-key") {
    const { privateKey } = generateKeyPairSync("ed25519");
    const pem = privateKey.export({ type: "pkcs8", format: "pem" }).toString();
    await writeFile(required("out"), pem, { flag: "wx", mode: 0o600 });
    return { issuerPublicKey: ed25519PublicKeyHex(loadEd25519PrivateKey({ pem })), out: required("out") };
  }
  if (command === "policy") {
    const registry = object(await jsonFile(typeof values.registry === "string" ? values.registry : fileURLToPath(new URL("../../../stadtstack-registry/snapshot/registry.json", import.meta.url))), "registry_invalid");
    if (registry.schemaVersion !== "municipal_registry_snapshot_v1" || typeof registry.snapshotId !== "string" || !Array.isArray(registry.units)) fail("registry_invalid");
    const municipalityId = required("municipality");
    const unit = registry.units.map((item) => object(item, "registry_invalid")).find((item) => item.id === municipalityId);
    if (!unit || typeof unit.ags !== "string") fail("registry_unit_unknown");
    const adapter = object(await jsonFile(required("adapter")), "adapter_invalid");
    if (typeof values.attestors === "string") adapter.attestors = await jsonFile(values.attestors);
    const publicBaseUrl = required("public-base-url");
    const policy = parseIssuerPolicy({ schemaVersion: "municipal_eligibility_issuer_policy_v1", municipalityId, ags: unit.ags, policyVersion: required("policy-version"), registry: { snapshotId: registry.snapshotId, digest: `sha256:${digest(registry)}` }, issuer: required("issuer"), issuerKeyId: required("issuer-key-id"), issuerPublicKey: required("issuer-public-key"), publicBaseUrl, statusBaseUrl: `${publicBaseUrl}/v1/eligibility/status`, acceptanceBaseUrl: `${publicBaseUrl}/v1/adoptions`, receiptTtlSeconds: integer("receipt-ttl-seconds"), statusMaxAgeSeconds: integer("status-max-age-seconds"), maxEventClockSkewSeconds: integer("max-event-clock-skew-seconds"), allowedAgentPubkeys: required("allowed-agent-pubkeys").split(","), basis: await jsonFile(required("basis")), adapter });
    await outputFile(required("out"), policy);
    return { policy, stadtstackPolicy: toStadtstackPolicy(policy) };
  }
  if (!["poll-draft", "poll-confirm-open", "poll-confirm-close", "poll-tally", "poll-result"].includes(command ?? "")) fail("operator_command_unknown");
  if (!environment.POLICY_PATH || !environment.DATABASE_PATH) fail("operator_configuration_invalid");
  const policy = parseIssuerPolicy(await jsonFile(environment.POLICY_PATH));
  const db = openDatabase(environment.DATABASE_PATH);
  try {
    const store = new VoteStore(db);
    const chainIdText = environment.CHAIN_ID ?? "";
    if (!/^[1-9][0-9]*$/u.test(chainIdText) || !Number.isSafeInteger(Number(chainIdText)) || !environment.RPC_URL || !environment.REGISTRY_ADDRESS || !isAddress(environment.REGISTRY_ADDRESS)) fail("operator_chain_configuration_invalid");
    const chainId = Number(chainIdText), address = environment.REGISTRY_ADDRESS as Address, rpcUrl = environment.RPC_URL;
    const client = createPublicClient({ transport: http(rpcUrl) });
    if (await client.getChainId() !== chainId) fail("chain_id_mismatch");
    const now = Number((await client.getBlock()).timestamp);
    const writeTransaction = async (election: ElectionMirror, tally?: { tallyHash: Hex; totalAccepted: number }) => {
      const artifacts = transactionArtifacts({ chainId, address, rpcUrl, election, ...(tally ? { tally } : {}) });
      await outputFile(required("out"), artifacts.batch);
      await writeFile(`${required("out")}.cast.txt`, `${artifacts.castCommand}\n`, { flag: "wx" });
      return artifacts;
    };
    if (command === "poll-draft") {
      const source = object(await jsonFile(required("metadata")), "metadata_invalid");
      const identity = { municipalityId: policy.municipalityId, policyVersion: policy.policyVersion, electionSlug: source.electionSlug as string };
      const computed = { schemaVersion: "advisory_election_metadata_v1", ...identity, electionId: electionId(identity), opensAt: integer("opens-at"), closesAt: integer("closes-at"), legalEffect: "advisory_non_binding" };
      for (const [key, value] of Object.entries(computed)) if (Object.hasOwn(source, key) && source[key] !== value) fail("metadata_option_mismatch");
      const metadata = validateMetadata({ ...source, ...computed });
      if (metadata.closesAt <= now) fail("election_window_invalid");
      if (!environment.ISSUER_SIGNING_KEY_FILE) fail("operator_signing_key_required");
      const signingKey = loadEd25519PrivateKey({ pem: await readFile(environment.ISSUER_SIGNING_KEY_FILE, "utf8") });
      const adapter = await createRuntimeAdapter(policy, db, environment);
      const issuer = new IssuerService({ policy, store: new IssuerStore(db), adapter, signingKey, clock: () => now, commitmentLock: store });
      const anchor = await buildAnchor(issuer, { metadata, anchoredAt: now, signal: AbortSignal.timeout(120000) });
      const election = store.putElection(metadata, anchor);
      return { election, metadata, anchor, ...await writeTransaction(election) };
    }
    const id = positionals[0] ?? required("election-id");
    if (!isBytes32(id)) fail("election_id_invalid");
    const election = store.getElection(id);
    if (!election || election.metadata.municipalityId !== policy.municipalityId || election.metadata.policyVersion !== policy.policyVersion) fail("election_unknown");
    const chain = await getElection(client, address, id);
    if (command === "poll-confirm-open") return store.openElection(id, chain);
    if (command === "poll-confirm-close") return store.closeElection(id, chain);
    assertElectionMatchesChain(election, chain, store.getAnchor(id)!);
    if (command === "poll-tally") {
      if (election.state !== "open" || chain.closed || now < Number(chain.closesAt)) fail("election_not_ended");
      const manifest = object(await jsonFile(fileURLToPath(new URL("../../artifacts/manifest.json", import.meta.url))), "manifest_invalid");
      const artifacts = object(manifest.artifacts, "manifest_invalid");
      const tally = buildTally({ election, chain, ballots: store.listBallots(id), verifier: { circuitSha256: artifacts["membership_vote.json"] as string, vkHash: manifest.vkHash as Hex } });
      const hash = tallyHash(tally);
      store.putTally(id, tally, hash);
      return { tally, tallyHash: hash, ...await writeTransaction(election, { tallyHash: hash, totalAccepted: tally.totalAccepted }) };
    }
    const stored = store.getTally(id);
    if (election.state !== "closed" || !stored || chain.tallyHash !== stored.tallyHash || chain.acceptedBallots !== BigInt(stored.tally.totalAccepted)) fail("election_result_not_closed");
    const review = exact(await jsonFile(required("review")), ["id", "methodKind", "methodVersion", "ruleId", "ruleVersion", "resultSummary", "unresolvedDissent", "representationAudit", "limitations", "reviewedAt", "resultArtifactRef", "minorityReportRef", "checksumBinding"], "review_invalid") as ResultContext;
    const result = projectParticipationResult(stored.tally, election.metadata, review);
    if (typeof values.out === "string") await outputFile(values.out, result);
    return result;
  } finally { db.close(); }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const result = await runOperator(process.argv.slice(2));
    if (process.argv.includes("--json")) console.log(canonical(result));
    else {
      const value = result as Record<string, unknown>;
      if (typeof value.issuerPublicKey === "string") console.log(value.issuerPublicKey);
      else if (value.stadtstackPolicy) {
        console.log("Stadtstack verifier policy:");
        console.log(JSON.stringify(value.stadtstackPolicy, null, 2));
      } else {
        const { castCommand, ...artifact } = value;
        console.log(JSON.stringify(artifact, null, 2));
        if (typeof castCommand === "string") console.log(`\nSign and send from your configured keystore:\n${castCommand}`);
      }
    }
  } catch (error) { console.error(process.argv.includes("--json") ? JSON.stringify({ error: error instanceof Error ? error.message : "operator_failed" }) : error instanceof Error ? error.message : "operator_failed"); process.exitCode = 1; }
}
