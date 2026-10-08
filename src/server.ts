import { createServer, type Server } from "node:http";
import { readFile } from "node:fs/promises";
import { Readable } from "node:stream";
import type { ReadableStream as NodeReadableStream } from "node:stream/web";
import { fileURLToPath } from "node:url";
import { resolve } from "node:path";
import { InPersonAttestorsAdapter } from "./adapters/in-person-attestors.ts";
import { RoebelCitizenNftAdapter } from "./adapters/roebel-citizen-nft.ts";
import { createHttpHandler } from "./http.ts";
import { parseIssuerPolicy } from "./issuer/policy.ts";
import { IssuerService } from "./issuer/service.ts";
import { IssuerStore } from "./issuer/store.ts";
import { openDatabase } from "./shared/db.ts";
import { loadEd25519PrivateKey } from "./shared/ed25519.ts";
import { fail } from "./shared/errors.ts";
import { errorResponse } from "./shared/http.ts";
import { VoteStore } from "./vote/store.ts";
import { createVoteHttpHandlers } from "./vote/http.ts";
import { VoteVerifier } from "./vote/verifier.ts";

/** A listening server and the shutdown that also releases the verifier and database. */
export type ServerRuntime = Readonly<{ server: Server; close(): Promise<void> }>;

/** Runtime reads secret references; keys never enter policy or database records. */
export async function startServer(environment: NodeJS.ProcessEnv = process.env): Promise<ServerRuntime> {
  if (!environment.POLICY_PATH || !environment.DATABASE_PATH || Boolean(environment.ISSUER_SIGNING_KEY_FILE) === Boolean(environment.ISSUER_SIGNING_KEY_SEED_HEX)) fail("server_configuration_invalid", 500);
  const policy = parseIssuerPolicy(JSON.parse(await readFile(environment.POLICY_PATH, "utf8")));
  const signingKey = environment.ISSUER_SIGNING_KEY_FILE ? loadEd25519PrivateKey({ pem: await readFile(environment.ISSUER_SIGNING_KEY_FILE, "utf8") }) :
    loadEd25519PrivateKey({ seedHex: environment.ISSUER_SIGNING_KEY_SEED_HEX! });
  const portText = environment.PORT ?? "3000";
  if (!/^[0-9]{1,5}$/u.test(portText) || Number(portText) > 65535) fail("server_port_invalid", 500);
  // Behind a reverse proxy every socket belongs to the proxy, so all voters
  // would share one rate-limit bucket. CLIENT_KEY_HEADER names a header the
  // trusted proxy overwrites with the client address (e.g. x-real-ip). Never
  // set it when clients can reach the server directly: they could forge it.
  const clientKeyHeader = environment.CLIENT_KEY_HEADER?.toLowerCase();
  if (clientKeyHeader !== undefined && !/^[a-z0-9-]{1,64}$/u.test(clientKeyHeader)) fail("server_configuration_invalid", 500);
  if (policy.adapter.kind === "roebel_citizen_nft_v1" && !environment.ROEBEL_RPC_URL) fail("server_configuration_invalid", 500);
  const db = openDatabase(environment.DATABASE_PATH);
  let verifier: VoteVerifier | undefined;
  try {
    const clock = () => Math.floor(Date.now() / 1000);
    const voteStore = new VoteStore(db);
    const adapter = policy.adapter.kind === "in_person_attestors_v1" ? new InPersonAttestorsAdapter(policy.adapter, { db, municipalityId: policy.municipalityId, policyVersion: policy.policyVersion, basis: policy.basis }) :
      new RoebelCitizenNftAdapter(policy.adapter, { rpcUrl: environment.ROEBEL_RPC_URL! });
    const issuer = new IssuerService({ policy, store: new IssuerStore(db), adapter, signingKey, clock, commitmentLock: voteStore });
    const artifact = JSON.parse(await readFile(new URL("../artifacts/membership_vote.json", import.meta.url), "utf8"));
    if (typeof artifact.bytecode !== "string" || !artifact.bytecode) fail("circuit_artifact_invalid", 500);
    verifier = new VoteVerifier(artifact);
    const peers = new WeakMap<Request, string>();
    const voteHandlers = createVoteHttpHandlers({ store: voteStore, verifier, clock, clientKey: (request) => peers.get(request) ?? "unknown-peer" });
    const handle = createHttpHandler({ issuer, voteHandlers });
    const server = createServer(async (incoming, outgoing) => {
      let response: Response;
      try {
        const path = incoming.url ?? "/";
        // Host and forwarding headers are not authentication authority. The
        // configured public origin is what the NIP-98 signer must bind.
        if (!path.startsWith("/") || path.startsWith("//")) fail("request_url_invalid");
        const headers = new Headers();
        for (let i = 0; i < incoming.rawHeaders.length; i += 2) headers.append(incoming.rawHeaders[i]!, incoming.rawHeaders[i + 1]!);
        const init: RequestInit & { duplex?: "half" } = { method: incoming.method ?? "GET", headers };
        if (init.method !== "GET" && init.method !== "HEAD") { init.body = Readable.toWeb(incoming) as ReadableStream<Uint8Array>; init.duplex = "half"; }
        const request = new Request(`${policy.publicBaseUrl}${path}`, init);
        const forwarded = clientKeyHeader ? headers.get(clientKeyHeader)?.trim() : undefined;
        peers.set(request, forwarded && forwarded.length <= 128 ? forwarded : incoming.socket.remoteAddress ?? "unknown-peer");
        response = await handle(request);
      } catch (error) { response = errorResponse(error); }
      outgoing.writeHead(response.status, Object.fromEntries(response.headers));
      if (response.body) Readable.fromWeb(response.body as NodeReadableStream<Uint8Array>).pipe(outgoing);
      else outgoing.end();
    });
    await new Promise<void>((resolve, reject) => {
      server.once("error", reject);
      server.listen(Number(portText), environment.HOST ?? "127.0.0.1", () => { server.removeListener("error", reject); resolve(); });
    });
    const activeVerifier = verifier;
    return { server, async close() {
      await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
      await activeVerifier.destroy(); db.close();
    } };
  } catch (error) { await verifier?.destroy(); db.close(); throw error; }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const runtime = await startServer();
  let closing = false;
  const stop = () => {
    if (closing) return;
    closing = true;
    void runtime.close().catch(() => { process.exitCode = 1; });
  };
  process.once("SIGTERM", stop); process.once("SIGINT", stop);
}
