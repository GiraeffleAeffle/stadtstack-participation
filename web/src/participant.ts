import { getPublicKey } from "nostr-tools/pure";
import { createPublicClient, http } from "viem";
import { deriveParticipantKeys } from "../../src/vote/identity.ts";
import { identityCommitment, type Hex } from "../../src/vote/hash.ts";
import { assertElectionMatchesChain, getElection, type ElectionMirror } from "../../src/vote/registry-client.ts";
import { buildMerkleTree, inclusionPath } from "../../src/vote/merkle.ts";
import { submitBallot } from "../../src/vote/client.ts";
import type { InclusionPath } from "../../src/vote/merkle.ts";
import type { ElectionAnchor } from "../../src/vote/anchor.ts";
import type { Ballot } from "../../src/vote/ballot.ts";
import type { Tally } from "../../src/vote/tally.ts";
import { subjectCode, subjectFingerprint } from "../../src/adapters/in-person-attestation.ts";
import { api, authenticatedRequest, createPasskey, element, errorMessage, renderQr, runAction, showConfig, storedCredential } from "./common.ts";
import type { ClientConfig } from "../../src/shared/seams.ts";

type Eligibility = { subjectPubkey: string; eligibility: { state: "active"; effectiveAt: number; validUntil: number | null } | { state: "inactive"; reason: string }; enrollment: { identityCommitment: Hex; enrolledAt: number } | null };
type EudiState = { state: "pending" | "ready" | "expired" | "failed"; reason?: string };
let config: ClientConfig;
let keys: { votingSecret: bigint; nostrSecretKey: Uint8Array } | undefined;
let transactionId: string | undefined;
let walletTimer: number | undefined;
let eligibilityBusy = false;
// Poll only until the person is eligible and enrolled; each poll spends a NIP-98 event.
let settled = false;
let session = 0;
let lastSignedAt = 0;
const status = element("status");
async function signed<T>(path: string, method: "GET" | "POST", body?: unknown): Promise<T> {
  // A deterministic NIP-98 event must never be reused, even for two clicks in
  // the same second. Wait for a fresh real timestamp rather than signing future time.
  while (Math.floor(Date.now() / 1000) <= lastSignedAt) {
    const { promise, resolve } = Promise.withResolvers<void>();
    window.setTimeout(resolve, 100);
    await promise;
  }
  if (!keys) throw new Error("auth_required");
  lastSignedAt = Math.floor(Date.now() / 1000);
  return api<T>(path, authenticatedRequest(config.publicBaseUrl, path, method, keys.nostrSecretKey, body, lastSignedAt));
}
async function refreshEligibility(): Promise<void> {
  if (!keys || eligibilityBusy) return;
  eligibilityBusy = true;
  const currentSession = session;
  try {
    const value = await signed<Eligibility>("/v1/eligibility/me", "GET");
    if (currentSession !== session || !keys) return;
    const active = value.eligibility.state === "active";
    const enrolled = value.enrollment?.identityCommitment === identityCommitment(keys.votingSecret);
    element("eligibility-status").textContent = active ? (enrolled ? "Du bist berechtigt und dein Stimmenschlüssel ist aktiviert." : "Deine Berechtigung ist bestätigt. Aktiviere jetzt deine Teilnahme.") : "Deine Berechtigung ist noch nicht bestätigt oder nicht mehr gültig.";
    element("enrollment").hidden = !active || enrolled;
    settled = active && enrolled;
    element("in-person").hidden = config.adapterKind !== "in_person_attestors_v1" || active;
    element("eudi").hidden = config.adapterKind !== "eudi_pid_v1" || (active && enrolled);
    if (config.adapterKind !== "in_person_attestors_v1" && config.adapterKind !== "eudi_pid_v1") element("eligibility-status").textContent = "Dieses Angebot unterstützt den Nachweis dieser Gemeinde noch nicht. Bitte wende dich an die Gemeinde.";
  } finally { eligibilityBusy = false; }
}
async function login(create: boolean): Promise<void> {
  const credentialId = create ? await createPasskey(config, "participant") : storedCredential(config, "participant");
  const derived = await deriveParticipantKeys({ municipalityId: config.municipalityId, credentialId });
  keys?.nostrSecretKey.fill(0); keys = derived; session++;
  const subject = getPublicKey(keys.nostrSecretKey);
  const code = subjectCode(config.municipalityId, subject);
  element<HTMLTextAreaElement>("subject-code").value = code;
  renderQr(element("subject-qr"), code);
  element("subject-fingerprint").textContent = subjectFingerprint(subject);
  element("eligibility").hidden = false; element("logout").hidden = false;
  status.textContent = "Du bist angemeldet. Dein geheimer Schlüssel bleibt nur für diese Sitzung im Arbeitsspeicher.";
  await refreshEligibility(); await loadPolls();
}
async function enroll(): Promise<void> {
  if (!keys) return;
  await signed("/v1/identity-commitments", "POST", { identityCommitment: identityCommitment(keys.votingSecret), evidence: config.adapterKind === "eudi_pid_v1" ? { transactionId } : null });
  transactionId = undefined;
  status.textContent = "Deine Teilnahme ist aktiviert. Bereits eingerichtete Umfragen behalten ihre bisherige Teilnehmerliste.";
  await refreshEligibility(); await loadPolls();
}
async function startEudi(): Promise<void> {
  if (walletTimer) window.clearTimeout(walletTimer);
  const request = await signed<{ transactionId: string; walletUrl: string; expiresAt: number }>("/v1/eudi/requests", "POST", {});
  transactionId = request.transactionId;
  const wallet = new URL(request.walletUrl);
  if (wallet.protocol !== "eudi-openid4vp:") throw new Error("wallet_url_invalid");
  const link = element<HTMLAnchorElement>("wallet-link"); link.href = request.walletUrl; link.hidden = false;
  renderQr(element("wallet-qr"), request.walletUrl);
  element("wallet-status").textContent = "Öffne deine EUDI-Wallet oder scanne den QR-Code mit dem Wallet-Gerät.";
  const currentSession = session;
  const poll = async (): Promise<void> => {
    if (!keys || currentSession !== session || transactionId !== request.transactionId) return;
    try {
      if (Date.now() / 1000 >= request.expiresAt) throw new Error("eudi_expired");
      if (document.visibilityState === "visible") {
        const state = await signed<EudiState>(`/v1/eudi/requests/${encodeURIComponent(request.transactionId)}`, "GET");
        if (state.state === "ready") { element("wallet-status").textContent = "Dein Nachweis ist bestätigt. Die Teilnahme wird aktiviert …"; await enroll(); return; }
        if (state.state === "expired") throw new Error("eudi_expired");
        if (state.state === "failed") { element("wallet-status").textContent = "Der Wallet-Nachweis konnte nicht bestätigt werden. Bitte prüfe deine Angaben und starte erneut."; return; }
      }
      walletTimer = window.setTimeout(() => { void poll(); }, 3000);
    } catch (error) { element("wallet-status").textContent = errorMessage(error); }
  };
  walletTimer = window.setTimeout(() => { void poll(); }, 3000);
}
async function proveBallot(input: { secret: bigint; electionId: Hex; choiceIndex: number; inclusion: InclusionPath; anchorRoot: Hex }, progress: HTMLElement): Promise<Ballot> {
  const worker = new Worker(new URL("./prover.worker.ts", import.meta.url), { type: "module" });
  try {
    const { promise, resolve, reject } = Promise.withResolvers<Ballot>();
    worker.onmessage = (event: MessageEvent<{ progress?: string; ballot?: Ballot; error?: string }>) => {
      if (event.data.progress) progress.textContent = event.data.progress;
      else if (event.data.ballot) resolve(event.data.ballot);
      else reject(new Error(event.data.error ?? "proof_invalid"));
    };
    worker.onerror = () => reject(new Error("proof_invalid"));
    worker.postMessage(input);
    return await promise;
  } finally { worker.terminate(); }
}
async function vote(mirror: ElectionMirror, choice: number, progress: HTMLElement): Promise<void> {
  if (!keys) { progress.textContent = "Bitte melde dich zuerst mit deinem Passkey an."; return; }
  if (!config.chain) { progress.textContent = "Das öffentliche Register ist noch nicht eingerichtet."; return; }
  const secret = keys.votingSecret;
  progress.textContent = "Umfrage und Teilnehmerliste werden mit dem öffentlichen Register verglichen …";
  const client = createPublicClient({ transport: http(config.chain.rpcUrl), chain: { id: config.chain.chainId, name: "Gemeinderegister", nativeCurrency: { name: "xDAI", symbol: "xDAI", decimals: 18 }, rpcUrls: { default: { http: [config.chain.rpcUrl] } } } });
  const [chain, anchor] = await Promise.all([getElection(client, config.chain.registryAddress, mirror.electionId), api<ElectionAnchor>(`/v1/elections/${mirror.electionId}/anchor`)]);
  assertElectionMatchesChain(mirror, chain, anchor);
  if (chain.closed || BigInt(Math.floor(Date.now() / 1000)) < chain.opensAt || BigInt(Math.floor(Date.now() / 1000)) >= chain.closesAt) throw new Error("election_not_open");
  const inclusion = inclusionPath(buildMerkleTree(anchor.leaves), identityCommitment(secret));
  const ballot = await proveBallot({ secret, electionId: mirror.electionId, choiceIndex: choice, inclusion, anchorRoot: anchor.root }, progress);
  progress.textContent = "Deine Antwort wird ohne Anmeldung gesendet …";
  const result = await submitBallot("", ballot);
  if (!result.ok) throw new Error(result.code);
  progress.textContent = "Deine Antwort wurde angenommen. Danke fürs Mitmachen!";
}
async function loadPolls(): Promise<void> {
  const { elections } = await api<{ elections: ElectionMirror[] }>("/v1/elections");
  const target = element("polls"); target.replaceChildren();
  if (!elections.length) { target.textContent = "Zurzeit gibt es keine Umfragen."; return; }
  for (const mirror of elections) {
    const article = document.createElement("article");
    const title = document.createElement("h3"); title.textContent = mirror.metadata.title;
    const question = document.createElement("p"); question.textContent = mirror.metadata.question;
    const dates = document.createElement("p"); dates.textContent = `Zeitraum: ${new Date(mirror.opensAt * 1000).toLocaleString("de-DE")} bis ${new Date(mirror.closesAt * 1000).toLocaleString("de-DE")}`;
    article.append(title, question, dates); target.append(article);
    const progress = document.createElement("p"); progress.setAttribute("role", "status");
    if (mirror.state === "closed") {
      const link = document.createElement("a"); link.href = `/v1/elections/${mirror.electionId}/tally`; link.textContent = "Ergebnis als JSON (prüfbar)"; article.append(link, progress);
      try {
        const { tally, tallyHash } = await api<{ tally: Tally; tallyHash: Hex }>(link.href.replace(location.origin, ""));
        const list = document.createElement("ul");
        for (const choice of tally.choices) { const item = document.createElement("li"); item.textContent = `${choice.label}: ${choice.count}`; list.append(item); }
        const hash = document.createElement("p"); hash.className = "hash"; hash.textContent = `Prüfsumme (im Register hinterlegt): ${tallyHash}`;
        article.append(list, hash); progress.textContent = `${tally.totalAccepted} ${tally.totalAccepted === 1 ? "Antwort" : "Antworten"} insgesamt.`;
      } catch { progress.textContent = "Das prüfbare Ergebnis ist noch nicht veröffentlicht."; }
      continue;
    }
    const now = Math.floor(Date.now() / 1000);
    if (now < mirror.opensAt || now >= mirror.closesAt) {
      progress.textContent = now < mirror.opensAt ? "Die Umfrage hat noch nicht begonnen." : "Die Umfrage ist beendet. Das Ergebnis wird ausgezählt und danach hier veröffentlicht.";
      article.append(progress);
      continue;
    }
    const form = document.createElement("form"); const fieldset = document.createElement("fieldset"); const legend = document.createElement("legend"); legend.textContent = "Deine Antwort"; fieldset.append(legend);
    for (const choice of mirror.metadata.choices) {
      const label = document.createElement("label"); const radio = document.createElement("input"); radio.type = "radio"; radio.name = "choice"; radio.value = String(choice.index); radio.required = true; radio.id = `choice-${mirror.electionId}-${choice.index}`; label.append(radio, document.createTextNode(choice.label)); fieldset.append(label);
    }
    const button = document.createElement("button"); button.type = "submit"; button.id = `vote-${mirror.electionId}`; button.textContent = "Antwort sicher absenden"; form.append(fieldset, button, progress); article.append(form);
    form.addEventListener("submit", (event) => { event.preventDefault(); const selected = new FormData(form).get("choice"); if (typeof selected !== "string") return; void runAction(button, progress, () => vote(mirror, Number(selected), progress)); });
  }
}
for (const [id, create] of [["create-passkey", true], ["use-passkey", false]] as const) {
  const button = element<HTMLButtonElement>(id); button.addEventListener("click", () => { void runAction(button, status, () => login(create)); });
}
for (const [id, action] of [["refresh-eligibility", refreshEligibility], ["enroll", enroll], ["refresh-polls", loadPolls], ["start-eudi", startEudi]] as const) {
  const button = element<HTMLButtonElement>(id); button.addEventListener("click", () => { void runAction(button, status, action); });
}
element("copy-subject").addEventListener("click", () => { void navigator.clipboard.writeText(element<HTMLTextAreaElement>("subject-code").value).then(() => { status.textContent = "Code kopiert."; }).catch(() => { status.textContent = "Bitte markiere und kopiere den Code von Hand."; }); });
element("logout").addEventListener("click", () => { keys?.nostrSecretKey.fill(0); keys = undefined; transactionId = undefined; settled = false; session++; if (walletTimer) window.clearTimeout(walletTimer); element("eligibility").hidden = true; element("logout").hidden = true; status.textContent = "Du bist abgemeldet."; });
window.setInterval(() => { if (!settled && document.visibilityState === "visible" && config?.adapterKind === "in_person_attestors_v1") void refreshEligibility().catch((error: unknown) => { status.textContent = errorMessage(error); }); }, 10000);
void api<ClientConfig>("/v1/client-config").then(async (value) => { config = value; showConfig(config); element<HTMLButtonElement>("create-passkey").disabled = false; element<HTMLButtonElement>("use-passkey").disabled = false; status.textContent = "Melde dich mit einem Passkey an, um teilzunehmen."; await loadPolls(); }).catch((error: unknown) => { status.textContent = errorMessage(error); });
