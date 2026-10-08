import { deriveAttestorSecretKey } from "../../src/vote/identity.ts";
import { ed25519PublicKeyHex } from "../../src/shared/ed25519.ts";
import { buildAttestation, buildRevocation, DOCUMENT_KINDS, parseSubjectCode, signAttestation, signRevocation, subjectFingerprint } from "../../src/adapters/in-person-attestation.ts";
import { api, basisConditions, createPasskey, element, errorMessage, runAction, showConfig, storedCredential } from "./common.ts";
import type { ClientConfig } from "../../src/shared/seams.ts";

type DetectedCode = { rawValue: string };
type CodeDetector = { detect(source: HTMLVideoElement): Promise<DetectedCode[]> };
type CodeDetectorConstructor = { new (options: { formats: string[] }): CodeDetector; getSupportedFormats(): Promise<string[]> };
let config: ClientConfig;
let secretKey: Uint8Array | undefined;
let attestorId: string | undefined;
let parsedSubject: string | undefined;
let stream: MediaStream | undefined;
let scanTimer: number | undefined;
const status = element("status");
const codeInput = element<HTMLTextAreaElement>("subject-code");
function stopCamera(): void {
  if (scanTimer) window.clearTimeout(scanTimer);
  stream?.getTracks().forEach((track) => track.stop()); stream = undefined;
  element<HTMLVideoElement>("camera").srcObject = null;
  element("camera").hidden = true; element("stop-camera").hidden = true;
}
function readSubject(): string {
  const { subjectPubkey } = parseSubjectCode(codeInput.value, config.municipalityId);
  parsedSubject = subjectPubkey;
  element("subject-fingerprint").textContent = subjectFingerprint(subjectPubkey);
  return subjectPubkey;
}
async function login(create: boolean): Promise<void> {
  const credentialId = create ? await createPasskey(config, "attestor") : storedCredential(config, "attestor");
  const derived = await deriveAttestorSecretKey({ municipalityId: config.municipalityId, credentialId });
  secretKey?.fill(0); secretKey = derived;
  const publicKey = ed25519PublicKeyHex(secretKey);
  attestorId = config.attestors?.find((attestor) => attestor.publicKey === publicKey)?.attestorId;
  element<HTMLTextAreaElement>("attestor-key").value = publicKey;
  element("attestor-fingerprint").textContent = subjectFingerprint(publicKey);
  element("key-details").hidden = false; element("logout").hidden = false;
  element("key-status").textContent = attestorId ? `Dein Prüfschlüssel ist freigegeben (${attestorId}).` : "Dein Prüfschlüssel ist noch nicht freigegeben. Kopiere den öffentlichen Schlüssel und sende ihn an die zuständige Person in der Gemeinde. Der geheime Schlüssel wird nicht geteilt.";
  for (const id of ["subject-section", "attest-section", "revoke-section"]) element(id).hidden = !attestorId;
  status.textContent = attestorId ? "Du kannst jetzt einen Teilnahmecode prüfen." : "Sende deinen öffentlichen Prüfschlüssel an die Gemeinde.";
}
async function scanCode(): Promise<void> {
  const detectorCandidate: unknown = Reflect.get(globalThis, "BarcodeDetector");
  if (typeof detectorCandidate !== "function") { element("camera-status").textContent = "Dein Browser kann QR-Codes nicht direkt lesen. Bitte kopiere den Code vom Gerät der Person und füge ihn hier ein."; return; }
  const Detector = detectorCandidate as CodeDetectorConstructor;
  if (!(await Detector.getSupportedFormats()).includes("qr_code")) { element("camera-status").textContent = "Dieser Browser unterstützt keine QR-Codes. Bitte füge den Code als Text ein."; return; }
  stopCamera();
  const detector = new Detector({ formats: ["qr_code"] });
  stream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: "environment" }, audio: false });
  const video = element<HTMLVideoElement>("camera"); video.srcObject = stream; video.hidden = false; element("stop-camera").hidden = false; await video.play();
  const scan = async (): Promise<void> => {
    if (!stream) return;
    try {
      const codes = await detector.detect(video);
      for (const code of codes) {
        try { parseSubjectCode(code.rawValue, config.municipalityId); } catch { continue; }
        codeInput.value = code.rawValue; resetConfirmations(); readSubject(); stopCamera(); element("camera-status").textContent = "Code gelesen. Vergleiche jetzt den Fingerabdruck."; return;
      }
      scanTimer = window.setTimeout(() => { void scan(); }, 250);
    } catch (error) { stopCamera(); element("camera-status").textContent = errorMessage(error); }
  };
  scanTimer = window.setTimeout(() => { void scan(); }, 250);
}
function resetConfirmations(): void {
  parsedSubject = undefined;
  element("subject-fingerprint").textContent = "Noch kein gültiger Code";
  document.querySelectorAll<HTMLInputElement>("#conditions input, #attest-fingerprint-confirm, #revoke-confirm").forEach((input) => { input.checked = false; });
}
async function attest(): Promise<void> {
  if (!secretKey || !attestorId) throw new Error("attestation_invalid");
  const subject = readSubject();
  if (!parsedSubject || !element<HTMLInputElement>("attest-fingerprint-confirm").checked) throw new Error("subject_code_invalid");
  const documentKinds = Array.from(document.querySelectorAll<HTMLInputElement>("#documents input:checked"), (input) => input.value);
  if (!documentKinds.length) { status.textContent = "Wähle mindestens ein geprüftes Dokument aus."; return; }
  const core = buildAttestation({ municipalityId: config.municipalityId, policyVersion: config.policyVersion, subjectPubkey: subject, attestorId, attestedAt: Math.floor(Date.now() / 1000), basis: config.basis, documentKinds });
  await api("/v1/attestations", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(signAttestation(secretKey, core)) });
  status.textContent = "Deine Bestätigung wurde gespeichert. Weitere unabhängige Bestätigungen können noch nötig sein."; resetConfirmations();
}
async function revoke(): Promise<void> {
  if (!secretKey || !attestorId || !element<HTMLInputElement>("revoke-confirm").checked) throw new Error("attestation_invalid");
  const subject = readSubject();
  const core = buildRevocation({ municipalityId: config.municipalityId, policyVersion: config.policyVersion, subjectPubkey: subject, attestorId, revokedAt: Math.floor(Date.now() / 1000) });
  await api("/v1/attestation-revocations", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(signRevocation(secretKey, core)) });
  status.textContent = "Dein Widerruf wurde gespeichert."; resetConfirmations();
}
for (const [id, create] of [["create-passkey", true], ["use-passkey", false]] as const) { const button = element<HTMLButtonElement>(id); button.addEventListener("click", () => { void runAction(button, status, () => login(create)); }); }
for (const [formId, buttonId, action] of [["attest-form", "submit-attestation", attest], ["revoke-form", "submit-revocation", revoke]] as const) { element<HTMLFormElement>(formId).addEventListener("submit", (event) => { event.preventDefault(); void runAction(element<HTMLButtonElement>(buttonId), status, action); }); }
element("check-code").addEventListener("click", () => { try { readSubject(); status.textContent = "Code gültig. Vergleiche den Fingerabdruck auf beiden Geräten."; } catch (error) { status.textContent = errorMessage(error); } });
codeInput.addEventListener("input", () => { resetConfirmations(); try { readSubject(); } catch { /* Incomplete pasted codes stay unconfirmed. */ } });
element("scan-code").addEventListener("click", () => { void runAction(element<HTMLButtonElement>("scan-code"), status, scanCode); });
element("stop-camera").addEventListener("click", stopCamera);
element("copy-key").addEventListener("click", () => { void navigator.clipboard.writeText(element<HTMLTextAreaElement>("attestor-key").value).then(() => { status.textContent = "Prüfschlüssel kopiert."; }).catch(() => { status.textContent = "Bitte markiere und kopiere den Schlüssel von Hand."; }); });
element("logout").addEventListener("click", () => { secretKey?.fill(0); secretKey = undefined; attestorId = undefined; stopCamera(); resetConfirmations(); for (const id of ["key-details", "logout", "subject-section", "attest-section", "revoke-section"]) element(id).hidden = true; status.textContent = "Du bist abgemeldet."; });
document.addEventListener("visibilitychange", () => { if (document.hidden) stopCamera(); });
void api<ClientConfig>("/v1/client-config").then((value) => {
  config = value; showConfig(config);
  if (config.adapterKind !== "in_person_attestors_v1") { status.textContent = "Diese Gemeinde nutzt keine persönliche Prüfung über dieses Angebot."; return; }
  for (const [kind, text] of Object.entries(DOCUMENT_KINDS)) { const label = document.createElement("label"); const input = document.createElement("input"); input.type = "checkbox"; input.name = "documentKind"; input.value = kind; input.id = `document-${kind}`; label.append(input, document.createTextNode(text)); element("documents").append(label); }
  for (const [index, condition] of basisConditions(config).entries()) { const label = document.createElement("label"); const input = document.createElement("input"); input.type = "checkbox"; input.required = true; input.id = `condition-${index}`; label.append(input, document.createTextNode(`Ich habe geprüft: ${condition}.`)); element("conditions").append(label); }
  element<HTMLButtonElement>("create-passkey").disabled = false; element<HTMLButtonElement>("use-passkey").disabled = false; status.textContent = "Melde dich mit deinem Prüf-Passkey an.";
}).catch((error: unknown) => { status.textContent = errorMessage(error); });
