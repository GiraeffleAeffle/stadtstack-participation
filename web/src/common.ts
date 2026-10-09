import { finalizeEvent } from "nostr-tools/pure";
import { base64urlnopad } from "@scure/base";
import { encode } from "uqr";
import { nip98Header, nip98Template } from "../../src/shared/nostr.ts";
import { credentialCreationOptions } from "../../src/vote/identity.ts";
import type { ClientConfig } from "../../src/shared/seams.ts";

export function authenticatedRequest(baseUrl: string, path: string, method: "GET" | "POST", key: Uint8Array, input?: unknown, createdAt = Math.floor(Date.now() / 1000)): RequestInit {
  const body = input === undefined ? undefined : JSON.stringify(input);
  const event = finalizeEvent(nip98Template({ url: baseUrl + path, method, body: new TextEncoder().encode(body ?? ""), createdAt }), key);
  return { method, body, credentials: "omit", cache: "no-store", redirect: "error", headers: { ...(body === undefined ? {} : { "content-type": "application/json" }), authorization: nip98Header(event) } };
}
export async function api<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(path, { credentials: "omit", cache: "no-store", redirect: "error", ...init });
  const data: unknown = await response.json();
  if (!response.ok) throw new Error(data && typeof data === "object" && "error" in data && typeof data.error === "string" ? data.error : "request_failed");
  return data as T;
}
export function element<T extends HTMLElement>(id: string): T {
  const value = document.getElementById(id);
  if (!value) throw new Error(`Missing element: ${id}`);
  return value as T;
}
export function basisConditions(config: ClientConfig): string[] {
  const b = config.basis;
  const conditions = [b.residence === "main_residence" ? `Hauptwohnsitz in ${config.displayName}` : `Haupt- oder Nebenwohnsitz in ${config.displayName}`];
  if (b.minimumAgeYears !== null) conditions.push(`Mindestens ${b.minimumAgeYears} Jahre alt`);
  if (b.nationality !== "any") conditions.push(b.nationality === "eu_citizen" ? "Staatsangehörigkeit eines EU-Landes" : "Deutsche Staatsangehörigkeit");
  if (b.localityScope !== null) conditions.push(`Wohnsitz im zugelassenen Ortsteil: ${b.localityScope.join(", ")}`);
  return conditions;
}
export function showConfig(config: ClientConfig): void {
  element("municipality").textContent = config.displayName;
  element("basis").textContent = basisConditions(config).join(" · ");
  element("operator").textContent = operatorNotice(config);
  element("test-mode").hidden = config.chain?.chainId !== 10200;
}
/** Who runs the service, so an independent offer never looks official. */
export function operatorNotice(config: ClientConfig): string {
  return config.operator.isMunicipality ? `Ein Angebot von ${config.operator.name}.` : `Ein unabhängiges Angebot von ${config.operator.name} – kein Angebot der Verwaltung von ${config.displayName}.`;
}
export function renderQr(target: HTMLElement, text: string): void {
  const { data, size } = encode(text, { ecc: "M" });
  const ns = "http://www.w3.org/2000/svg";
  const svg = document.createElementNS(ns, "svg");
  svg.setAttribute("viewBox", `0 0 ${size + 8} ${size + 8}`);
  svg.setAttribute("role", "img"); svg.setAttribute("aria-label", "QR-Code");
  const background = document.createElementNS(ns, "rect");
  background.setAttribute("width", "100%"); background.setAttribute("height", "100%"); background.setAttribute("fill", "white"); svg.append(background);
  const path = document.createElementNS(ns, "path");
  const pixels: string[] = [];
  for (let y = 0; y < size; y++) for (let x = 0; x < size; x++) if (data[y]?.[x]) pixels.push(`M${x + 4} ${y + 4}h1v1h-1z`);
  path.setAttribute("d", pixels.join("")); path.setAttribute("fill", "black"); svg.append(path); target.replaceChildren(svg);
}
export async function createPasskey(config: ClientConfig, role: "participant" | "attestor"): Promise<Uint8Array<ArrayBuffer>> {
  const publicKey = await credentialCreationOptions({ challenge: crypto.getRandomValues(new Uint8Array(32)), rp: { name: `Mitmachen ${config.displayName}` }, user: { id: crypto.getRandomValues(new Uint8Array(32)), name: role === "participant" ? "Mitmachen" : "Prüfung", displayName: role === "participant" ? "Mitmachen" : "Prüfung" }, pubKeyCredParams: [{ type: "public-key", alg: -7 }, { type: "public-key", alg: -257 }], authenticatorSelection: { residentKey: "required", userVerification: "required" }, timeout: 120000, attestation: "none" }, config.municipalityId, role);
  const credential = await navigator.credentials.create({ publicKey });
  if (!(credential instanceof PublicKeyCredential)) throw new Error("prf_unavailable");
  const id = new Uint8Array(credential.rawId);
  try { localStorage.setItem(`stadtstack/${config.municipalityId}/${role}/credential`, base64urlnopad.encode(id)); } catch { /* Storage is optional; secrets never enter it. */ }
  return id;
}
export function storedCredential(config: ClientConfig, role: "participant" | "attestor"): Uint8Array<ArrayBuffer> | undefined {
  try { const encoded = localStorage.getItem(`stadtstack/${config.municipalityId}/${role}/credential`); return encoded ? new Uint8Array(base64urlnopad.decode(encoded)) : undefined; } catch { return undefined; }
}
export async function runAction(button: HTMLButtonElement, status: HTMLElement, action: () => Promise<void>): Promise<void> {
  button.disabled = true;
  try { await action(); } catch (error) { status.textContent = errorMessage(error); } finally { button.disabled = false; }
}
const ERROR_MESSAGES: Readonly<Record<string, string>> = {
  prf_unavailable: "Dieser Passkey unterstützt die sichere Schlüsselfunktion (PRF) nicht. Geeignet sind zum Beispiel Chrome auf Android mit Google Passwortmanager, Safari ab Version 18 auf iOS/iPadOS 18 oder macOS 15 mit iCloud-Schlüsselbund sowie Chrome oder Edge mit einem PRF-fähigen FIDO2-Sicherheitsschlüssel. Unter Windows kann ein solcher Sicherheitsschlüssel nötig sein. Nicht jeder Passkey und Browser unterstützt PRF. Es gibt keinen unsicheren Ersatz. Versuche ein anderes unterstütztes Gerät.",
  subject_code_invalid: "Der Code ist ungültig oder gehört zu einer anderen Gemeinde. Bitte kopiere den vollständigen Code unverändert.",
  commitment_locked: "Eine Umfrage ist noch mit deinem alten Schlüssel offen. Ein neuer Schlüssel kann erst danach aktiviert werden.",
  evidence_already_used: "Dieser Nachweis wird bereits verwendet. Bitte wende dich an den Betreiber dieses Angebots.",
  duplicate_nullifier: "Du hast an dieser Umfrage bereits teilgenommen.",
  election_not_open: "Diese Umfrage ist noch nicht geöffnet oder bereits beendet.",
  commitment_not_anchored: "Du stehst nicht in der Liste dieser Umfrage. Du hast dich möglicherweise erst nach ihrer Einrichtung angemeldet. Bei späteren Umfragen kannst du teilnehmen.",
  auth_replayed: "Diese Anfrage wurde bereits verwendet. Bitte warte kurz und versuche es erneut.",
  auth_invalid: "Die Anmeldung konnte nicht geprüft werden. Bitte prüfe die Uhrzeit deines Geräts und melde dich erneut an.",
  eligibility_inactive: "Deine Teilnahmeberechtigung ist noch nicht aktiv oder wurde widerrufen.",
  attestation_invalid: "Die Bestätigung passt nicht zur aktuellen Regel oder dein Prüfschlüssel ist nicht mehr freigegeben.",
  attestation_signature_invalid: "Die Unterschrift konnte nicht geprüft werden. Melde dich bitte erneut an.",
  rate_limited: "Zu viele Anfragen. Bitte warte kurz.", verification_busy: "Die Prüfung ist ausgelastet. Bitte versuche es später erneut.",
  proof_invalid: "Der Nachweis wurde nicht angenommen. Bitte versuche es erneut oder wende dich an den Betreiber dieses Angebots.",
  eudi_expired: "Die Wallet-Anfrage ist abgelaufen. Bitte starte eine neue Anfrage.",
  commitment_already_enrolled: "Dieser Stimmenschlüssel ist bereits einer anderen Anmeldung zugeordnet. Bitte wende dich an den Betreiber dieses Angebots.",
  auth_required: "Bitte melde dich zuerst mit deinem Passkey an.",
  auth_url_invalid: "Die Adresse dieses Angebots ist nicht richtig eingerichtet. Bitte informiere den Betreiber dieses Angebots.",
  election_unknown: "Diese Umfrage ist nicht mehr verfügbar. Bitte aktualisiere die Umfragen.",
  attestor_adapter_unavailable: "Dieses Angebot nutzt hier keine persönliche Prüfung.",
  request_url_invalid: "Die Anfrageadresse ist ungültig. Bitte lade die Seite neu.",
  content_type_invalid: "Die Anfrage konnte nicht gelesen werden. Bitte lade die Seite neu.",
  body_too_large: "Die Anfrage ist zu groß und wurde nicht angenommen. Bitte informiere den Betreiber dieses Angebots.",
  json_invalid: "Die Anfrage konnte nicht gelesen werden. Bitte lade die Seite neu.",
  enrollment_request_invalid: "Die Anmeldung ist ungültig. Bitte lade die Seite neu und melde dich erneut an.",
  commitment_invalid: "Der Stimmenschlüssel ist ungültig. Bitte melde dich erneut mit deinem Passkey an.",
  ballot_invalid: "Die Antwort ist ungültig und wurde nicht angenommen. Bitte versuche es erneut.",
  choice_invalid: "Diese Antwortmöglichkeit ist nicht gültig. Bitte aktualisiere die Umfrage.",
  signal_mismatch: "Der Nachweis passt nicht zur Antwort. Es wurde keine Stimme angenommen.",
  field_invalid: "Der Nachweis enthält ungültige Werte. Es wurde keine Stimme angenommen.",
  election_id_invalid: "Die Umfrageadresse ist ungültig. Bitte aktualisiere die Umfragen.",
  election_id_mismatch: "Die Antwort passt nicht zur Umfrage. Es wurde keine Stimme angenommen.",
  tally_not_closed: "Diese Umfrage ist noch nicht beendet. Das Ergebnis wird erst danach veröffentlicht.",
  tally_unavailable: "Das Ergebnis ist noch nicht veröffentlicht. Bitte versuche es später erneut.",
  eudi_request_invalid: "Die Wallet-Anfrage ist ungültig. Bitte starte sie erneut.",
  eudi_transaction_not_found: "Diese Wallet-Anfrage wurde nicht gefunden. Bitte starte eine neue Anfrage.",
  verifier_unavailable: "Der Wallet-Testprüfdienst ist gerade nicht erreichbar. Bitte versuche es später erneut.",
  verifier_response_invalid: "Der Wallet-Testprüfdienst hat keine gültige Antwort geliefert. Bitte versuche es später erneut.",
};
export function errorMessage(error: unknown): string {
  if (error instanceof DOMException && error.name === "NotAllowedError") return "Die Passkey-Anfrage wurde abgebrochen oder dein Gerät unterstützt sie nicht. Versuche es erneut.";
  const code = error instanceof Error ? error.message : "request_failed";
  if (code.startsWith("chain_") || code === "anchor_root_mismatch") return "Die Umfragedaten stimmen nicht mit dem öffentlichen Register überein. Es wurde keine Stimme gesendet. Bitte informiere den Betreiber dieses Angebots.";
  if (code.startsWith("eligibility_")) return "Deine Teilnahmeberechtigung ist noch nicht aktiv, abgelaufen oder widerrufen. Bitte lasse sie erneut bestätigen.";
  return ERROR_MESSAGES[code] ?? "Das hat nicht geklappt. Bitte versuche es erneut. Wenn das Problem bleibt, wende dich an den Betreiber dieses Angebots.";
}
