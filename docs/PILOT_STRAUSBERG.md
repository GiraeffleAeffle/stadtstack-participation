# Strausberg advisory participation pilot

This is a proposed, gated staging pilot in Strausberg, Brandenburg. It is not an
official election, representative survey or commitment to municipal spending.
No municipal partnership, controller, named attestor or poll date is assumed.
Deployment steps are in [DEPLOYMENT.md](DEPLOYMENT.md); poll/Safe operations are
in [OPERATIONS.md](OPERATIONS.md); security limits are in
[THREAT_MODEL.md](THREAT_MODEL.md). Do not recruit until the owner completes the
decisions below and the exact-host rehearsal passes.

## Owner decisions before recruitment

Record a dated approval with reasons, responsible people and a publication copy.

1. **Controller and authority:** decide whether the municipality, project owner
   or another organisation determines purposes/means; obtain agreement rather
   than calling the city the controller by implication. Name controller contact,
   privacy contact, legal basis, processors and venue/support owner. Consult the
   responsible data-protection officer. Real people must not be enrolled until
   these disclosures and deletion/incident responsibilities are settled.
2. **Eligibility basis, proposal:** main residence in the municipality of
   Strausberg; minimum age **16**; **any nationality**; no locality restriction.
   Proposed reason: include young residents and everyone affected by local
   amenities, while keeping the pilot's catchment clear. This is a civic pilot
   choice, not a statement of legal electoral entitlement. Owner decides and
   cites an actual policy/legal/community reason; do not inherit official
   election nationality rules or use postal code as municipality identity.
3. **Attestors:** appoint **three named independent people**, confirm attendance,
   training, key custody/recovery, conflicts and the attestors' own participant
   subject keys. Proposal **K=2 distinct checks**, **R=1 revocation**: two people
   catch mistakes; one authorised person can stop mistaken eligibility quickly.
   Owner explicitly accepts the risk of one person censoring eligibility and
   two colluding people admitting duplicates. Proposal attestation window 7 days
   and validity 30 days, covering the enrollment/window; choose precise seconds
   and `[validFrom, validUntil)` intervals. No self-attestation.
4. **Documents and duplicate-person process:** agree what independently shows
   the person, birth date/age and **current main residence**: identity card, or
   passport plus current municipal registration certificate. Set a documented
   recency rule for residence evidence and an accessible escalation for people
   without the usual document. Inspect only; no scan, photo, photocopy, address,
   document number or date of birth recorded. Record only supported document-kind
   labels. A foreign passport is not a rejection reason under nationality any.
   Do not claim that two signatures prove human uniqueness: multiple passkeys
   can otherwise get multiple attestations. Decide a proportionate approved
   operational duplicate check that does not invent an undocumented PII ledger;
   if it cannot be resolved, limit to a supervised rehearsal and disclose that
   limitation rather than advertise one-person-one-vote assurance.
5. **Key-to-policy ceremony:** each attestor opens `/pruefung` on the exact host,
   creates a PRF-capable passkey, records their **public** Ed25519 key and sends
   it to the operator through an authenticated second channel. Each attestor
   also opens `/` with their participant passkey and sends the subject code
   shown there: the policy requires at least one declared own subject key per
   attestor (`ownSubjectPubkeys`), so nobody can confirm themselves. Operator
   compares fingerprints live with each person, checks keys differ from the
   issuer and each other, and inserts them with IDs/own subject keys/validity
   into the CLI adapter JSON. Validate, publish a new versioned policy and have
   all three independently review `/v1/policy`; no private key ever leaves the
   device. Changing the hostname invalidates this ceremony. Rehearse key
   loss/revocation.
6. **Poll:** choose one candidate below, owner-approved neutral question/options,
   information source, support venue, enrollment cutoff, opens/closes timestamps
   and timezone, target invitations and minimum publishable anonymity set.
   Decide before launch what happens with too few ballots, tie, outage or
   incomplete publication. Suggested minimum 20 participants is a privacy
   discussion starting point, not a mathematical anonymity guarantee.
7. **Retention/publication:** approve the concrete schedule below or replace it
   with a justified schedule; publish it before collection. Set who receives the
   advisory result and when they will acknowledge it. Neither code nor this
   document supplies a legal basis or automatic retention enforcement.

## Candidate topics grounded in Stadtstack data

Source evidence: owner's MIT `rental-deposit-hackathon/stadtstack-data/out/cities/
strausberg/feed.json`, generated **28 September 2026**. Feed definitions in
`stadtstack-data/src/feeds.ts` name Stadt Strausberg press RSS
<https://www.stadt-strausberg.de/aktuelles/feed/>. These are factual pointers,
not survey mandates or licenses to copy photos/text. The source article URLs
were opened read-only on 8 October and redirect to the city's news archive
anchors listed below. Recheck status/municipal competence before setting dates.

| Candidate | Source / evidence | Why advisory; suggested neutral German question |
| --- | --- | --- |
| Kulturpark everyday use | Stadt Strausberg, “Kulturpark Strausberg: Zweiter Bauabschnitt wird zum Monatsende fertiggestellt”, 24 Sep; [original URL](https://www.stadt-strausberg.de/aktuelles/kulturpark-strausberg-zweiter-bauabschnitt-wird-zum-monatsende-fertiggestellt/) → [archive #30386](https://www.stadt-strausberg.de/aktuelles/#post-30386). Reports sport/bathing opening from 3 Oct, paths/seating and future service building/stage. | Collect priorities for feedback on use, not a vote to override an approved building project. “Zu welchem Bereich des Kulturparks soll die Stadt zuerst Rückmeldungen zur Nutzung sammeln?” Options: Wege und Barrierefreiheit; Sport und Bewegung; Aufenthalt und Sitzmöglichkeiten; Keiner davon / keine Präferenz. |
| Bicycle reuse and repair | Stadt Strausberg, “Fahrrad- und Fahrradteileflohmarkt im Kunstparkhaus”, 24 Sep; [original URL](https://www.stadt-strausberg.de/aktuelles/fahrrad-und-fahrradteileflohmarkt-im-kunstparkhaus/) → [archive #30384](https://www.stadt-strausberg.de/aktuelles/#post-30384). Reports 10 Oct flea market, used bikes and coding service. | Local, tangible and low-stakes: ask about future information/support, not compel a private organiser to repeat an event. “Welche Information zu Fahrradangeboten in Strausberg wäre für dich am hilfreichsten?” Options: Gebrauchtkauf und Weitergabe; Reparaturmöglichkeiten; Diebstahlschutz und Codierung; Keine davon / keine Präferenz. |
| Future career-information formats | Stadt Strausberg, “30. Ausbildungstag in Strausberg: Mehr als 50 Aussteller informierten über Berufschancen”, 18 Sep; [original URL](https://www.stadt-strausberg.de/aktuelles/30-ausbildungstag-in-strausberg-mehr-als-50-aussteller-informierten-ueber-berufschancen/) → [archive #30358](https://www.stadt-strausberg.de/aktuelles/#post-30358). Reports 12 Sep event, about 450 visitors, training/career changes and seasonal internships. | Young residents can give meaningful feedback without promising jobs or changing school rules. “Welches zusätzliche Angebot zur Berufsorientierung würdest du am ehesten nutzen?” Options: Gespräche mit Betrieben vor Ort; Informationen zu Praktika; Online-Übersicht regionaler Angebote; Keines davon / keine Präferenz. |

These are **proposed questions**, not statements that options are funded or
available. Choose one, check understanding with residents without collecting
choices, balance option length/order, and freeze exact metadata before opening.
Avoid the mayoral runoff/election topic entirely: it risks confusing this
advisory experiment with statutory voting. Do not ask sensitive political,
health or religious questions in a first pilot.

## Timeline and responsibilities

Dates are relative to the owner's chosen launch, not promises.

- **T−21 to T−14 days:** owner/controller approve all decisions, DPIA screening,
  contracts and notices; operator completes owner-only deployment steps; three
  attestors perform public-key ceremony on the exact host. Verify physical
  venue, device PRF support, accessible information and independent review.
- **T−14 to T−7:** supervised rehearsal with clearly separate test subjects/poll;
  exercise two distinct attestations, self-attestation rejection, renewal,
  revocation, lost-passkey limitation, enrollment, Safe open/close, proof/tally
  audit, backup restore and emergency stop. Do not put real identity data in EU
  test wallets. Go/no-go meeting; publish notices and exact schedule afterwards.
- **T−7 to T−1:** enrollment sessions with two independent attestors. Participant
  controls their own screen; no attendee-to-choice checklist. Announce cutoff
  prominently. Complete enrollment before the electorate snapshot.
- **T−1 / snapshot:** operator rechecks eligibility, drafts anchor/metadata and
  Safe batch; independent reviewer checks electorate process, counts, title,
  options, hashes, window and chain ID. Safe signs the open transaction; confirm
  on-chain state before displaying the poll as open. Late enrollments cannot be
  inserted into an immutable open anchor.
- **T to T+7:** proposed seven-day advisory window, support without observing
  choices. Check health/capacity and backups, not request bodies or live votes.
  Record only aggregate incidents. Changing eligibility does not rewrite the
  frozen electorate. Never ask for a participant secret for troubleshooting.
- **After closesAt:** operator builds deterministic tally and Safe close batch;
  reviewer independently verifies proofs/nullifiers/counts/hash against anchor
  and contract. Safe closes; confirm mirror. Publish result within seven days,
  with privacy caveats and a date for the recipient's response.
- **30 days after publication:** proposed end of complaint/support period;
  controller authorises deletion of private live pilot database, keys no longer
  needed and local/offsite copies, after preserving only reviewed public audit
  artifacts. Complete backup deletion too; retained disks need explicit owner
  disposal. Document completion, not a promise of automatic deletion.

## Participant information (German publication draft)

Publish only after replacing unresolved roles/contact/schedule with approved
real details in the surrounding event notice. Rewrite with local participants;
this block is not a substitute for the controller's complete privacy notice.

> **Deine Meinung für Strausberg – freiwilliger Test**
>
> Hier kannst du an einer unverbindlichen Umfrage zu einem Thema in Strausberg
> teilnehmen. Das ist keine Wahl und kein Bürgerentscheid. Das Ergebnis ist eine
> Rückmeldung; es verpflichtet die Stadt zu keiner Entscheidung. Du musst nicht
> teilnehmen und hast dadurch keine Nachteile.
>
> Für diesen Test schlagen wir vor: Hauptwohnsitz in Strausberg, mindestens
> 16 Jahre, jede Staatsangehörigkeit. Die endgültigen Regeln, Termine, der
> Veranstalter und der Datenschutzkontakt stehen in der Einladung und den
> Teilnahmeinformationen. Zwei verschiedene Prüfpersonen sehen sich deine
> Nachweise vor Ort an. Sie fotografieren oder kopieren sie nicht.
>
> Öffne nur **https://mitmachen.stadtstack.eu**. Lege dort einen Passkey auf deinem
> eigenen Gerät an. Dein Gerät muss die benötigte Passkey-Funktion unterstützen;
> wenn das nicht klappt, frage beim angekündigten Hilfetermin nach. Wir speichern
> keinen Ersatz für deinen geheimen Schlüssel. Zeige den angezeigten Teilnahmecode
> beiden Prüfpersonen. Vergleicht die kurze Kennung auf beiden Bildschirmen.
> Nach beiden Prüfungen meldest du dich vor dem angekündigten Stichtag an.
> Während der Umfrage wählst du eine Antwort und sendest sie selbst ab. Gib deinen
> Passkey oder geheimen Schlüssel niemals weiter. Bei Verlust kannst du für eine
> bereits laufende Umfrage möglicherweise nicht mehr teilnehmen.
>
> Gespeichert werden dein öffentlicher Teilnahmeschlüssel, die signierten
> Prüfbestätigungen ohne Dokumentinhalte, dein Berechtigungsnachweis und eine
> technische Kennung für die Teilnahme. Die Prüfbestätigungen enthalten Zeitpunkt
> und Dokumentart, nicht Name, Anschrift, Geburtsdatum oder Ausweisnummer. Die
> Abstimmung speichert Antwort und mathematischen Nachweis ohne Namen,
> Teilnahmeschlüssel oder Abstimmungszeit. Der Betreiber kennt dennoch die
> Verbindung zwischen deiner Anmeldung und der technischen Kennung und sieht
> live Verbindungen. Deshalb können wir keine absolute Anonymität versprechen,
> besonders nicht bei kleinen Gruppen oder beobachteten Geräten.
>
> Veröffentlicht werden die Antwortzahlen und prüfbare technische Nachweise mit
> den einzelnen Antworten ohne Namen. Einmal öffentlich verbreitete Ergebnisse
> lassen sich nicht zuverlässig zurückholen. Die privaten Pilotdaten sollen
> 30 Tage nach der Ergebnisveröffentlichung gelöscht werden; dazu gehören auch
> Sicherungskopien. Die genaue freigegebene Frist und deine Datenschutzrechte
> stehen in der Datenschutzerklärung. Wenn du Fragen hast oder eine Prüfung
> falsch war, nutze den in der Einladung genannten Kontakt. Niemand darf dich
> zwingen, eine bestimmte Antwort zu wählen oder deinen Schlüssel zu zeigen.

## Attestor instructions (German)

> **Vor der Prüfung:** Öffne `/pruefung` nur auf dem vereinbarten Host. Nutze deinen
> eigenen Passkey mit Geräteprüfung. Vergleiche Gemeinde, Regelversion und deine
> freigegebene Kennung mit der veröffentlichten Richtlinie. Bei Abweichungen
> nicht bestätigen, sondern die verantwortliche Person kontaktieren.
>
> **Prüfen:** Erkläre den freiwilligen, unverbindlichen Test. Prüfe persönlich
> die freigegebenen Originalnachweise für Hauptwohnsitz und Mindestalter.
> Staatsangehörigkeit ist beim vorgeschlagenen Modell kein Ausschlussgrund.
> Keine Fotos, Kopien oder Notizen zu Namen, Anschrift, Geburtsdatum oder
> Dokumentnummer. Prüfe keine eigenen Teilnahmeschlüssel und unterschreibe nicht
> für eine andere Prüfperson. Bei Unsicherheit keine Ausnahme erfinden: an die
> vereinbarte Klärungsstelle verweisen.
>
> **Code vergleichen:** Scanne den Teilnahmecode vom Bildschirm der Person.
> Vergleicht beide die kurze Kennung und die Gemeinde. Die Person behält die
> Kontrolle über ihr Gerät. Bestätige erst nach erfolgreicher Prüfung und
> Codevergleich; wähle nur die tatsächlich gesehenen Dokumentarten. Eine zweite,
> andere Prüfperson muss selbst prüfen. Keine Antwort zur Umfrage erfragen oder
> beobachten.
>
> **Fehler und Widerruf:** Melde falsche Bestätigungen oder Schlüsselverlust sofort
> über den vereinbarten Kontakt. Signiere einen Widerruf nur für den geprüften
> richtigen Teilnahmecode und dokumentiere den Vorgang ohne Dokumentinhalte nach
> dem freigegebenen Verfahren. Bei R=1 reicht ein berechtigter Widerruf. Er ändert
> den eingefrorenen Kreis einer laufenden Umfrage nicht nachträglich. Eine neue
> Freigabe braucht erneut K frische Bestätigungen; alte Bestätigungen verlängern
> sich nicht. Niemals private Schlüssel an den Betreiber schicken.

## Data protection and DPIA outline

This is pseudonymous personal-data processing, not a personal-data-free system.
There is **no automatic TTL deletion** of the complete pilot database. Until the
controller performs disposal, stored private records persist; receipt expiry and
attestation expiry are authorisation windows, not erasure. The proposed 30-day
post-publication schedule must be operationally implemented and verified.

| Data / location | Purpose / proposed lifetime |
| --- | --- |
| Public subject keys, subject→commitment and private evidence references, enrollment timestamps; issuer DB | Eligibility/enrollment and duplicate handling; pilot plus 30-day post-publication support window |
| Signed attestations/revocations, attestor IDs/keys, basis/document-kind labels and timestamps | Recheck and dispute handling; same private pilot lifetime |
| Receipts/checksums/status links, adoptions and single-use NIP-98 IDs, EUDI request/ref state if enabled | Evidence/status/replay protection; same lifetime unless a reviewed shorter cleanup applies |
| Anchors, metadata, anonymous ballots (choice, proof, nullifier, signal hash), canonical tally | Public auditability; publish after close, archive as announced, assume public redistribution is indefinite |
| SQLite WAL/SHM/free pages, online snapshots, offsite exports | Same sensitivity as DB; chart keeps 28 successful snapshots, not a fixed seven-day TTL; explicit final disposal of every copy/disk required |
| Live socket IP and transient client limiter keys | Abuse limits in memory, not ballot records; infrastructure logging/dumps can persist these unless owner disables them |
| EUDI attributes (test-only alternative, not this pilot) | Names/birthdate/postal/locality transient for comparison/uniqueness, discarded; keyed uniqueness reference remains private; verifier is an additional external trust/processing boundary |

Before launch: document purpose and necessity, lawful basis and minors' needs;
identify controller/processors (hosting, ingress, RPC, and verifier if any),
locations/transfers, subject rights/contact, retention and access matrix. Map
flows from documents/passkey to pseudonymous enrollment, immutable chain anchor,
plain anonymous ballot and public tally. Evaluate live timing correlation, small
cohorts, attestor collusion/duplicates, device compromise/exclusion, coercion,
key loss, omitted ballots, backups and immutable public disclosures. Record
likelihood/severity, safeguards, residual risks and whether a full DPIA is
required; involve the DPO and supervisory authority when applicable. Plan
incident escalation, notification assessment, requests for access/erasure and
how public redistribution limits erasure. No analytics, participant lists,
request-body logging or hidden PII deduplication ledger. Agree accessible help
that does not let the helper learn or store passkey-derived secrets.

## Publication, stop and rollback

Publish title/question/options, eligibility basis, enrollment cutoff,
opens/closes window, number of admitted anchor members, accepted-ballot counts,
limits and source links alongside **canonical verifiable tally JSON**, anchor,
metadata, circuit/VK identifiers, registry/chain and the on-chain tally hash.
Independent reviewers check proofs, distinct nullifiers, counts and hash; this
cannot prove every attempted/acknowledged vote was included or electorate honesty.
State prominently: advisory, non-representative self-selection, no legal effect.
Do not publish issuer DB, subject-to-commitment mapping, document-kind records,
request order/timestamps or identifying support notes. If the approved minimum
cohort is missed, do not claim safe small-group anonymity; follow the pre-agreed
stop policy before public artifacts are irreversibly disclosed.

Stop admissions/invitations for incorrect basis/key policy, suspected duplicates,
privacy incident, client/proof compromise, lost attestor quorum or chain/mirror
mismatch. Owner records decision, contacts controller and publishes a neutral
notice; no silent denominator change. Emergency shutdown and digest rollback
follow DEPLOYMENT. The registry cannot close before closesAt; never rewrite an
anchor or restore old DB as if ballots were unaffected. A rerun needs a **new
poll ID/window**, fresh review and disclosure, not overwritten results. Preserve
only proportionate secured incident evidence and complete agreed disposal.
