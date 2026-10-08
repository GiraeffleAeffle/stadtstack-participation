import assert from "node:assert/strict";
import test from "node:test";
import { mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createRuntimeAdapter } from "../../src/server.ts";
import { parseIssuerPolicy } from "../../src/issuer/policy.ts";
import { openDatabase } from "../../src/shared/db.ts";
import { policyInput } from "../issuer/fixtures.ts";

test("EUDI runtime requires a sufficiently long uniqueness key in a distinct resolved file", async () => {
  const directory = await mkdtemp(join(tmpdir(), "stadtstack-eudi-keys-"));
  const db = openDatabase(":memory:");
  try {
    const policy = parseIssuerPolicy({ ...policyInput(), adapter: { kind: "eudi_pid_v1", verifierBaseUrl: "https://verifier.example",
      acceptedVcts: ["urn:eudi:pid:1"], acceptedAddresses: [{ postalCode: "15344", locality: "Strausberg" }], transactionTtlSeconds: 300, validitySeconds: 3600 } });
    const signingFile = join(directory, "issuer.pem");
    const uniquenessFile = join(directory, "uniqueness.bin");
    const alias = join(directory, "alias.bin");
    // Synthetic local runtime inputs only; no production key files are read.
    await writeFile(signingFile, new Uint8Array(32).fill(1));
    await writeFile(uniquenessFile, new Uint8Array(32).fill(2));
    await symlink(signingFile, alias);
    await assert.rejects(createRuntimeAdapter(policy, db, {}), /server_configuration_invalid/u);
    for (const file of [signingFile, join(directory, ".", "issuer.pem"), alias]) {
      await assert.rejects(createRuntimeAdapter(policy, db, { ISSUER_SIGNING_KEY_FILE: signingFile, EUDI_UNIQUENESS_KEY_FILE: file }), /eudi_uniqueness_key_invalid/u);
    }
    const adapter = await createRuntimeAdapter(policy, db, { ISSUER_SIGNING_KEY_FILE: signingFile, EUDI_UNIQUENESS_KEY_FILE: uniquenessFile });
    assert.equal(adapter.kind, "eudi_pid_v1");
    await writeFile(uniquenessFile, new Uint8Array(31));
    await assert.rejects(createRuntimeAdapter(policy, db, { ISSUER_SIGNING_KEY_FILE: signingFile, EUDI_UNIQUENESS_KEY_FILE: uniquenessFile }), /eudi_uniqueness_key_invalid/u);
  } finally { db.close(); await rm(directory, { recursive: true, force: true }); }
});
