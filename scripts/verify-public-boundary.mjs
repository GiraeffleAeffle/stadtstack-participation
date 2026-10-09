#!/usr/bin/env node
// Fail-closed check of everything that would be published: tracked files plus
// untracked files that are not ignored. It looks for secrets, local paths,
// operations hosts, forbidden file types and unexpected binaries. It prints
// paths and rule names only, never matched values.
import { execFileSync } from "node:child_process";
import { readFileSync, statSync } from "node:fs";

const root = execFileSync("git", ["rev-parse", "--show-toplevel"], { encoding: "utf8" }).trim();
const list = (args) => execFileSync("git", args, { cwd: root, encoding: "utf8" }).split("\n").filter(Boolean);
const files = [...new Set([...list(["ls-files"]), ...list(["ls-files", "--others", "--exclude-standard"])])].sort();

const forbiddenPaths = [
  [/(^|\/)\.env(\.|$)(?!example$)/u, "env-file"],
  [/(^|\/)\.secrets\//u, "secrets-dir"],
  [/\.(pem|key|p12|pfx|keystore)$/u, "key-file"],
  [/(^|\/)(tfplan|.*\.tfstate.*)$/u, "terraform-state"],
  [/(^|\/)\.terraform\//u, "terraform-dir"],
  [/(^|\/)node_modules\//u, "node-modules"],
  [/\.(sqlite|db)(-wal|-shm)?$/u, "database-file"],
  [/(^|\/)(kubeconfig|talosconfig)/u, "cluster-config"],
];

// Well-known public development keys (Anvil/Hardhat accounts 0 and 1).
const publicDevKeys = new Set([
  "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
  "59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d",
]);

const contentRules = [
  // A key has a base64 body; code that only names the header (parsers, checks) does not.
  [/-----BEGIN [A-Z ]*PRIVATE KEY-----\r?\n[A-Za-z0-9+/=]{40,}/u, "pem-private-key"],
  // Base64 of "-----BEGIN", assembled so this file does not match itself.
  [new RegExp(["LS0tLS1", "CRUdJTi"].join(""), "u"), "base64-pem"],
  [/sk-(?:ant-|proj-|or-)[A-Za-z0-9_-]{20,}/u, "llm-api-key"],
  [/gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,}/u, "github-token"],
  [/AKIA[0-9A-Z]{16}/u, "aws-key"],
  [/xox[abpr]-[A-Za-z0-9-]{10,}/u, "slack-token"],
  [/AIza[0-9A-Za-z_-]{35}/u, "google-key"],
  [/eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/u, "jwt"],
  [/tskey-[a-z]+-[A-Za-z0-9]{10,}/u, "tailscale-key"],
  [/AGE-SECRET-KEY-1[0-9A-Z]{20,}/u, "age-key"],
  [/postgres(?:ql)?:\/\/[^:/\s]+:[^@/\s]{6,}@/u, "database-url-with-password"],
  [/\/Users\/[A-Za-z]|\/home\/[a-z][a-z0-9_-]*\//u, "local-path"],
  [/agentcart\.eu|\.svc\.cluster\.local|vercel\.app|ts\.net\b/u, "operations-host"],
  // Reserved documentation names (RFC 2606) are not addresses.
  [/[A-Za-z0-9._%+-]+@(?!users\.noreply\.github\.com|example\.(?:org|com|net)|[A-Za-z0-9.-]*\.(?:example|test|invalid|localhost)\b)[A-Za-z0-9.-]+\.[a-z]{2,}/u, "email-address"],
];
const hexKeyAssignment = /(?:PRIVATE_KEY|PRIVKEY|SECRET_KEY|SEED|MNEMONIC)[^\n]{0,24}?(?:0x)?([0-9a-fA-F]{64})/gu;
// Verification key, the public BN254 CRS prefix (provenance.json pins source and
// hashes) and the self-hosted OFL fonts (fonts/LICENSE.md names their sources).
const binaryAllowed = [/^artifacts\/[^/]+\.vk$/u, /^web\/public\/assets\/crs\/g[12]\.dat$/u, /^web\/src\/fonts\/[a-z0-9-]+\.woff2$/u];
const maxBytes = 1_048_576;

const findings = [];
for (const path of files) {
  for (const [pattern, rule] of forbiddenPaths) if (pattern.test(path)) findings.push([path, rule]);
  let stat;
  try { stat = statSync(`${root}/${path}`); } catch { continue; }
  if (!stat.isFile()) continue;
  if (stat.size > maxBytes) findings.push([path, "file-over-1MiB"]);
  const bytes = readFileSync(`${root}/${path}`);
  if (bytes.includes(0)) {
    if (!binaryAllowed.some((pattern) => pattern.test(path))) findings.push([path, "unexpected-binary"]);
    continue;
  }
  const text = bytes.toString("utf8");
  for (const [pattern, rule] of contentRules) if (pattern.test(text)) findings.push([path, rule]);
  for (const match of text.matchAll(hexKeyAssignment)) {
    if (!publicDevKeys.has(match[1].toLowerCase())) findings.push([path, "hex-key-assignment"]);
  }
  if (path.endsWith(".sol") && !/^\/\/ SPDX-License-Identifier: /mu.test(text)) findings.push([path, "missing-spdx"]);
}

if (findings.length) {
  for (const [path, rule] of findings) console.error(`${rule}\t${path}`);
  console.error(`public boundary: ${findings.length} finding(s) in ${files.length} files`);
  process.exit(1);
}
console.log(`public boundary: ok (${files.length} files)`);
