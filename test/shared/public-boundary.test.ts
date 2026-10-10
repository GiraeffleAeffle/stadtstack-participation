import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { test } from "node:test";
import type { TestContext } from "node:test";
import { fileURLToPath } from "node:url";

const sourceRoot = fileURLToPath(new URL("../../", import.meta.url));
const icons = ["web/public/assets/apple-touch-icon.png", "web/public/assets/favicon.ico"];

function setup(t: TestContext) {
  const root = mkdtempSync(join(tmpdir(), "participation-boundary-"));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  execFileSync("git", ["init", "--quiet", root]);
  for (const path of icons) {
    mkdirSync(dirname(join(root, path)), { recursive: true });
    copyFileSync(join(sourceRoot, path), join(root, path));
  }
  execFileSync("git", ["add", "web"], { cwd: root });
  const scan = () => spawnSync(process.execPath, [join(sourceRoot, "scripts/verify-public-boundary.mjs")], { cwd: root, encoding: "utf8" });
  return { root, scan };
}

test("public boundary admits both reviewed raster icons", (t) => {
  const { scan } = setup(t);
  const result = scan();
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /public boundary: ok/);
});

for (const path of icons) {
  test(`public boundary rejects untracked copies outside the approved path: ${path}`, (t) => {
    const { root, scan } = setup(t);
    const extra = path.replace("/assets/", "/assets/extra-");
    copyFileSync(join(root, path), join(root, extra));
    const result = scan();
    assert.equal(result.status, 1);
    assert.ok(result.stderr.includes(`unexpected-binary\t${extra}`));
  });

  test(`public boundary rejects modified bytes at the approved path: ${path}`, (t) => {
    const { root, scan } = setup(t);
    const file = join(root, path);
    writeFileSync(file, Buffer.concat([readFileSync(file), Buffer.from("unreviewed") ]));
    const result = scan();
    assert.equal(result.status, 1);
    assert.ok(result.stderr.includes(`public-icon-hash-mismatch\t${path}`));
  });

  test(`public boundary rejects text replacing an approved icon: ${path}`, (t) => {
    const { root, scan } = setup(t);
    writeFileSync(join(root, path), "not the approved image");
    const result = scan();
    assert.equal(result.status, 1);
    assert.ok(result.stderr.includes(`public-icon-hash-mismatch\t${path}`));
  });
}

test("public boundary retains file-size, forbidden-path and content checks", (t) => {
  const { root, scan } = setup(t);
  writeFileSync(join(root, icons[0]), Buffer.alloc(1_048_577));
  writeFileSync(join(root, ".env"), Buffer.from([0, 1, 2]));
  const token = ["gh", "p_", "x".repeat(30)].join("");
  writeFileSync(join(root, "notes.txt"), token);
  const result = scan();
  assert.equal(result.status, 1);
  assert.ok(result.stderr.includes(`file-over-1MiB\t${icons[0]}`));
  assert.ok(result.stderr.includes(`public-icon-hash-mismatch\t${icons[0]}`));
  assert.ok(result.stderr.includes("env-file\t.env"));
  assert.ok(result.stderr.includes("github-token\tnotes.txt"));
  assert.ok(!result.stderr.includes(token));
});
