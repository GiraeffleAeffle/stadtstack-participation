// MIT. Run after: forge build --root test/fixtures/evm-mocks
import { readFile, writeFile } from "node:fs/promises";
const artifacts = {};
for (const name of ["CitizenMock", "WalletMock", "WalletFactoryMock"]) {
  const artifact = JSON.parse(await readFile(new URL(`out/${name}.sol/${name}.json`, import.meta.url), "utf8"));
  artifacts[name] = { abi: artifact.abi, bytecode: artifact.bytecode.object };
}
await writeFile(new URL("bytecode.json", import.meta.url), `${JSON.stringify(artifacts, null, 2)}\n`);
