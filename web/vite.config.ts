import { defineConfig, loadEnv, type Plugin } from "vite";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL(".", import.meta.url));
const repo = fileURLToPath(new URL("..", import.meta.url));
// Pinned bb.js browser builds still use Buffer for byte-array conversion and
// download CRS from a third-party origin. Keep the browser dependency boundary
// local without a global Node polyfill; Uint8Array is the cbind binary contract.
function browserProverAssets(): Plugin {
  return {
    name: "stadtstack-browser-prover-assets", enforce: "pre",
    transform(code, id) {
      if (id.endsWith("/@aztec/bb.js/dest/browser/barretenberg/backend.js")) {
        return code.replace("import { Buffer } from 'buffer';", "").replaceAll("Buffer.from(this.acirUncompressedBytecode)", "this.acirUncompressedBytecode").replaceAll("Buffer.from([])", "new Uint8Array(0)").replaceAll("Buffer.from(bytecode)", "bytecode").replaceAll("Buffer.from(witness)", "witness").replaceAll("Buffer.from(vk)", "vk");
      }
      if (id.endsWith("/@aztec/bb.js/dest/browser/crs/net_crs.js")) return code.replaceAll("https://crs.aztec.network/", "/assets/crs/");
      if (id.endsWith("/@aztec/bb.js/dest/browser/barretenberg_wasm/fetch_code/browser/index.js")) {
        // bb.js embeds gzip WASM in a same-origin JS module but fetches its data:
        // URL. Decode those embedded bytes directly: CSP connect-src 'self'
        // deliberately does not permit fetching data: URLs.
        return code.replace("const res = await fetch(url);", "").replace("const maybeCompressedData = await res.arrayBuffer();", "const maybeCompressedData = url.startsWith('data:application/gzip;base64,') ? Uint8Array.from(atob(url.slice('data:application/gzip;base64,'.length)), c => c.charCodeAt(0)).buffer : await (await fetch(url)).arrayBuffer();");
      }
    },
  };
}
export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, repo, "VITE_");
  return {
    root, plugins: [browserProverAssets()], assetsInclude: ["**/*.wasm"],
    optimizeDeps: { exclude: ["@aztec/bb.js", "@noir-lang/noir_js", "@noir-lang/acvm_js", "@noir-lang/noirc_abi"] },
    worker: { format: "es", plugins: () => [browserProverAssets()] },
    build: { target: "esnext", outDir: "dist", emptyOutDir: true, assetsInlineLimit: 0, rolldownOptions: { input: { participant: `${root}index.html`, attestor: `${root}pruefung.html` } } },
    server: { host: "localhost", fs: { allow: [repo] }, proxy: { "/v1": { target: env.VITE_API_TARGET || "http://127.0.0.1:8787", changeOrigin: true } }, headers: { "Cross-Origin-Opener-Policy": "same-origin", "Cross-Origin-Embedder-Policy": "require-corp" } },
    preview: { host: "localhost", headers: { "Cross-Origin-Opener-Policy": "same-origin", "Cross-Origin-Embedder-Policy": "require-corp" } },
  };
});
