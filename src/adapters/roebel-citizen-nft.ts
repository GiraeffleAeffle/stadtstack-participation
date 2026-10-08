/**
 * Independent MIT implementation of the public CitizenNFTv2 interface; no Röbel
 * implementation is imported. Sources (read-only, 2026-10-08):
 * https://raw.githubusercontent.com/Roebel-Labs/Roebel-App/main/packages/blockchain/src/index.ts
 * https://raw.githubusercontent.com/Roebel-Labs/Roebel-App/main/contracts/governor-contract/contracts/verification-system/CitizenNFTv2.sol
 * Public ABI: isActive(address) view returns (bool).
 * Gnosis example policy config (re-pin the hash before deployment):
 * { kind: "roebel_citizen_nft_v1", chainId: 100,
 *   contractAddress: "0x59aa26f499d7c2b3ec2c8524ed06f54fc4e85de5",
 *   expectedCodeHash: "0x952276d2d6da4bfe3ed3dbc39f6745f2421b01ad476c286cb7a6fa166c7e4218",
 *   blockTag: "latest", walletProofMaxAgeSeconds: 300 }
 * Observed with cast codehash; cast call isActive(address)(bool) with the zero
 * address returned false at https://rpc.gnosischain.com.
 *
 * EIP-191 personal_sign text is exactly two lines, with no trailing newline:
 * stadtstack-participation/wallet-proof/v1
 * <canonical JSON of { municipalityId, policyVersion, subjectPubkey, purpose,
 *                     requestId, issuedAt }>
 * `purpose` is the complete seam object, not just its kind. Evidence has exactly
 * { wallet, signature, issuedAt }. Future timestamps and expired proofs fail.
 */
import { createPublicClient, http, keccak256, parseAbi } from "viem";
import type { Address, Hex } from "viem";
import { canonical, exact, isSafeNonNegativeInteger, snapshot } from "../shared/canonical.ts";
import { fail } from "../shared/errors.ts";
import { EVM_ADDRESS, isBytes32 } from "../shared/ids.ts";
import type { EligibilityAdapter, EligibilityCheckInput, EligibilityDecision, EligibilityRecheckInput } from "../shared/seams.ts";

export type RoebelCitizenNftConfig = Readonly<{
  kind: "roebel_citizen_nft_v1";
  chainId: number;
  contractAddress: Address;
  expectedCodeHash: Hex;
  blockTag: "latest" | "safe" | "finalized";
  walletProofMaxAgeSeconds: number;
}>;

export function validateRoebelCitizenNftConfig(value: unknown): RoebelCitizenNftConfig {
  const config = exact(snapshot(value), ["kind", "chainId", "contractAddress", "expectedCodeHash", "blockTag", "walletProofMaxAgeSeconds"], "adapter_config_invalid");
  if (config.kind !== "roebel_citizen_nft_v1" || !isSafeNonNegativeInteger(config.chainId) || config.chainId === 0 ||
      typeof config.contractAddress !== "string" || !EVM_ADDRESS.test(config.contractAddress) || /^0x0{40}$/u.test(config.contractAddress) ||
      !isBytes32(config.expectedCodeHash) ||
      (config.blockTag !== "latest" && config.blockTag !== "safe" && config.blockTag !== "finalized") ||
      !isSafeNonNegativeInteger(config.walletProofMaxAgeSeconds) || config.walletProofMaxAgeSeconds === 0) fail("adapter_config_invalid");
  return config as RoebelCitizenNftConfig;
}

export function walletProofMessage(input: Pick<EligibilityCheckInput, "municipalityId" | "policyVersion" | "subjectPubkey" | "purpose" | "requestId">, issuedAt: number): string {
  return `stadtstack-participation/wallet-proof/v1\n${canonical({ municipalityId: input.municipalityId, policyVersion: input.policyVersion, subjectPubkey: input.subjectPubkey, purpose: input.purpose, requestId: input.requestId, issuedAt })}`;
}

const citizenAbi = parseAbi(["function isActive(address wallet) view returns (bool)"]);

export class RoebelCitizenNftAdapter implements EligibilityAdapter {
  readonly kind = "roebel_citizen_nft_v1";
  readonly config: RoebelCitizenNftConfig;
  private readonly rpcUrl: string;
  private readonly timeoutMs: number;

  constructor(config: RoebelCitizenNftConfig, runtime: Readonly<{ rpcUrl: string; timeoutMs?: number }>) {
    this.config = validateRoebelCitizenNftConfig(config);
    const url = new URL(runtime.rpcUrl);
    if ((url.protocol !== "https:" && url.protocol !== "http:") || url.username || url.password) fail("rpc_config_invalid");
    this.rpcUrl = url.href;
    this.timeoutMs = runtime.timeoutMs ?? 5_000;
    if (!Number.isSafeInteger(this.timeoutMs) || this.timeoutMs <= 0) fail("rpc_config_invalid");
  }

  async check(input: EligibilityCheckInput): Promise<EligibilityDecision> {
    let evidence: Record<string, unknown>;
    try { evidence = exact(snapshot(input.evidence), ["wallet", "signature", "issuedAt"], "wallet_proof_invalid"); }
    catch { return { state: "inactive", reason: "wallet_proof_invalid" }; }
    if (typeof evidence.wallet !== "string" || !/^0x[0-9a-fA-F]{40}$/u.test(evidence.wallet) ||
        typeof evidence.signature !== "string" || !/^0x(?:[0-9a-fA-F]{2})+$/u.test(evidence.signature) ||
        !isSafeNonNegativeInteger(evidence.issuedAt) || !isSafeNonNegativeInteger(input.now) ||
        evidence.issuedAt > input.now || input.now - evidence.issuedAt > this.config.walletProofMaxAgeSeconds) {
      return { state: "inactive", reason: "wallet_proof_invalid" };
    }
    return this.evaluate(input, evidence.wallet.toLowerCase() as Address, {
      message: walletProofMessage(input, evidence.issuedAt), signature: evidence.signature as Hex,
    });
  }

  async recheck(input: EligibilityRecheckInput): Promise<EligibilityDecision> {
    if (!EVM_ADDRESS.test(input.evidenceRef) || !isSafeNonNegativeInteger(input.now)) return { state: "inactive", reason: "evidence_ref_invalid" };
    return this.evaluate(input, input.evidenceRef as Address);
  }

  private async evaluate(input: EligibilityCheckInput | EligibilityRecheckInput, wallet: Address, proof?: Readonly<{ message: string; signature: Hex }>): Promise<EligibilityDecision> {
    const signal = AbortSignal.any([input.signal, AbortSignal.timeout(this.timeoutMs)]);
    const client = createPublicClient({ transport: http(this.rpcUrl, { retryCount: 0, timeout: this.timeoutMs, fetchOptions: { signal } }) });
    try {
      signal.throwIfAborted();
      if (await client.getChainId() !== this.config.chainId) return { state: "inactive", reason: "chain_mismatch" };
      const block = await client.getBlock({ blockTag: this.config.blockTag });
      if (block.number === null) return { state: "inactive", reason: "rpc_failed" };
      const blockNumber = block.number;
      const code = await client.getCode({ address: this.config.contractAddress, blockNumber });
      if (!code || code === "0x" || keccak256(code) !== this.config.expectedCodeHash) return { state: "inactive", reason: "code_hash_mismatch" };
      // EOA-first avoids viem's auto-mode ECDSA fallback after an RPC error.
      // Contract and counterfactual wallets still use its on-chain verifier.
      if (proof && !await client.verifyMessage({ address: wallet, ...proof, blockNumber, mode: "eoa" })) return { state: "inactive", reason: "wallet_proof_invalid" };
      const active = await client.readContract({ address: this.config.contractAddress, abi: citizenAbi, functionName: "isActive", args: [wallet], blockNumber });
      signal.throwIfAborted();
      return active ? { state: "active", effectiveAt: input.now, validUntil: null, evidenceRef: wallet } : { state: "inactive", reason: "citizen_inactive" };
    } catch {
      return { state: "inactive", reason: "rpc_failed" };
    }
  }
}
