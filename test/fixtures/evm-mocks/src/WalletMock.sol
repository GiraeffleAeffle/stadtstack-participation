// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

// Test-only ERC-1271 wallet accepting one explicitly authorised message hash.
contract WalletMock {
    bytes32 private approvedHash;

    function approve(bytes32 hash) external {
        approvedHash = hash;
    }

    function isValidSignature(bytes32 hash, bytes calldata signature) external view returns (bytes4) {
        return hash == approvedHash && signature.length == 65 && signature[0] == 0x42
            ? bytes4(0x1626ba7e) : bytes4(0xffffffff);
    }
}
