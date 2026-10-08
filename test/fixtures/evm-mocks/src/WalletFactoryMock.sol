// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {WalletMock} from "./WalletMock.sol";

// Test-only counterfactual deployment for ERC-6492 eth_call simulation.
contract WalletFactoryMock {
    function deploy(bytes32 salt, bytes32 approvedHash) external returns (address) {
        WalletMock wallet = new WalletMock{salt: salt}();
        wallet.approve(approvedHash);
        return address(wallet);
    }
}
