// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

// Test-only independent implementation of the public eligibility interface.
contract CitizenMock {
    mapping(address => bool) private active;

    function setActive(address wallet, bool value) external {
        active[wallet] = value;
    }

    function isActive(address wallet) external view returns (bool) {
        return active[wallet];
    }
}
