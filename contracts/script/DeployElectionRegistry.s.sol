// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {ElectionRegistry, IMembershipVoteVerifier} from "../src/ElectionRegistry.sol";
import {MembershipVoteVerifier} from "../src/MembershipVoteVerifier.sol";

interface DeploymentVm {
    enum CallerMode { None, Broadcast, RecurrentBroadcast, Prank, RecurrentPrank }
    function envAddress(string calldata name) external returns (address);
    function startBroadcast() external;
    function stopBroadcast() external;
    function readCallers() external returns (CallerMode mode, address sender, address origin);
}

/// @notice Run with Forge; only --broadcast submits the simulated transactions.
/// @dev Uses Forge's selected account, never a private key environment variable.
contract DeployElectionRegistry {
    DeploymentVm private constant VM =
        DeploymentVm(address(uint160(uint256(keccak256("hevm cheat code")))));
    address private constant CONSOLE = 0x000000000000000000636F6e736F6c652e6c6f67;

    function run() external returns (MembershipVoteVerifier verifier, ElectionRegistry registry) {
        address admin = VM.envAddress("ADMIN_ADDRESS");
        address operator = VM.envAddress("OPERATOR_ADDRESS");
        require(admin != address(0) && operator != address(0), "Zero role address");

        VM.startBroadcast();
        (, address deployer,) = VM.readCallers();
        verifier = new MembershipVoteVerifier();
        registry = new ElectionRegistry(admin, operator, IMembershipVoteVerifier(address(verifier)));
        VM.stopBroadcast();

        bytes32 adminRole = registry.DEFAULT_ADMIN_ROLE();
        bytes32 operatorRole = registry.ELECTION_OPERATOR_ROLE();
        require(registry.hasRole(adminRole, admin), "Missing admin role");
        require(registry.hasRole(operatorRole, operator), "Missing operator role");
        require(registry.hasRole(adminRole, deployer) == (deployer == admin), "Unexpected deployer admin role");
        require(registry.hasRole(operatorRole, deployer) == (deployer == operator), "Unexpected deployer operator role");
        require(address(registry.verifier()) == address(verifier), "Wrong verifier");

        logAddress("Deployer", deployer);
        logAddress("Admin", admin);
        logAddress("Operator", operator);
        logAddress("MembershipVoteVerifier", address(verifier));
        logAddress("ElectionRegistry", address(registry));
    }

    function logAddress(string memory label, address value) private view {
        (bool success,) = CONSOLE.staticcall(abi.encodeWithSignature("log(string,address)", label, value));
        require(success, "Console logging failed");
    }
}
