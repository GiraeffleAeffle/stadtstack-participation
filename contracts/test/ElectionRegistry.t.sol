// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {ElectionRegistry, IMembershipVoteVerifier} from "../src/ElectionRegistry.sol";
import {MembershipVoteVerifier} from "../src/MembershipVoteVerifier.sol";

interface Vm {
    function prank(address sender) external;
    function warp(uint256 timestamp) external;
    function expectRevert() external;
    function expectRevert(bytes4 selector) external;
    function readFile(string calldata path) external view returns (string memory);
    function parseJsonBytes(string calldata json, string calldata key) external pure returns (bytes memory);
    function parseJsonBytes32(string calldata json, string calldata key) external pure returns (bytes32);
}

contract ElectionRegistryTest {
    Vm private constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    address private constant ADMIN = address(0xA);
    address private constant OPERATOR = address(0xB);
    address private constant OTHER = address(0xC);
    bytes32 private constant ID = bytes32(uint256(1));
    bytes32 private constant ROOT = bytes32(uint256(123));
    bytes32 private constant METADATA = keccak256("metadata");
    uint256 private constant R = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
    ElectionRegistry private registry;
    MembershipVoteVerifier private verifier;

    function setUp() public {
        vm.warp(1000);
        verifier = new MembershipVoteVerifier();
        registry = new ElectionRegistry(ADMIN, OPERATOR, IMembershipVoteVerifier(address(verifier)));
    }

    function open(bytes32 id) private {
        vm.prank(OPERATOR);
        registry.openElection(id, "example", ROOT, 16, METADATA, 999, 1000, 2000);
    }

    function testOpenCloseLifecycleAndEveryField() public {
        open(ID);
        ElectionRegistry.Election memory beforeClose = registry.getElection(ID);
        require(keccak256(bytes(beforeClose.municipalityId)) == keccak256("example"));
        require(beforeClose.anchorRoot == ROOT && beforeClose.treeDepth == 16);
        require(beforeClose.metadataHash == METADATA && beforeClose.scope == 999);
        require(beforeClose.opensAt == 1000 && beforeClose.closesAt == 2000);
        require(!beforeClose.closed && beforeClose.tallyHash == bytes32(0) && beforeClose.acceptedBallots == 0);
        vm.warp(2000);
        vm.prank(OPERATOR);
        registry.closeElection(ID, keccak256("tally"), 17);
        ElectionRegistry.Election memory afterClose = registry.getElection(ID);
        require(afterClose.closed && afterClose.tallyHash == keccak256("tally") && afterClose.acceptedBallots == 17);
        require(afterClose.anchorRoot == ROOT && afterClose.metadataHash == METADATA && afterClose.scope == 999);
        require(afterClose.opensAt == 1000 && afterClose.closesAt == 2000 && afterClose.treeDepth == 16);
        require(keccak256(bytes(afterClose.municipalityId)) == keccak256("example"));
    }

    function testDeployerHasNoRoles() public view {
        require(!registry.hasRole(registry.DEFAULT_ADMIN_ROLE(), address(this)));
        require(!registry.hasRole(registry.ELECTION_OPERATOR_ROLE(), address(this)));
        require(registry.hasRole(registry.DEFAULT_ADMIN_ROLE(), ADMIN));
        require(registry.hasRole(registry.ELECTION_OPERATOR_ROLE(), OPERATOR));
    }

    function testOnlyOperatorOpens() public {
        vm.expectRevert();
        vm.prank(ADMIN);
        registry.openElection(ID, "example", ROOT, 16, METADATA, 999, 1000, 2000);
        vm.expectRevert();
        registry.openElection(ID, "example", ROOT, 16, METADATA, 999, 1000, 2000);
        vm.expectRevert();
        vm.prank(OTHER);
        registry.openElection(ID, "example", ROOT, 16, METADATA, 999, 1000, 2000);
    }

    function testOnlyOperatorCloses() public {
        open(ID);
        vm.warp(2000);
        vm.expectRevert();
        vm.prank(ADMIN);
        registry.closeElection(ID, METADATA, 1);
        vm.expectRevert();
        registry.closeElection(ID, METADATA, 1);
        vm.expectRevert();
        vm.prank(OTHER);
        registry.closeElection(ID, METADATA, 1);
    }

    function testAdminManagesRoles() public {
        bytes32 role = registry.ELECTION_OPERATOR_ROLE();
        vm.expectRevert();
        vm.prank(OPERATOR);
        registry.grantRole(role, OTHER);
        vm.prank(ADMIN);
        registry.grantRole(role, OTHER);
        vm.prank(OTHER);
        registry.openElection(ID, "example", ROOT, 16, METADATA, 999, 1000, 2000);
        vm.prank(ADMIN);
        registry.revokeRole(role, OTHER);
        require(!registry.hasRole(role, OTHER));
        vm.warp(2000);
        vm.expectRevert();
        vm.prank(OTHER);
        registry.closeElection(ID, METADATA, 0);
    }

    function testInvalidDepth() public {
        vm.expectRevert(ElectionRegistry.InvalidDepth.selector);
        vm.prank(OPERATOR);
        registry.openElection(ID, "example", ROOT, 15, METADATA, 999, 1000, 2000);
    }

    function testZeroRoot() public {
        vm.expectRevert(ElectionRegistry.InvalidRoot.selector);
        vm.prank(OPERATOR);
        registry.openElection(ID, "example", bytes32(0), 16, METADATA, 999, 1000, 2000);
    }

    function testZeroScope() public {
        vm.expectRevert(ElectionRegistry.InvalidScope.selector);
        vm.prank(OPERATOR);
        registry.openElection(ID, "example", ROOT, 16, METADATA, 0, 1000, 2000);
    }

    function testScopeAtModulus() public {
        vm.expectRevert(ElectionRegistry.InvalidScope.selector);
        vm.prank(OPERATOR);
        registry.openElection(ID, "example", ROOT, 16, METADATA, R, 1000, 2000);
    }

    function testScopeAboveModulus() public {
        vm.expectRevert(ElectionRegistry.InvalidScope.selector);
        vm.prank(OPERATOR);
        registry.openElection(ID, "example", ROOT, 16, METADATA, R + 1, 1000, 2000);
    }

    function testScopeMaximumAccepted() public {
        vm.prank(OPERATOR);
        registry.openElection(ID, "example", ROOT, 16, METADATA, R - 1, 1000, 2000);
        require(registry.getElection(ID).scope == R - 1);
    }

    function testEqualWindow() public {
        vm.expectRevert(ElectionRegistry.InvalidWindow.selector);
        vm.prank(OPERATOR);
        registry.openElection(ID, "example", ROOT, 16, METADATA, 999, 2000, 2000);
    }

    function testReversedWindow() public {
        vm.expectRevert(ElectionRegistry.InvalidWindow.selector);
        vm.prank(OPERATOR);
        registry.openElection(ID, "example", ROOT, 16, METADATA, 999, 2001, 2000);
    }

    function testCloseTimeInPast() public {
        vm.expectRevert(ElectionRegistry.InvalidWindow.selector);
        vm.prank(OPERATOR);
        registry.openElection(ID, "example", ROOT, 16, METADATA, 999, 0, 999);
    }

    function testCloseTimeAtPresent() public {
        vm.expectRevert(ElectionRegistry.InvalidWindow.selector);
        vm.prank(OPERATOR);
        registry.openElection(ID, "example", ROOT, 16, METADATA, 999, 0, 1000);
    }

    function testDuplicateElectionId() public {
        open(ID);
        vm.expectRevert(ElectionRegistry.ElectionExists.selector);
        open(ID);
        vm.warp(2000);
        vm.prank(OPERATOR);
        registry.closeElection(ID, METADATA, 0);
        vm.expectRevert(ElectionRegistry.ElectionExists.selector);
        open(ID);
    }

    function testCannotCloseBeforeEnd() public {
        open(ID);
        vm.warp(1999);
        vm.expectRevert(ElectionRegistry.ElectionStillOpen.selector);
        vm.prank(OPERATOR);
        registry.closeElection(ID, METADATA, 0);
    }

    function testCannotCloseTwice() public {
        open(ID);
        vm.warp(2000);
        vm.prank(OPERATOR);
        registry.closeElection(ID, METADATA, 0);
        vm.expectRevert(ElectionRegistry.ElectionAlreadyClosed.selector);
        vm.prank(OPERATOR);
        registry.closeElection(ID, ROOT, 1);
    }

    function testUnknownElection() public {
        vm.expectRevert(ElectionRegistry.ElectionUnknown.selector);
        registry.getElection(ID);
        vm.expectRevert(ElectionRegistry.ElectionUnknown.selector);
        registry.verifyBallot(ID, hex"", ROOT, METADATA);
        vm.expectRevert(ElectionRegistry.ElectionUnknown.selector);
        vm.prank(OPERATOR);
        registry.closeElection(ID, METADATA, 0);
    }

    function testInvalidConstructorAddresses() public {
        vm.expectRevert(ElectionRegistry.InvalidConfiguration.selector);
        new ElectionRegistry(address(0), OPERATOR, IMembershipVoteVerifier(address(verifier)));
        vm.expectRevert(ElectionRegistry.InvalidConfiguration.selector);
        new ElectionRegistry(ADMIN, address(0), IMembershipVoteVerifier(address(verifier)));
        vm.expectRevert(ElectionRegistry.InvalidConfiguration.selector);
        new ElectionRegistry(ADMIN, OPERATOR, IMembershipVoteVerifier(address(0)));
    }

    function proofFixture() private returns (bytes32 id, bytes memory proof, bytes32 nullifier, bytes32 signal) {
        string memory json = vm.readFile("test/fixtures/ballot-proof.json");
        id = vm.parseJsonBytes32(json, ".electionId");
        proof = vm.parseJsonBytes(json, ".proof");
        nullifier = vm.parseJsonBytes32(json, ".nullifier");
        signal = vm.parseJsonBytes32(json, ".signalHash");
        vm.prank(OPERATOR);
        registry.openElection(id, "example", vm.parseJsonBytes32(json, ".root"), 16, METADATA,
            uint256(vm.parseJsonBytes32(json, ".scope")), 1000, 2000);
    }

    function assertRejected(bytes32 id, bytes memory proof, bytes32 nullifier, bytes32 signal) private view {
        (bool success, bytes memory result) = address(registry).staticcall(
            abi.encodeCall(registry.verifyBallot, (id, proof, nullifier, signal)));
        require(!success || !abi.decode(result, (bool)), "invalid ballot accepted");
    }

    function testRealBbJsProofVerifiesAndRemainsAuditable() public {
        (bytes32 id, bytes memory proof, bytes32 nullifier, bytes32 signal) = proofFixture();
        require(registry.verifyBallot(id, proof, nullifier, signal), "bb.js proof rejected by Solidity");
        vm.warp(2000);
        vm.prank(OPERATOR);
        registry.closeElection(id, METADATA, 1);
        require(registry.verifyBallot(id, proof, nullifier, signal), "closed-election audit failed");
    }

    function testTamperedProofRejected() public {
        (bytes32 id, bytes memory proof, bytes32 nullifier, bytes32 signal) = proofFixture();
        proof[0] = bytes1(uint8(proof[0]) ^ 1);
        assertRejected(id, proof, nullifier, signal);
    }

    function testWrongNullifierRejected() public {
        (bytes32 id, bytes memory proof, bytes32 nullifier, bytes32 signal) = proofFixture();
        assertRejected(id, proof, bytes32(uint256(nullifier) + 1), signal);
    }

    function testWrongSignalRejected() public {
        (bytes32 id, bytes memory proof, bytes32 nullifier, bytes32 signal) = proofFixture();
        assertRejected(id, proof, nullifier, bytes32(uint256(signal) + 1));
    }

    function testOtherElectionRejected() public {
        (, bytes memory proof, bytes32 nullifier, bytes32 signal) = proofFixture();
        // Same anchor, different scope: cross-election replay must fail independently of membership.
        string memory json = vm.readFile("test/fixtures/ballot-proof.json");
        vm.prank(OPERATOR);
        registry.openElection(ID, "example", vm.parseJsonBytes32(json, ".root"), 16, METADATA, 999, 1000, 2000);
        assertRejected(ID, proof, nullifier, signal);
    }

    function testVerifierFitsEip170() public view {
        require(address(verifier).code.length <= 24576, "verifier exceeds EIP-170");
    }
}
