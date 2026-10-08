// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";

interface IMembershipVoteVerifier {
    function verify(bytes calldata proof, bytes32[] calldata publicInputs) external view returns (bool);
}

/// @notice Immutable eligibility anchors for anonymous, non-binding advisory polls.
contract ElectionRegistry is AccessControl {
    bytes32 public constant ELECTION_OPERATOR_ROLE = keccak256("ELECTION_OPERATOR_ROLE");
    uint256 public constant FIELD_MODULUS =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;
    uint8 public constant TREE_DEPTH = 16;
    IMembershipVoteVerifier public immutable verifier;

    struct Election {
        string municipalityId;
        bytes32 anchorRoot;
        uint8 treeDepth;
        bytes32 metadataHash;
        uint256 scope;
        uint64 opensAt;
        uint64 closesAt;
        bool closed;
        bytes32 tallyHash;
        uint256 acceptedBallots;
    }

    mapping(bytes32 electionId => Election) private elections;
    error InvalidConfiguration();
    error InvalidDepth();
    error InvalidRoot();
    error InvalidScope();
    error InvalidWindow();
    error ElectionExists();
    error ElectionUnknown();
    error ElectionAlreadyClosed();
    error ElectionStillOpen();

    event ElectionOpened(bytes32 indexed electionId, string municipalityId, bytes32 anchorRoot,
        bytes32 metadataHash, uint256 scope, uint64 opensAt, uint64 closesAt);
    event ElectionClosed(bytes32 indexed electionId, bytes32 tallyHash, uint256 acceptedBallots);

    constructor(address admin, address operator, IMembershipVoteVerifier verifier_) {
        if (admin == address(0) || operator == address(0) || address(verifier_) == address(0)) {
            revert InvalidConfiguration();
        }
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(ELECTION_OPERATOR_ROLE, operator);
        verifier = verifier_;
    }

    function openElection(bytes32 electionId, string calldata municipalityId, bytes32 anchorRoot,
        uint8 treeDepth, bytes32 metadataHash, uint256 scope, uint64 opensAt, uint64 closesAt)
        external onlyRole(ELECTION_OPERATOR_ROLE)
    {
        if (elections[electionId].anchorRoot != bytes32(0)) revert ElectionExists();
        if (treeDepth != TREE_DEPTH) revert InvalidDepth();
        if (anchorRoot == bytes32(0)) revert InvalidRoot();
        if (scope == 0 || scope >= FIELD_MODULUS) revert InvalidScope();
        if (opensAt >= closesAt || closesAt <= block.timestamp) revert InvalidWindow();
        elections[electionId] = Election({ municipalityId: municipalityId, anchorRoot: anchorRoot,
            treeDepth: treeDepth, metadataHash: metadataHash, scope: scope, opensAt: opensAt,
            closesAt: closesAt, closed: false, tallyHash: bytes32(0), acceptedBallots: 0 });
        emit ElectionOpened(electionId, municipalityId, anchorRoot, metadataHash, scope, opensAt, closesAt);
    }

    function closeElection(bytes32 electionId, bytes32 tallyHash, uint256 acceptedBallots)
        external onlyRole(ELECTION_OPERATOR_ROLE)
    {
        Election storage election = elections[electionId];
        if (election.anchorRoot == bytes32(0)) revert ElectionUnknown();
        if (election.closed) revert ElectionAlreadyClosed();
        if (block.timestamp < election.closesAt) revert ElectionStillOpen();
        election.closed = true;
        election.tallyHash = tallyHash;
        election.acceptedBallots = acceptedBallots;
        emit ElectionClosed(electionId, tallyHash, acceptedBallots);
    }

    function getElection(bytes32 electionId) external view returns (Election memory) {
        Election storage election = elections[electionId];
        if (election.anchorRoot == bytes32(0)) revert ElectionUnknown();
        return election;
    }

    /// @dev No window gate: published proofs must remain auditable after closure.
    function verifyBallot(bytes32 electionId, bytes calldata proof, bytes32 nullifier, bytes32 signalHash)
        external view returns (bool)
    {
        Election storage election = elections[electionId];
        if (election.anchorRoot == bytes32(0)) revert ElectionUnknown();
        bytes32[] memory publicInputs = new bytes32[](4);
        publicInputs[0] = election.anchorRoot;
        publicInputs[1] = nullifier;
        publicInputs[2] = bytes32(election.scope);
        publicInputs[3] = signalHash;
        return verifier.verify(proof, publicInputs);
    }
}
