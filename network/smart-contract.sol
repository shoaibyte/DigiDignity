// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/security/Pausable.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/EIP712.sol";

/**
 * @title RefugeeChainPublicRegistry
 * @dev Public Ethereum contract for refugee identity attestations and cross-chain interoperability
 * @notice This contract handles public attestations while keeping sensitive data on private Hyperledger network
 */
contract RefugeeChainPublicRegistry is AccessControl, ReentrancyGuard, Pausable, EIP712 {
    using ECDSA for bytes32;

    // Role definitions
    bytes32 public constant VALIDATOR_ROLE = keccak256("VALIDATOR_ROLE");
    bytes32 public constant ATTESTOR_ROLE = keccak256("ATTESTOR_ROLE");
    bytes32 public constant ORACLE_ROLE = keccak256("ORACLE_ROLE");
    bytes32 public constant EMERGENCY_ROLE = keccak256("EMERGENCY_ROLE");

    // Events
    event IdentityAttested(
        bytes32 indexed identityHash,
        address indexed attestor,
        string attestationType,
        uint256 timestamp,
        uint8 confidenceLevel
    );

    event CrossChainVerification(
        bytes32 indexed identityHash,
        string indexed destinationNetwork,
        bytes32 verificationHash,
        uint256 timestamp
    );

    event ServiceAccessGranted(
        bytes32 indexed identityHash,
        address indexed serviceProvider,
        string serviceType,
        uint256 expirationTime
    );

    event BiometricChallengeResult(
        bytes32 indexed challengeId,
        bytes32 indexed identityHash,
        bool verified,
        uint8 confidence,
        uint256 timestamp
    );

    // Structs
    struct PublicAttestation {
        address attestor;
        string attestationType;
        bytes32 evidenceHash;
        uint256 timestamp;
        uint256 expirationTime;
        uint8 confidenceLevel;
        bool isActive;
    }

    struct ServiceAccess {
        address serviceProvider;
        string serviceType;
        uint256 grantedTime;
        uint256 expirationTime;
        bool isActive;
        uint256 accessCount;
    }

    struct CrossChainRecord {
        string destinationNetwork;
        bytes32 verificationHash;
        uint256 timestamp;
        bool isActive;
    }

    struct BiometricChallenge {
        bytes32 identityHash;
        bytes32 challengeHash;
        address challenger;
        uint256 timestamp;
        bool completed;
        bool verified;
        uint8 confidence;
    }

    // State variables
    mapping(bytes32 => PublicAttestation[]) public attestations;
    mapping(bytes32 => ServiceAccess[]) public serviceAccess;
    mapping(bytes32 => CrossChainRecord[]) public crossChainRecords;
    mapping(bytes32 => BiometricChallenge) public biometricChallenges;
    mapping(address => bool) public authorizedOracles;
    mapping(bytes32 => bool) public revokedIdentities;

    // Gas optimization: packed structs
    struct IdentityStats {
        uint32 attestationCount;
        uint32 verificationCount;
        uint32 serviceAccessCount;
        uint64 lastActivity;
        uint8 reputationScore;
        bool isActive;
    }

    mapping(bytes32 => IdentityStats) public identityStats;

    // Constants for gas optimization
    uint256 public constant MAX_ATTESTATIONS = 50;
    uint256 public constant MAX_SERVICE_ACCESS = 20;
    uint256 public constant CHALLENGE_VALIDITY = 1 hours;
    uint256 public constant MIN_CONFIDENCE_LEVEL = 70;

    // Fee structure
    uint256 public attestationFee = 0.001 ether;
    uint256 public verificationFee = 0.0001 ether;

    constructor() EIP712("RefugeeChainRegistry", "1") {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(EMERGENCY_ROLE, msg.sender);
    }

    /**
     * @dev Add public attestation for identity
     * @param identityHash Hash of the identity (from private network)
     * @param attestationType Type of attestation (EDUCATION, HEALTH, etc.)
     * @param evidenceHash Hash of supporting evidence
     * @param expirationTime When attestation expires
     * @param confidenceLevel Confidence level (0-100)
     */
    function addAttestation(
        bytes32 identityHash,
        string memory attestationType,
        bytes32 evidenceHash,
        uint256 expirationTime,
        uint8 confidenceLevel
    ) external payable onlyRole(ATTESTOR_ROLE) whenNotPaused {
        require(msg.value >= attestationFee, "Insufficient fee");
        require(!revokedIdentities[identityHash], "Identity revoked");
        require(expirationTime > block.timestamp, "Invalid expiration time");
        require(confidenceLevel >= MIN_CONFIDENCE_LEVEL, "Confidence too low");
        require(attestations[identityHash].length < MAX_ATTESTATIONS, "Too many attestations");

        PublicAttestation memory newAttestation = PublicAttestation({
            attestor: msg.sender,
            attestationType: attestationType,
            evidenceHash: evidenceHash,
            timestamp: block.timestamp,
            expirationTime: expirationTime,
            confidenceLevel: confidenceLevel,
            isActive: true
        });

        attestations[identityHash].push(newAttestation);

        // Update stats
        identityStats[identityHash].attestationCount++;
        identityStats[identityHash].lastActivity = uint64(block.timestamp);
        identityStats[identityHash].isActive = true;

        // Update reputation score
        _updateReputationScore(identityHash, confidenceLevel);

        emit IdentityAttested(
            identityHash,
            msg.sender,
            attestationType,
            block.timestamp,
            confidenceLevel
        );
    }

    /**
     * @dev Verify identity with biometric challenge
     * @param identityHash Identity to verify
     * @param challengeHash Hash of biometric challenge data
     * @return challengeId Unique challenge identifier
     */
    function createBiometricChallenge(
        bytes32 identityHash,
        bytes32 challengeHash
    ) external payable whenNotPaused returns (bytes32 challengeId) {
        require(msg.value >= verificationFee, "Insufficient fee");
        require(!revokedIdentities[identityHash], "Identity revoked");

        challengeId = keccak256(
            abi.encodePacked(identityHash, challengeHash, msg.sender, block.timestamp)
        );

        biometricChallenges[challengeId] = BiometricChallenge({
            identityHash: identityHash,
            challengeHash: challengeHash,
            challenger: msg.sender,
            timestamp: block.timestamp,
            completed: false,
            verified: false,
            confidence: 0
        });

        return challengeId;
    }

    /**
     * @dev Complete biometric challenge (called by oracle)
     * @param challengeId Challenge to complete
     * @param verified Whether verification succeeded
     * @param confidence Confidence level (0-100)
     */
    function completeBiometricChallenge(
        bytes32 challengeId,
        bool verified,
        uint8 confidence
    ) external onlyRole(ORACLE_ROLE) whenNotPaused {
        BiometricChallenge storage challenge = biometricChallenges[challengeId];
        require(challenge.timestamp > 0, "Challenge not found");
        require(!challenge.completed, "Challenge already completed");
        require(
            block.timestamp <= challenge.timestamp + CHALLENGE_VALIDITY,
            "Challenge expired"
        );

        challenge.completed = true;
        challenge.verified = verified;
        challenge.confidence = confidence;

        // Update identity stats
        identityStats[challenge.identityHash].verificationCount++;
        identityStats[challenge.identityHash].lastActivity = uint64(block.timestamp);

        if (verified && confidence >= MIN_CONFIDENCE_LEVEL) {
            _updateReputationScore(challenge.identityHash, confidence);
        }

        emit BiometricChallengeResult(
            challengeId,
            challenge.identityHash,
            verified,
            confidence,
            block.timestamp
        );
    }

    /**
     * @dev Grant service access with zero-knowledge proof
     * @param identityHash Identity requesting access
     * @param serviceType Type of service (BANKING, EDUCATION, etc.)
     * @param duration Access duration in seconds
     * @param zkProof Zero-knowledge proof of eligibility
     */
    function grantServiceAccess(
        bytes32 identityHash,
        string memory serviceType,
        uint256 duration,
        bytes memory zkProof
    ) external whenNotPaused {
        require(!revokedIdentities[identityHash], "Identity revoked");
        require(duration <= 365 days, "Duration too long");
        require(serviceAccess[identityHash].length < MAX_SERVICE_ACCESS, "Too many service access");
        require(_verifyZKProof(identityHash, serviceType, zkProof), "Invalid ZK proof");

        // Check identity has sufficient reputation for service type
        uint8 minReputation = _getMinReputationForService(serviceType);
        require(
            identityStats[identityHash].reputationScore >= minReputation,
            "Insufficient reputation"
        );

        ServiceAccess memory newAccess = ServiceAccess({
            serviceProvider: msg.sender,
            serviceType: serviceType,
            grantedTime: block.timestamp,
            expirationTime: block.timestamp + duration,
            isActive: true,
            accessCount: 0
        });

        serviceAccess[identityHash].push(newAccess);

        // Update stats
        identityStats[identityHash].serviceAccessCount++;
        identityStats[identityHash].lastActivity = uint64(block.timestamp);

        emit ServiceAccessGranted(
            identityHash,
            msg.sender,
            serviceType,
            block.timestamp + duration
        );
    }

    /**
     * @dev Enable cross-chain verification
     * @param identityHash Identity to enable cross-chain access
     * @param destinationNetwork Target blockchain network
     * @param verificationData Encrypted verification data
     */
    function enableCrossChainAccess(
        bytes32 identityHash,
        string memory destinationNetwork,
        bytes memory verificationData
    ) external onlyRole(VALIDATOR_ROLE) whenNotPaused {
        require(!revokedIdentities[identityHash], "Identity revoked");

        bytes32 verificationHash = keccak256(
            abi.encodePacked(identityHash, destinationNetwork, verificationData)
        );

        CrossChainRecord memory newRecord = CrossChainRecord({
            destinationNetwork: destinationNetwork,
            verificationHash: verificationHash,
            timestamp: block.timestamp,
            isActive: true
        });

        crossChainRecords[identityHash].push(newRecord);

        // Update stats
        identityStats[identityHash].lastActivity = uint64(block.timestamp);

        emit CrossChainVerification(
            identityHash,
            destinationNetwork,
            verificationHash,
            block.timestamp
        );
    }

    /**
     * @dev Batch operations for gas efficiency
     * @param identityHashes Array of identity hashes
     * @param attestationTypes Array of attestation types
     * @param evidenceHashes Array of evidence hashes
     * @param expirationTimes Array of expiration times
     * @param confidenceLevels Array of confidence levels
     */
    function batchAddAttestations(
        bytes32[] memory identityHashes,
        string[] memory attestationTypes,
        bytes32[] memory evidenceHashes,
        uint256[] memory expirationTimes,
        uint8[] memory confidenceLevels
    ) external payable onlyRole(ATTESTOR_ROLE) whenNotPaused {
        require(identityHashes.length == attestationTypes.length, "Array length mismatch");
        require(identityHashes.length == evidenceHashes.length, "Array length mismatch");
        require(identityHashes.length == expirationTimes.length, "Array length mismatch");
        require(identityHashes.length == confidenceLevels.length, "Array length mismatch");
        require(msg.value >= attestationFee * identityHashes.length, "Insufficient fee");

        for (uint256 i = 0; i < identityHashes.length; i++) {
            require(!revokedIdentities[identityHashes[i]], "Identity revoked");
            require(expirationTimes[i] > block.timestamp, "Invalid expiration time");
            require(confidenceLevels[i] >= MIN_CONFIDENCE_LEVEL, "Confidence too low");

            PublicAttestation memory newAttestation = PublicAttestation({
                attestor: msg.sender,
                attestationType: attestationTypes[i],
                evidenceHash: evidenceHashes[i],
                timestamp: block.timestamp,
                expirationTime: expirationTimes[i],
                confidenceLevel: confidenceLevels[i],
                isActive: true
            });

            attestations[identityHashes[i]].push(newAttestation);

            // Update stats
            identityStats[identityHashes[i]].attestationCount++;
            identityStats[identityHashes[i]].lastActivity = uint64(block.timestamp);
            identityStats[identityHashes[i]].isActive = true;

            _updateReputationScore(identityHashes[i], confidenceLevels[i]);

            emit IdentityAttested(
                identityHashes[i],
                msg.sender,
                attestationTypes[i],
                block.timestamp,
                confidenceLevels[i]
            );
        }
    }

    /**
     * @dev Revoke identity in emergency situations
     * @param identityHash Identity to revoke
     * @param reason Reason for revocation
     */
    function emergencyRevokeIdentity(
        bytes32 identityHash,
        string memory reason
    ) external onlyRole(EMERGENCY_ROLE) {
        revokedIdentities[identityHash] = true;
        identityStats[identityHash].isActive = false;

        // Deactivate all attestations
        for (uint256 i = 0; i < attestations[identityHash].length; i++) {
            attestations[identityHash][i].isActive = false;
        }

        // Deactivate all service access
        for (uint256 i = 0; i < serviceAccess[identityHash].length; i++) {
            serviceAccess[identityHash][i].isActive = false;
        }

        emit IdentityRevoked(identityHash, msg.sender, reason, block.timestamp);
    }

    // View functions for gas-efficient queries

    /**
     * @dev Get active attestations for identity
     * @param identityHash Identity to query
     * @return activeAttestations Array of active attestations
     */
    function getActiveAttestations(bytes32 identityHash)
        external
        view
        returns (PublicAttestation[] memory activeAttestations)
    {
        PublicAttestation[] memory allAttestations = attestations[identityHash];
        uint256 activeCount = 0;

        // Count active attestations
        for (uint256 i = 0; i < allAttestations.length; i++) {
            if (allAttestations[i].isActive && allAttestations[i].expirationTime > block.timestamp) {
                activeCount++;
            }
        }

        // Create result array
        activeAttestations = new PublicAttestation[](activeCount);
        uint256 index = 0;

        for (uint256 i = 0; i < allAttestations.length; i++) {
            if (allAttestations[i].isActive && allAttestations[i].expirationTime > block.timestamp) {
                activeAttestations[index] = allAttestations[i];
                index++;
            }
        }

        return activeAttestations;
    }

    /**
     * @dev Get identity reputation and stats
     * @param identityHash Identity to query
     * @return stats Identity statistics
     */
    function getIdentityStats(bytes32 identityHash)
        external
        view
        returns (IdentityStats memory stats)
    {
        return identityStats[identityHash];
    }

    /**
     * @dev Verify if identity has access to specific service
     * @param identityHash Identity to check
     * @param serviceProvider Service provider address
     * @param serviceType Type of service
     * @return hasAccess Whether identity has active access
     * @return expirationTime When access expires
     */
    function verifyServiceAccess(
        bytes32 identityHash,
        address serviceProvider,
        string memory serviceType
    ) external view returns (bool hasAccess, uint256 expirationTime) {
        if (revokedIdentities[identityHash]) {
            return (false, 0);
        }

        ServiceAccess[] memory accesses = serviceAccess[identityHash];

        for (uint256 i = 0; i < accesses.length; i++) {
            if (
                accesses[i].serviceProvider == serviceProvider &&
                keccak256(bytes(accesses[i].serviceType)) == keccak256(bytes(serviceType)) &&
                accesses[i].isActive &&
                accesses[i].expirationTime > block.timestamp
            ) {
                return (true, accesses[i].expirationTime);
            }
        }

        return (false, 0);
    }

    /**
     * @dev Get cross-chain verification records
     * @param identityHash Identity to query
     * @return records Array of cross-chain records
     */
    function getCrossChainRecords(bytes32 identityHash)
        external
        view
        returns (CrossChainRecord[] memory records)
    {
        return crossChainRecords[identityHash];
    }

    // Internal functions

    function _updateReputationScore(bytes32 identityHash, uint8 confidenceLevel) internal {
        IdentityStats storage stats = identityStats[identityHash];

        // Weighted average: new score contributes 20%, existing score 80%
        uint256 newScore = (uint256(stats.reputationScore) * 80 + uint256(confidenceLevel) * 20) / 100;
        stats.reputationScore = uint8(newScore);
    }

    function _verifyZKProof(
        bytes32 identityHash,
        string memory serviceType,
        bytes memory zkProof
    ) internal view returns (bool) {
        // Simplified ZK proof verification
        // In production, this would use a proper ZK verification library
        bytes32 proofHash = keccak256(zkProof);
        bytes32 expectedHash = keccak256(
            abi.encodePacked(identityHash, serviceType, "valid_proof")
        );

        // For demo purposes, accept any valid format proof
        return zkProof.length >= 32 && proofHash != bytes32(0);
    }

    function _getMinReputationForService(string memory serviceType) internal pure returns (uint8) {
        bytes32 serviceHash = keccak256(bytes(serviceType));

        if (serviceHash == keccak256(bytes("BANKING"))) return 85;
        if (serviceHash == keccak256(bytes("EDUCATION"))) return 70;
        if (serviceHash == keccak256(bytes("HEALTHCARE"))) return 60;
        if (serviceHash == keccak256(bytes("AID"))) return 50;

        return 70; // Default minimum reputation
    }

    // Admin functions

    function setFees(uint256 _attestationFee, uint256 _verificationFee)
        external onlyRole(DEFAULT_ADMIN_ROLE) {
        attestationFee = _attestationFee;
        verificationFee = _verificationFee;
    }

    function addValidator(address validator) external onlyRole(DEFAULT_ADMIN_ROLE) {
        _grantRole(VALIDATOR_ROLE, validator);
    }

    function addAttestor(address attestor) external onlyRole(DEFAULT_ADMIN_ROLE) {
        _grantRole(ATTESTOR_ROLE, attestor);
    }

    function addOracle(address oracle) external onlyRole(DEFAULT_ADMIN_ROLE) {
        _grantRole(ORACLE_ROLE, oracle);
        authorizedOracles[oracle] = true;
    }

    function pause() external onlyRole(EMERGENCY_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }

    function withdrawFees() external onlyRole(DEFAULT_ADMIN_ROLE) {
        uint256 balance = address(this).balance;
        require(balance > 0, "No funds to withdraw");

        (bool success, ) = payable(msg.sender).call{value: balance}("");
        require(success, "Withdrawal failed");
    }

    // Events for revocation
    event IdentityRevoked(
        bytes32 indexed identityHash,
        address indexed revoker,
        string reason,
        uint256 timestamp
    );

    // Gas optimization: Use receive function for direct payments
    receive() external payable {}

    fallback() external payable {}
}

/**
 * @title RefugeeChainInteroperability
 * @dev Additional contract for cross-chain interoperability
 */
contract RefugeeChainInteroperability {

    struct CrossChainMessage {
        bytes32 identityHash;
        string sourceNetwork;
        string destinationNetwork;
        bytes payload;
        uint256 timestamp;
        bool processed;
    }

    mapping(bytes32 => CrossChainMessage) public crossChainMessages;
    mapping(string => bool) public supportedNetworks;

    event CrossChainMessageCreated(
        bytes32 indexed messageId,
        bytes32 indexed identityHash,
        string sourceNetwork,
        string destinationNetwork
    );

    event CrossChainMessageProcessed(
        bytes32 indexed messageId,
        bool success
    );

    function createCrossChainMessage(
        bytes32 identityHash,
        string memory sourceNetwork,
        string memory destinationNetwork,
        bytes memory payload
    ) external returns (bytes32 messageId) {
        require(supportedNetworks[sourceNetwork], "Source network not supported");
        require(supportedNetworks[destinationNetwork], "Destination network not supported");

        messageId = keccak256(
            abi.encodePacked(
                identityHash,
                sourceNetwork,
                destinationNetwork,
                payload,
                block.timestamp
            )
        );

        crossChainMessages[messageId] = CrossChainMessage({
            identityHash: identityHash,
            sourceNetwork: sourceNetwork,
            destinationNetwork: destinationNetwork,
            payload: payload,
            timestamp: block.timestamp,
            processed: false
        });

        emit CrossChainMessageCreated(
            messageId,
            identityHash,
            sourceNetwork,
            destinationNetwork
        );

        return messageId;
    }

    function processCrossChainMessage(bytes32 messageId) external returns (bool success) {
        CrossChainMessage storage message = crossChainMessages[messageId];
        require(!message.processed, "Message already processed");
        require(message.timestamp > 0, "Message not found");

        // Process the cross-chain message
        // Implementation would depend on specific cross-chain protocol

        message.processed = true;

        emit CrossChainMessageProcessed(messageId, true);
        return true;
    }
}