// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title AletheiaRegistry
 * @notice Pillar 3 ("The Ledger") of the Aletheia architecture.
 *
 * Records the SHA-256 hash of an enriched threat intelligence record
 * on-chain, along with its classification metadata. Independent nodes
 * can corroborate an existing record (confirming they observed the
 * same indicator), and anyone can verify a record's existence and
 * submission history.
 *
 * Design notes:
 *  - The FULL record (session data, commands, enrichment detail)
 *    never touches the chain — only its hash and small metadata do.
 *    Off-chain storage (PostgreSQL) holds the full record.
 *  - A node's identity on-chain IS its Ethereum address (msg.sender).
 *    No separate registration step is required to submit; this keeps
 *    the contract simple for a PoA network where validator addresses
 *    are already the trusted node identities.
 *  - Reputation is a simple accumulating score, not a decaying one —
 *    see getReputation() for the rationale.
 */
contract AletheiaRegistry {

    // ─────────────────────────────────────────────────────────
    // Types
    // ─────────────────────────────────────────────────────────

    struct ThreatRecord {
        bytes32 recordHash;          // SHA-256 hash of the full off-chain record
        address submittingNode;      // who first submitted this record
        uint256 timestamp;           // block timestamp at submission
        string attackType;           // e.g. "malware_deployment"
        uint8 severity;              // 0=low, 1=medium, 2=high, 3=critical
        string[] attckTags;          // MITRE ATT&CK technique IDs
        uint8 enrichmentScore;       // AbuseIPDB-style confidence score, 0-100
        uint256 corroborationCount;  // number of independent nodes that corroborated this
        bool exists;                 // existence flag (bytes32(0) hash is a valid key, so we can't rely on hash != 0)
    }

    struct NodeReputation {
        int256 score;                     // accumulated reputation
        uint256 totalSubmissions;         // records this node has submitted
        uint256 totalCorroborationsGiven; // corroborations this node has given to OTHER nodes' records
    }

    // ─────────────────────────────────────────────────────────
    // Storage
    // ─────────────────────────────────────────────────────────

    mapping(bytes32 => ThreatRecord) private records;
    mapping(bytes32 => mapping(address => bool)) private hasCorroborated;
    mapping(address => NodeReputation) private reputations;

    uint256 public constant REPUTATION_PER_CORROBORATION_RECEIVED = 10;
    uint256 public constant REPUTATION_PER_CORROBORATION_GIVEN = 2;

    // ─────────────────────────────────────────────────────────
    // Events
    // ─────────────────────────────────────────────────────────

    event RecordSubmitted(
        bytes32 indexed recordHash,
        address indexed submittingNode,
        string attackType,
        uint8 severity,
        uint256 timestamp
    );

    event RecordCorroborated(
        bytes32 indexed recordHash,
        address indexed corroboratingNode,
        uint256 newCorroborationCount
    );

    // ─────────────────────────────────────────────────────────
    // Errors (cheaper than require-strings on repeated calls)
    // ─────────────────────────────────────────────────────────

    error RecordAlreadyExists(bytes32 recordHash);
    error RecordDoesNotExist(bytes32 recordHash);
    error CannotCorroborateOwnSubmission();
    error AlreadyCorroboratedByThisNode();
    error SeverityOutOfRange(uint8 severity);
    error EnrichmentScoreOutOfRange(uint8 score);

    // ─────────────────────────────────────────────────────────
    // Core methods
    // ─────────────────────────────────────────────────────────

    /**
     * @notice Submit a new threat record. Reverts if this exact hash
     *         has already been submitted — use corroborate() instead
     *         if you independently observed the same indicator.
     */
    function submitRecord(
        bytes32 recordHash,
        string calldata attackType,
        uint8 severity,
        string[] calldata attckTags,
        uint8 enrichmentScore
    ) external {
        if (records[recordHash].exists) revert RecordAlreadyExists(recordHash);
        if (severity > 3) revert SeverityOutOfRange(severity);
        if (enrichmentScore > 100) revert EnrichmentScoreOutOfRange(enrichmentScore);

        ThreatRecord storage r = records[recordHash];
        r.recordHash = recordHash;
        r.submittingNode = msg.sender;
        r.timestamp = block.timestamp;
        r.attackType = attackType;
        r.severity = severity;
        r.enrichmentScore = enrichmentScore;
        r.exists = true;

        for (uint256 i = 0; i < attckTags.length; i++) {
            r.attckTags.push(attckTags[i]);
        }

        reputations[msg.sender].totalSubmissions += 1;

        emit RecordSubmitted(recordHash, msg.sender, attackType, severity, block.timestamp);
    }

    /**
     * @notice Independently confirm that the caller's node also
     *         observed the indicator behind an existing record.
     *         Increases the submitting node's reputation and the
     *         corroborating node's own "contribution" reputation.
     */
    function corroborate(bytes32 recordHash) external {
        ThreatRecord storage r = records[recordHash];
        if (!r.exists) revert RecordDoesNotExist(recordHash);
        if (r.submittingNode == msg.sender) revert CannotCorroborateOwnSubmission();
        if (hasCorroborated[recordHash][msg.sender]) revert AlreadyCorroboratedByThisNode();

        hasCorroborated[recordHash][msg.sender] = true;
        r.corroborationCount += 1;

        reputations[r.submittingNode].score += int256(REPUTATION_PER_CORROBORATION_RECEIVED);
        reputations[msg.sender].totalCorroborationsGiven += 1;
        reputations[msg.sender].score += int256(REPUTATION_PER_CORROBORATION_GIVEN);

        emit RecordCorroborated(recordHash, msg.sender, r.corroborationCount);
    }

    /**
     * @notice Check whether a hash exists on-chain and retrieve its
     *         core metadata. Read-only — callable by anyone, free
     *         off-chain (no gas when called via a view call).
     */
    function verify(bytes32 recordHash)
        external
        view
        returns (
            bool exists,
            address submittingNode,
            uint256 timestamp,
            string memory attackType,
            uint8 severity,
            uint256 corroborationCount
        )
    {
        ThreatRecord storage r = records[recordHash];
        return (r.exists, r.submittingNode, r.timestamp, r.attackType, r.severity, r.corroborationCount);
    }

    /**
     * @notice Full record detail, including ATT&CK tags and enrichment
     *         score (split from verify() to avoid a stack-too-deep /
     *         overly large return on the common-path call).
     */
    function getRecordDetails(bytes32 recordHash)
        external
        view
        returns (string[] memory attckTags, uint8 enrichmentScore)
    {
        if (!records[recordHash].exists) revert RecordDoesNotExist(recordHash);
        ThreatRecord storage r = records[recordHash];
        return (r.attckTags, r.enrichmentScore);
    }

    /**
     * @notice A node's current reputation: raw accumulated score plus
     *         submission/corroboration-given counts.
     *
     *         Deliberately NOT time-decayed on-chain: Solidity has no
     *         native scheduler, so decay would require either (a) a
     *         keeper bot calling a decay function periodically, or
     *         (b) computing decay lazily here using block.timestamp
     *         at read time. Option (b) is the honest, simple choice
     *         for this prototype — the dashboard (Pillar 2/5) can
     *         apply its own decay curve to this raw score for display,
     *         without the contract needing to be re-deployed if the
     *         decay formula changes.
     */
    function getReputation(address node)
        external
        view
        returns (int256 score, uint256 totalSubmissions, uint256 totalCorroborationsGiven)
    {
        NodeReputation storage rep = reputations[node];
        return (rep.score, rep.totalSubmissions, rep.totalCorroborationsGiven);
    }

    function hasNodeCorroborated(bytes32 recordHash, address node) external view returns (bool) {
        return hasCorroborated[recordHash][node];
    }
}
