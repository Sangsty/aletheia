const { expect } = require("chai");
const { ethers } = require("hardhat");
const { anyValue } = require("@nomicfoundation/hardhat-chai-matchers/withArgs");

describe("AletheiaRegistry", function () {
  let registry, nodeA, nodeB, nodeC, nodeD;

  const recordHash = ethers.id("session:a7bcf90c3823");
  const attackType = "malware_deployment";
  const severity = 2; // high
  const attckTags = ["T1059.004", "T1105", "T1082", "T1110"];
  const enrichmentScore = 81;

  beforeEach(async function () {
    [nodeA, nodeB, nodeC, nodeD] = await ethers.getSigners();
    const Registry = await ethers.getContractFactory("AletheiaRegistry");
    registry = await Registry.deploy();
    await registry.waitForDeployment();
  });

  describe("submitRecord", function () {
    it("stores a new record and emits RecordSubmitted", async function () {
      await expect(
        registry.connect(nodeA).submitRecord(recordHash, attackType, severity, attckTags, enrichmentScore)
      )
        .to.emit(registry, "RecordSubmitted")
        .withArgs(recordHash, nodeA.address, attackType, severity, anyValue);
    });

    it("rejects a duplicate submission of the same hash", async function () {
      await registry.connect(nodeA).submitRecord(recordHash, attackType, severity, attckTags, enrichmentScore);
      await expect(
        registry.connect(nodeA).submitRecord(recordHash, attackType, severity, attckTags, enrichmentScore)
      ).to.be.revertedWithCustomError(registry, "RecordAlreadyExists");
    });

    it("rejects severity out of range (> 3)", async function () {
      await expect(
        registry.connect(nodeA).submitRecord(recordHash, "unclassified", 9, [], 50)
      ).to.be.revertedWithCustomError(registry, "SeverityOutOfRange");
    });

    it("rejects enrichmentScore out of range (> 100)", async function () {
      await expect(
        registry.connect(nodeA).submitRecord(recordHash, "unclassified", 0, [], 150)
      ).to.be.revertedWithCustomError(registry, "EnrichmentScoreOutOfRange");
    });

    it("increments the submitting node's totalSubmissions", async function () {
      await registry.connect(nodeA).submitRecord(recordHash, attackType, severity, attckTags, enrichmentScore);
      const [, totalSubmissions] = await registry.getReputation(nodeA.address);
      expect(totalSubmissions).to.equal(1);
    });
  });

  describe("verify", function () {
    it("returns exists=false for a hash that was never submitted", async function () {
      const [exists] = await registry.verify(ethers.id("never-submitted"));
      expect(exists).to.equal(false);
    });

    it("returns correct metadata for a submitted record", async function () {
      await registry.connect(nodeA).submitRecord(recordHash, attackType, severity, attckTags, enrichmentScore);
      const [exists, submittingNode, , returnedAttackType, returnedSeverity, corroborationCount] =
        await registry.verify(recordHash);
      expect(exists).to.equal(true);
      expect(submittingNode).to.equal(nodeA.address);
      expect(returnedAttackType).to.equal(attackType);
      expect(returnedSeverity).to.equal(severity);
      expect(corroborationCount).to.equal(0);
    });
  });

  describe("corroborate", function () {
    beforeEach(async function () {
      await registry.connect(nodeA).submitRecord(recordHash, attackType, severity, attckTags, enrichmentScore);
    });

    it("increments corroborationCount when an independent node corroborates", async function () {
      await registry.connect(nodeB).corroborate(recordHash);
      const [, , , , , corroborationCount] = await registry.verify(recordHash);
      expect(corroborationCount).to.equal(1);
    });

    it("allows multiple independent nodes to corroborate the same record", async function () {
      await registry.connect(nodeB).corroborate(recordHash);
      await registry.connect(nodeC).corroborate(recordHash);
      const [, , , , , corroborationCount] = await registry.verify(recordHash);
      expect(corroborationCount).to.equal(2);
    });

    it("rejects the submitting node corroborating its own record", async function () {
      await expect(
        registry.connect(nodeA).corroborate(recordHash)
      ).to.be.revertedWithCustomError(registry, "CannotCorroborateOwnSubmission");
    });

    it("rejects the same node corroborating the same record twice", async function () {
      await registry.connect(nodeB).corroborate(recordHash);
      await expect(
        registry.connect(nodeB).corroborate(recordHash)
      ).to.be.revertedWithCustomError(registry, "AlreadyCorroboratedByThisNode");
    });

    it("rejects corroborating a record that doesn't exist", async function () {
      await expect(
        registry.connect(nodeB).corroborate(ethers.id("nonexistent"))
      ).to.be.revertedWithCustomError(registry, "RecordDoesNotExist");
    });
  });

  describe("reputation", function () {
    beforeEach(async function () {
      await registry.connect(nodeA).submitRecord(recordHash, attackType, severity, attckTags, enrichmentScore);
    });

    it("increases the submitting node's score when corroborated", async function () {
      await registry.connect(nodeB).corroborate(recordHash);
      const [score] = await registry.getReputation(nodeA.address);
      expect(score).to.equal(10); // REPUTATION_PER_CORROBORATION_RECEIVED
    });

    it("increases the corroborating node's score and totalCorroborationsGiven", async function () {
      await registry.connect(nodeB).corroborate(recordHash);
      const [score, , totalCorroborationsGiven] = await registry.getReputation(nodeB.address);
      expect(score).to.equal(2); // REPUTATION_PER_CORROBORATION_GIVEN
      expect(totalCorroborationsGiven).to.equal(1);
    });

    it("accumulates correctly across multiple corroborations", async function () {
      await registry.connect(nodeB).corroborate(recordHash);
      await registry.connect(nodeC).corroborate(recordHash);
      await registry.connect(nodeD).corroborate(recordHash);
      const [score] = await registry.getReputation(nodeA.address);
      expect(score).to.equal(30); // 3 corroborations x 10
    });
  });

  describe("getRecordDetails", function () {
    it("returns ATT&CK tags and enrichment score", async function () {
      await registry.connect(nodeA).submitRecord(recordHash, attackType, severity, attckTags, enrichmentScore);
      const [tags, score] = await registry.getRecordDetails(recordHash);
      expect(tags).to.deep.equal(attckTags);
      expect(score).to.equal(enrichmentScore);
    });

    it("reverts for a record that doesn't exist", async function () {
      await expect(
        registry.getRecordDetails(ethers.id("nonexistent"))
      ).to.be.revertedWithCustomError(registry, "RecordDoesNotExist");
    });
  });
});
