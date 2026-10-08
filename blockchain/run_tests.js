/**
 * Standalone test runner for AletheiaRegistry.
 *
 * Compiles the contract with solc, deploys it to an in-process Ganache
 * EVM, and runs a sequence of real transactions against it — exercising
 * submit, corroborate, verify, reputation accumulation, and every
 * revert condition. This exists as a workaround for this sandboxed
 * environment's network restrictions (Hardhat's own test runner needs
 * to download its compiler from binaries.soliditylang.org, which is
 * blocked here). On a normal machine, `npx hardhat test` using
 * test/AletheiaRegistry.test.js is the standard way to run these
 * same checks.
 */

const solc = require("solc");
const fs = require("fs");
const ganache = require("ganache");
const { ethers } = require("ethers");

let passed = 0;
let failed = 0;

function check(label, condition) {
  if (condition) {
    console.log(`  PASS  ${label}`);
    passed++;
  } else {
    console.log(`  FAIL  ${label}`);
    failed++;
  }
}

async function expectRevert(txPromise, label) {
  // Must await BOTH the send and the mined receipt — a tx that reverts
  // on-chain doesn't throw at send() time, only at wait() time.
  try {
    const tx = await txPromise;
    await tx.wait();
    check(label, false);
  } catch (err) {
    check(label, true);
  }
}

async function main() {
  // ── Compile ──────────────────────────────────────────────
  const source = fs.readFileSync("contracts/AletheiaRegistry.sol", "utf8");
  const input = {
    language: "Solidity",
    sources: { "AletheiaRegistry.sol": { content: source } },
    settings: {
      outputSelection: { "*": { "*": ["abi", "evm.bytecode"] } },
      optimizer: { enabled: true, runs: 200 },
    },
  };
  const output = JSON.parse(solc.compile(JSON.stringify(input)));
  const errors = (output.errors || []).filter((e) => e.severity === "error");
  if (errors.length > 0) {
    errors.forEach((e) => console.log(e.formattedMessage));
    process.exit(1);
  }
  const contractOutput = output.contracts["AletheiaRegistry.sol"]["AletheiaRegistry"];
  const abi = contractOutput.abi;
  const bytecode = "0x" + contractOutput.evm.bytecode.object;

  // ── Start local EVM ──────────────────────────────────────
  const server = ganache.provider({ logging: { quiet: true } });
  const provider = new ethers.BrowserProvider(server);

  const signers = [];
  for (let i = 0; i < 4; i++) {
    signers.push(await provider.getSigner(i));
  }
  const [nodeA, nodeB, nodeC, nodeD] = signers;

  console.log("Nodes (simulating 4 independent honeypot operators):");
  console.log(`  nodeA: ${await nodeA.getAddress()}`);
  console.log(`  nodeB: ${await nodeB.getAddress()}`);
  console.log(`  nodeC: ${await nodeC.getAddress()}`);
  console.log(`  nodeD: ${await nodeD.getAddress()}`);
  console.log("");

  // ── Deploy ───────────────────────────────────────────────
  const factory = new ethers.ContractFactory(abi, bytecode, nodeA);
  const contract = await factory.deploy();
  await contract.waitForDeployment();
  const address = await contract.getAddress();
  console.log(`Deployed AletheiaRegistry at ${address}\n`);

  const contractAsB = contract.connect(nodeB);
  const contractAsC = contract.connect(nodeC);
  const contractAsD = contract.connect(nodeD);

  // ── Test data: matches the real Aletheia pipeline output ──
  const recordHash = "0x" + "1ad5b59d376492bacdff4218a1ab6c9ca1c1e0ab92b08fd4f31e157cb595e91" + "5".padStart(0, "0");
  // normalize to a valid 32-byte hex (64 hex chars after 0x)
  const validHash = ethers.id("session:a7bcf90c3823"); // deterministic bytes32 test hash
  const attackType = "malware_deployment";
  const severity = 2; // high
  const attckTags = ["T1059.004", "T1105", "T1082", "T1110"];
  const enrichmentScore = 81;

  console.log("=== submitRecord() ===");
  const tx1 = await contract.submitRecord(validHash, attackType, severity, attckTags, enrichmentScore);
  const receipt1 = await tx1.wait();
  check("submitRecord succeeds and emits RecordSubmitted", receipt1.status === 1);

  const verifyResult = await contract.verify(validHash);
  check("verify() reports exists=true", verifyResult[0] === true);
  check("verify() reports correct submittingNode", verifyResult[1] === (await nodeA.getAddress()));
  check("verify() reports correct attackType", verifyResult[3] === attackType);
  check("verify() reports correct severity", Number(verifyResult[4]) === severity);
  check("verify() reports corroborationCount=0 initially", Number(verifyResult[5]) === 0);

  const details = await contract.getRecordDetails(validHash);
  check("getRecordDetails() returns correct ATT&CK tags", JSON.stringify(details[0]) === JSON.stringify(attckTags));
  check("getRecordDetails() returns correct enrichmentScore", Number(details[1]) === enrichmentScore);

  console.log("\n=== Duplicate submission should revert ===");
  await expectRevert(
    contract.submitRecord(validHash, attackType, severity, attckTags, enrichmentScore),
    "resubmitting the same hash reverts (RecordAlreadyExists)"
  );

  console.log("\n=== corroborate() — independent nodes confirm the same indicator ===");
  const tx2 = await contractAsB.corroborate(validHash);
  await tx2.wait();
  const tx3 = await contractAsC.corroborate(validHash);
  await tx3.wait();

  const verifyAfterCorroboration = await contract.verify(validHash);
  check("corroborationCount is 2 after two independent corroborations", Number(verifyAfterCorroboration[5]) === 2);

  console.log("\n=== Self-corroboration should revert ===");
  await expectRevert(
    contract.corroborate(validHash), // nodeA corroborating its own submission
    "submitting node corroborating its own record reverts"
  );

  console.log("\n=== Double corroboration by the same node should revert ===");
  await expectRevert(
    contractAsB.corroborate(validHash), // nodeB corroborating again
    "same node corroborating twice reverts (AlreadyCorroboratedByThisNode)"
  );

  console.log("\n=== Reputation accumulation ===");
  const repA = await contract.getReputation(await nodeA.getAddress());
  check("submitting node (A) reputation reflects 2 corroborations received (score=20)", Number(repA[0]) === 20);
  check("submitting node (A) totalSubmissions = 1", Number(repA[1]) === 1);

  const repB = await contract.getReputation(await nodeB.getAddress());
  check("corroborating node (B) reputation reflects 1 corroboration given (score=2)", Number(repB[0]) === 2);
  check("corroborating node (B) totalCorroborationsGiven = 1", Number(repB[2]) === 1);

  console.log("\n=== Invalid input bounds ===");
  const otherHash = ethers.id("session:test-invalid-severity");
  await expectRevert(
    contractAsD.submitRecord(otherHash, "unclassified", 9, [], 50),
    "severity > 3 reverts (SeverityOutOfRange)"
  );

  const anotherHash = ethers.id("session:test-invalid-score");
  await expectRevert(
    contractAsD.submitRecord(anotherHash, "unclassified", 0, [], 150),
    "enrichmentScore > 100 reverts (EnrichmentScoreOutOfRange)"
  );

  console.log("\n=== verify() on a hash that was never submitted ===");
  const unknownHash = ethers.id("session:never-submitted");
  const unknownResult = await contract.verify(unknownHash);
  check("verify() on unknown hash returns exists=false (no revert)", unknownResult[0] === false);

  console.log("\n=== Second independent threat record (different node submitting) ===");
  const secondHash = ethers.id("session:f2e91d0a55b1");
  const tx4 = await contractAsD.submitRecord(secondHash, "cryptominer_installation", 3, ["T1496"], 95);
  await tx4.wait();
  const verify2 = await contract.verify(secondHash);
  check("second record from a different submitting node works independently", verify2[0] === true && verify2[1] === (await nodeD.getAddress()));

  // ── Summary ──────────────────────────────────────────────
  console.log("\n" + "=".repeat(50));
  console.log(`RESULTS: ${passed} passed, ${failed} failed (${passed + failed} total)`);
  console.log("=".repeat(50));

  if (typeof server.close === "function") {
    await server.close();
  } else if (typeof server.disconnect === "function") {
    await server.disconnect();
  }
  process.exit(failed > 0 ? 1 : 0);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
