const hre = require("hardhat");

// The 3 federation node addresses, fixed permanently at deploy time
// (see AletheiaRegistry.sol's contract-level design notes for why).
// Set these from the public ADDRESSES of your 3 funded Amoy wallets —
// NOT the private keys. Read from env vars so nothing is hardcoded
// or accidentally committed:
//   ALETHEIA_NODE_A_ADDRESS, ALETHEIA_NODE_B_ADDRESS, ALETHEIA_NODE_C_ADDRESS
const NODE_A = process.env.ALETHEIA_NODE_A_ADDRESS;
const NODE_B = process.env.ALETHEIA_NODE_B_ADDRESS;
const NODE_C = process.env.ALETHEIA_NODE_C_ADDRESS;

async function main() {
  if (!NODE_A || !NODE_B || !NODE_C) {
    throw new Error(
      "Set ALETHEIA_NODE_A_ADDRESS, ALETHEIA_NODE_B_ADDRESS and " +
      "ALETHEIA_NODE_C_ADDRESS (the 3 wallet ADDRESSES, not private keys) " +
      "before deploying — the contract fixes these permanently at deploy time."
    );
  }

  const [deployer] = await hre.ethers.getSigners();
  console.log(`Deploying AletheiaRegistry with account: ${deployer.address}`);
  console.log(`Fixing federation nodes: A=${NODE_A} B=${NODE_B} C=${NODE_C}`);

  const Registry = await hre.ethers.getContractFactory("AletheiaRegistry");
  const registry = await Registry.deploy(NODE_A, NODE_B, NODE_C);
  await registry.waitForDeployment();

  const address = await registry.getAddress();
  console.log(`AletheiaRegistry deployed to: ${address}`);
  console.log("");
  console.log("Save this address — your Python pipeline's web3.py bridge");
  console.log("(Phase 4) will need it to submit records to this contract.");
  console.log("Only the 3 fixed node addresses above can submit/corroborate.");
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
