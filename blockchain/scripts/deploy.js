const hre = require("hardhat");

async function main() {
  const [deployer] = await hre.ethers.getSigners();
  console.log(`Deploying AletheiaRegistry with account: ${deployer.address}`);

  const Registry = await hre.ethers.getContractFactory("AletheiaRegistry");
  const registry = await Registry.deploy();
  await registry.waitForDeployment();

  const address = await registry.getAddress();
  console.log(`AletheiaRegistry deployed to: ${address}`);
  console.log("");
  console.log("Save this address — your Python pipeline's web3.py bridge");
  console.log("(Phase 4) will need it to submit records to this contract.");
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
