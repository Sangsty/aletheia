const { ethers } = require("ethers");

const nodes = ["Node A (Oracle)", "Node B (AWS)", "Node C (GCP)"];

for (const name of nodes) {
  const wallet = ethers.Wallet.createRandom();
  console.log(name);
  console.log("  Address:     " + wallet.address);
  console.log("  Private key: " + wallet.privateKey);
  console.log("");
}
