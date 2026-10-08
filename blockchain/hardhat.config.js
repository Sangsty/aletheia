require("@nomicfoundation/hardhat-toolbox");
require("dotenv").config();

/** @type {import('hardhat/config').HardhatUserConfig} */
module.exports = {
  solidity: {
    version: "0.8.24",
    settings: {
      optimizer: {
        enabled: true,
        runs: 200,
      },
    },
  },
  networks: {
    hardhat: {
      // Local in-memory chain used for npx hardhat test - no setup needed.
    },
    localhost: {
      // npx hardhat node must be running separately for this one.
      url: "http://127.0.0.1:8545",
    },
    amoy: {
      // Polygon Amoy public testnet - real, persistent, publicly verifiable.
      url: process.env.AMOY_RPC_URL || "https://rpc-amoy.polygon.technology",
      accounts: process.env.DEPLOYER_PRIVATE_KEY ? [process.env.DEPLOYER_PRIVATE_KEY] : [],
    },
  },
};
