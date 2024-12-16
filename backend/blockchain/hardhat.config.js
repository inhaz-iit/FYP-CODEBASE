require("@nomicfoundation/hardhat-toolbox");
require("hardhat-gas-reporter");
const config = require("../configuration/config");

/** @type import('hardhat/config').HardhatUserConfig */
module.exports = {
  solidity: "0.8.20",
  networks: {
    sepolia: {
        url: config.SEPOLIA_RPC, // Sepolia RPC URL
        accounts: [config.PRIVATE_KEY]  // wallet private key
    },
    amoy: {
        url: config.AMOY_RPC, // Amoy RPC URL
        accounts: [config.PRIVATE_KEY]  // wallet private key
    },
  },
  gasReporter: {
    enabled: true,
    currency: "ETH",
    gasPrice: 20,
  },
};
