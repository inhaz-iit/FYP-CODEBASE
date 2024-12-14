require("@nomicfoundation/hardhat-toolbox");
require("hardhat-gas-reporter");
const config = require("../configuration/config");

/** @type import('hardhat/config').HardhatUserConfig */
module.exports = {
  solidity: "0.8.20",
  networks: {
    sepolia: {
        url: config.SEPOLIA_RPC, // Your Sepolia RPC URL
        accounts: [config.PRIVATE_KEY]  // Your wallet private key
    },
  },
  gasReporter: {
    enabled: true,
    currency: "ETH",
    gasPrice: 20,
  },
};
