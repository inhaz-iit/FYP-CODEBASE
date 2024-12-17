require("dotenv").config();
const { ethers } = require("hardhat");

async function main() {
    console.log("Deploying MintContract...");

    // Get the contract factory
    const MintContract = await ethers.getContractFactory("MintContract");

    // Deploy the contract
    const mintContract = await MintContract.deploy();

    console.log("MintContract deployed to:", mintContract.address);
    console.log("Transaction Hash:", mintContract.deployTransaction.hash);
}

// Execute the script
main()
    .then(() => process.exit(0))
    .catch((error) => {
        console.error(error);
        process.exit(1);
    });