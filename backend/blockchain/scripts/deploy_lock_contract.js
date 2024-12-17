const { ethers } = require("hardhat");
const config = require("../../configuration/config");

async function main() {
    const tokenAddress = config.TOKEN_ADDRESS; // ERC20 token address ZKP on Sepolia
    
    console.log("Deploying LockContract...");

    // Get the contract factory
    const LockContract = await ethers.getContractFactory("LockContract");

    // Deploy the contract
    const lockContract = await LockContract.deploy(tokenAddress);

    console.log(lockContract);

    console.log("LockContract deployed to:", lockContract.address);
    console.log("Transaction Hash:", lockContract.deployTransaction.hash);
}

// Execute the script
main()
    .then(() => process.exit(0))
    .catch((error) => {
        console.error(error);
        process.exit(1);
    });